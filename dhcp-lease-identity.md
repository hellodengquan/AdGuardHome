# DHCP 租约与客户端识别链路分析

本文档梳理 AdGuard Home 中 DHCP 租约写入、租约过期、客户端识别与策略叠加四段的代码衔接关系。

## 一、整体架构概览

```
DHCP 客户端请求 → DHCP 服务层 → 租约存储 → 客户端存储 → DNS 过滤/查询日志
     │                │            │           │              │
     └─ DHCPDISCOVER ─┘            │           │              │
     └─ DHCPREQUEST ───────────────┘           │              │
                                              │              │
                                租约信息(HWAddr, IP, Hostname) │
                                                              │
                                       查询日志补全客户端信息 ─┘
                                       过滤策略叠加 ────────────┘
```

核心模块：
- `internal/dhcpsvc/` - DHCP 服务层（租约管理）
- `internal/client/` - 客户端存储（持久化+运行时）
- `internal/dnsforward/` - DNS 转发（策略叠加入口）
- `internal/querylog/` - 查询日志（客户端信息补全）
- `internal/filtering/` - 过滤引擎（策略应用）

---

## 二、DHCP 租约写入

### 2.1 租约数据结构

**文件**：`internal/dhcpsvc/lease.go:24-41`

```go
type Lease struct {
    IP       netip.Addr        // 分配的 IP 地址
    Expiry   time.Time         // 过期时间
    Hostname string            // 客户端主机名
    HWAddr   net.HardwareAddr  // MAC 地址
    IsStatic bool              // 是否为静态租约
}
```

### 2.2 租约写入流程

#### 阶段一：DHCPDISCOVER（发现阶段）

**入口**：`internal/dhcpsvc/handler4.go:88-125` → `handleDiscover`

1. 提取客户端 MAC 地址，转换为 `macKey`
2. 检查 `iface.common.leases` 中是否已有该 MAC 的租约
   - 有租约：调用 `lease.updateExpiry()` 更新过期时间，直接回复 DHCPOFFER
   - 无租约：调用 `iface.common.allocateLease()` 分配新租约

#### 阶段二：DHCPREQUEST（请求阶段 - SELECTING 状态）

**入口**：`internal/dhcpsvc/handler4.go:186-234` → `handleSelecting`

1. 验证请求的 IP 与预留租约的 IP 是否匹配
2. 从 DHCP 请求中提取主机名（`hostname4(req)`）
3. 调用 `iface.updateLease(ctx, lease)` 提交租约
4. 回复 DHCPACK

#### 阶段三：租约持久化

**核心方法**：`internal/dhcpsvc/leaseindex.go:76-105` → `leaseIndex.add()`

租约会同时写入三层存储：

| 存储层级 | 数据结构 | 索引键 | 用途 |
|---------|---------|--------|------|
| 接口层 | `netInterface.leases` | `macKey`（MAC 数组） | 按 MAC 快速查找 |
| 全局索引 | `leaseIndex.byAddr` | `netip.Addr` | 按 IP 快速查找 |
| 全局索引 | `leaseIndex.byName` | `string`（小写主机名） | 按主机名快速查找 |
| 持久化层 | JSON 文件（`dbFilePath`） | - | 重启后恢复 |

**持久化触发**：每次租约增删改都会调用 `dbStore()` 写入 JSON 文件（`internal/dhcpsvc/db.go:176-206`）

### 2.3 租约分配算法

**文件**：`internal/dhcpsvc/interface.go:188-224` → `allocateLease()`

1. 调用 `reserveLease()` 预留 IP：
   - 优先从地址池中找下一个空闲 IP（`nextIP()` + `leasedOffsets` 位图）
   - 若无空闲 IP，查找过期租约回收复用（`findExpiredLease()`）
2. 检查 IP 可用性（`addressChecker.IsAvailable()`）
3. 可用则写入 `iface.leases` 和 `leasedOffsets` 位图
4. 不可用则标记为 blocked 状态，继续分配下一个

### 2.4 findExpiredLease 并发回收的锁结构

#### 2.4.1 并发场景

DHCP 服务采用**每网卡一个 goroutine** 的模型：

**文件**：`internal/dhcpsvc/server.go:166`

```go
go srv.serveEther4(context.WithoutCancel(ctx), iface, netDev)
```

每个网络接口独立运行 `serveEther4`，从网络设备读取数据包并串行处理（通过 `for pkt := range src.Packets()`）。因此：
- **同一接口内**：所有 DHCP 消息串行处理，无内部并发
- **不同接口间**：多个网卡 goroutine 并行运行，共享全局租约索引

#### 2.4.2 两级锁结构

**锁的层级关系**（外层 → 内层）：

```
DHCPServer.leasesMu (*sync.RWMutex)
        │
        └── netInterface.indexMu (*sync.RWMutex)  // 引用共享的 leasesMu
                │
                ├── netInterface.leases (map[macKey]*Lease)
                ├── netInterface.leasedOffsets (*bitSet)
                └── leaseIndex (byAddr + byName)
```

注意：`netInterface.indexMu` 并非每个接口独立的锁，而是**指向同一个全局 `leasesMu` 的引用**。

**文件**：`internal/dhcpsvc/v4.go:210` / `internal/dhcpsvc/v6.go:202`

```go
common: &netInterface{
    indexMu: srv.leasesMu,  // 所有接口共享同一个 RWMutex
    index:   srv.leases,    // 所有接口共享同一个全局索引
    leases:  map[macKey]*Lease{},  // 各接口独立的 MAC 索引
    ...
}
```

#### 2.4.3 写锁场景（所有修改操作）

所有涉及租约修改的 DHCP 处理器都会在入口处获取写锁：

| 处理器 | 加锁位置 | 锁类型 |
|--------|---------|--------|
| `handleDiscover` | `handler4.go:100` | `indexMu.Lock()` 写锁 |
| `handleSelecting` | `handler4.go:205` | `indexMu.Lock()` 写锁 |
| `handleInitReboot` | `handler4.go:261` | `indexMu.Lock()` 写锁 |
| `handleRenew` | `handler4.go:299` | `indexMu.Lock()` 写锁 |
| `handleDecline` | `handler4.go:348` | `indexMu.Lock()` 写锁 |
| `handleRelease` | `handler4.go:390` | `indexMu.Lock()` 写锁 |

**调用链示例（发现阶段触发过期回收）**：

```
handleDiscover()
  ├── indexMu.Lock()                    // 获取全局写锁
  ├── iface.leases[mk] 查找已有租约
  │     └── 无租约 → allocateLease()
  │           └── reserveLease()
  │                 ├── nextIP()          // 查 leasedOffsets 位图
  │                 │     └── 无空闲 IP
  │                 ├── findExpiredLease(now)   // 遍历 iface.leases
  │                 │     └── 返回首个过期租约
  │                 ├── index.remove()         // 从全局索引移除旧租约
  │                 ├── lease.HWAddr = newMac   // 重置租约信息
  │                 └── iface.leases[newMacKey] = lease  // 重新挂载新 MAC
  └── indexMu.Unlock()                  // defer 释放
```

#### 2.4.4 读锁场景（客户端识别查询）

客户端识别链路中查询 DHCP 租约时使用读锁，允许并发读：

**文件**：`internal/dhcpsvc/server.go:213-246`

| 查询方法 | 锁类型 |
|---------|--------|
| `HostByIP(ip)` | `leasesMu.RLock()` 读锁 |
| `MACByIP(ip)` | `leasesMu.RLock()` 读锁 |
| `IPByHost(host)` | `leasesMu.RLock()` 读锁 |
| `Leases()` | `leasesMu.RLock()` 读锁 |

**调用链示例（DNS 请求策略叠加时）**：

```
ApplyClientFiltering(id, addr, setts)
  ├── findByClientID() → 未找到
  ├── findByIP() → 未找到
  └── dhcp.MACByIP(addr)
        ├── leasesMu.RLock()       // 获取全局读锁，不阻塞其他读
        ├── leases.leaseByAddr(addr)
        │     └── byAddr[addr] → 返回 Lease.HWAddr
        └── leasesMu.RUnlock()
```

#### 2.4.5 锁设计的关键特性

1. **粗粒度全局锁**：所有接口共享一个 `leasesMu`，避免分布式锁复杂性，但多网卡高并发时会有锁竞争
2. **同一把锁双命名**：`leasesMu` 和 `indexMu` 本质是同一个 `*sync.RWMutex`，前者强调"保护租约"，后者强调"保护索引"，语义层面的区分
3. **写锁持有范围大**：DHCP 处理器在入口即加写锁，覆盖整个处理流程（包括 IP 可用性检查这种可能较慢的操作），简化了并发正确性推理
4. **读写分离**：客户端识别（高频读）与 DHCP 租约管理（低频写）通过 RWMutex 分离，读操作不互斥

---

## 三、租约过期机制

### 3.1 过期时间管理

**文件**：`internal/dhcpsvc/lease.go:71-82` → `Lease.updateExpiry()`

```go
func (l *Lease) updateExpiry(clock timeutil.Clock, ttl time.Duration) {
    if l.IsStatic {
        return  // 静态租约永不过期
    }
    now := clock.Now()
    if now.Before(l.Expiry) {
        return  // 未过期则不更新
    }
    l.Expiry = now.Add(ttl)  // 已过期则重置为当前时间+TTL
}
```

### 3.2 过期租约回收

**触发点**：`internal/dhcpsvc/interface.go:229-267` → `reserveLease()`

当地址池无空闲 IP 时，调用 `findExpiredLease()` 查找第一个过期租约：

```go
func (iface *netInterface) findExpiredLease(now time.Time) (l *Lease) {
    for _, lease := range iface.leases {
        if !lease.IsStatic && lease.Expiry.Before(now) {
            return lease
        }
    }
    return nil
}
```

回收流程：
1. 从 `leaseIndex` 中移除旧租约
2. 重置租约的 HWAddr、Hostname、IsStatic
3. 更新过期时间为 `now + leaseTTL`
4. 以新 MAC 为 key 重新存入 `iface.leases`

### 3.3 租约释放与阻塞

#### DHCPRELEASE（主动释放）

**文件**：`internal/dhcpsvc/handler4.go:376-412` → `handleRelease()`

- 从 `leaseIndex` 和 `iface.leases` 中移除租约
- 更新 `leasedOffsets` 位图，释放 IP 地址
- 持久化到磁盘

**核心代码**（`handler4.go:390-411`）：

```go
iface.common.indexMu.Lock()   // 获取全局写锁
defer iface.common.indexMu.Unlock()

lease, hasLease := iface.common.leases[mk]
// ... 校验租约存在且 IP 匹配

err := iface.common.index.remove(ctx, l, lease, iface.common)
// remove() 内部会:
//   1. delete(iface.leases, mk)
//   2. delete(leaseIndex.byAddr, lease.IP)
//   3. delete(leaseIndex.byName, lowerHostname)
//   4. leasedOffsets.set(off, false)
//   5. dbStore() 持久化
```

#### DHCPDECLINE（地址冲突）

**文件**：`internal/dhcpsvc/handler4.go:328-370` → `handleDecline()`

- 调用 `iface.common.blockLease()` 标记为阻塞租约
- 阻塞租约特征：
  - HWAddr 设为全零（`blockedHardwareAddr`）
  - Hostname 清空
  - Expiry 设为 `now + leaseTTL`
  - 从 `iface.leases` 移除，但保留在 `leaseIndex` 中
- 阻塞期间该 IP 不会被重新分配

**核心代码**（`interface.go:132-153` → `blockLease()`）：

```go
func (iface *netInterface) blockLease(ctx, l, clock) error {
    _ = iface.removeLease(l)         // 1. 从 iface.leases 删除
    l.HWAddr = blockedHardwareAddr   // 2. MAC 置全零
    l.Hostname = ""                  // 3. 主机名清空
    l.Expiry = clock.Now().Add(iface.leaseTTL)  // 4. 设置阻塞 TTL
    l.IsStatic = false
    return iface.index.dbStore(...)  // 5. 持久化（保留在全局索引中）
}
```

### 3.4 DHCPRELEASE/DHCPDECLINE 与客户端识别链路的缓存清理

客户端识别链路中存在**三级缓存**，RELEASE 和 DECLINE 对它们的影响各不相同：

```
缓存层级 1: client/runtimeIndex (client.Runtime 缓存，内存)
缓存层级 2: querylog/clientCache (单次查询内的缓存，内存)
缓存层级 3: 全局租约索引 leaseIndex (DHCP 服务内存)
           └── 持久化 JSON 文件 (磁盘)
```

#### 3.4.1 缓存层级 1：client/runtimeIndex

**结构**：`internal/client/runtimeindex.go:6-9`

```go
type runtimeIndex struct {
    index map[netip.Addr]*Runtime  // IP → Runtime 客户端信息
}
```

`Runtime` 内部分来源存储：`hostsFile`、`dhcp`、`rdns`、`arp`、`whois`

**RELEASE/DECLINE 对该缓存的影响：不会直接清理**

DHCP 服务层（dhcpsvc）与客户端存储层（client/storage）之间**没有直接的回调或通知机制**。RELEASE/DECLINE 只修改 dhcpsvc 内部的数据结构，不会主动调用 `Storage.UpdateDHCP()` 或删除 runtimeIndex 中的条目。

**该缓存何时被清理？**

有两条路径：

**路径 A：批量刷新（显式触发）**

`internal/client/storage.go:359-383` → `UpdateDHCP()`

```go
func (s *Storage) UpdateDHCP(ctx) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.runtimeIndex.clearSource(SourceDHCP)  // 先清空所有 DHCP 来源信息

    for _, l := range s.dhcp.Leases() {     // 再从 DHCP 服务重新拉取
        s.runtimeIndex.setInfo(l.IP, SourceDHCP, []string{l.Hostname})
    }

    s.runtimeIndex.removeEmpty()  // 清理无任何来源信息的空 Runtime
}
```

`clearSource(SourceDHCP)` 实现（`runtimeindex.go:55-59`）：
```go
func (ri *runtimeIndex) clearSource(src Source) {
    for _, rc := range ri.index {
        rc.unset(src)  // 每个 Runtime 移除该来源的数据
    }
}
```

触发时机：
- **HTTP API 调用**：`internal/home/clientshttp.go:110` → 用户访问 `/control/clients` 页面时
- **测试代码**：单元测试中手动调用
- 注意：默认**没有后台定时器**自动刷新 DHCP 来源缓存（与 ARP 来源不同，ARP 有 `ARPClientsUpdatePeriod` 定时刷新）

**路径 B：按需查询（惰性失效）**

`internal/client/storage.go:687-712` → `ClientRuntime(ip)`

```go
func (s *Storage) ClientRuntime(ip netip.Addr) (rc *Runtime) {
    s.mu.Lock()
    defer s.mu.Unlock()

    rc = s.runtimeIndex.client(ip)
    if rc != nil && rc.hostsFile != nil {
        return rc.clone()  // hosts 文件优先级更高，直接返回
    }

    // 即使缓存中存在 DHCP 来源数据，仍实时查 DHCP 服务
    host := s.dhcp.HostByIP(ip)  // ← 绕过缓存直接查租约索引
    if host == "" {
        // RELEASE 后：租约已删除 → host 为空
        // DECLINE 后：Hostname 被清空 → host 也为空
        return rc.clone()        // 返回旧缓存（可能为 nil 或有残留）
    }

    rc = s.runtimeIndex.setInfo(ip, SourceDHCP, []string{host})
    return rc.clone()
}
```

**关键惰性失效逻辑**：

- 当租约被 RELEASE：`dhcp.HostByIP(ip)` 返回空字符串（租约已从 `leaseIndex.byAddr` 中删除）
- 当租约被 DECLINE：`dhcp.HostByIP(ip)` 也返回空字符串（租约的 `Hostname` 字段被置空）
- 此时**不会主动清空** runtimeIndex 中旧的 DHCP 来源数据，但下次调用 `UpdateDHCP()` 批量刷新时会被清除
- 如果 `rc` 原本有数据且仅来自 DHCP 来源，`host == ""` 时会返回旧值（缓存不一致窗口）

#### 3.4.2 缓存层级 2：querylog/clientCache

**结构**：`internal/querylog/client.go:15-25`

```go
type clientCacheKey struct {
    clientID string
    ip       string
}

type clientCache map[clientCacheKey]*Client
```

这是**单次 HTTP 查询请求级别的缓存**，在查询日志搜索函数的参数中创建和传递：

```go
func (l *queryLog) client(clientID, ip string, cache clientCache) (*Client, error) {
    cck := clientCacheKey{clientID: clientID, ip: ip}
    if c, ok = cache[cck]; ok {
        return c, nil  // 缓存命中，直接返回
    }
    // ... 查不到则调用 l.findClient(ids)
    cache[cck] = c     // 缓存结果（包括空结果）
    return c, nil
}
```

**RELEASE/DECLINE 对该缓存的影响：无直接关联**

该缓存生命周期仅存在于**一次 `/control/querylog` HTTP 请求**内，请求结束即被 GC 回收。RELEASE/DECLINE 不会影响已有的 querylog 搜索请求缓存，但：
- 如果搜索请求发生在 RELEASE/DECLINE **之后**，`findClient` 回调会实时查到最新状态（租约不存在或 Hostname 为空）
- 如果搜索请求发生在 RELEASE/DECLINE **之前**，缓存可能包含旧数据，但这是请求级别的，很快就会消失

#### 3.4.3 缓存层级 3：全局租约索引 + 持久化文件

这是 DHCP 服务的**权威数据源**，RELEASE/DECLINE 会直接修改：

| 操作 | leaseIndex.byAddr | leaseIndex.byName | iface.leases | leasedOffsets | 持久化 JSON |
|------|-------------------|-------------------|--------------|---------------|-------------|
| RELEASE | 删除 | 删除 | 删除 | 置 false（释放） | 已删除 |
| DECLINE | 更新（Hostname=""） | 删除 | 删除 | 不变（仍被占用） | 更新为 blocked 状态 |

**持久化细节**（`internal/dhcpsvc/db.go:176-206` → `dbStore()`）：

RELEASE 和 DECLINE 处理的最后都会调用 `dbStore()`，同步写入磁盘，保证重启后状态一致。

#### 3.4.4 缓存一致性时序分析

以 RELEASE 为例，完整链路时序：

```
T0: 客户端 192.168.1.100 有租约，runtimeIndex[192.168.1.100].dhcp = "my-pc"
T1: 客户端发送 DHCPRELEASE
T2: dhcpsvc.handleRelease() 获取写锁
    ├── 从 leaseIndex.byAddr 删除 192.168.1.100
    ├── 从 leaseIndex.byName 删除 "my-pc"
    ├── 从 iface.leases 删除该 MAC
    ├── leasedOffsets 对应位置 false
    └── dbStore() 写入磁盘
T3: 锁释放

T4 时刻的三种可能查询结果：

(1) 新 DNS 请求 → ApplyClientFiltering → dhcp.MACByIP(192.168.1.100)
    └── leasesMu.RLock() → byAddr 无该 IP → 返回 nil
    └── 持久化客户端 findByMAC 失败 → 应用全局默认策略
    ✅ 正确，无缓存不一致

(2) 新 DNS 请求 → ClientRuntime(192.168.1.100)
    ├── runtimeIndex.client(ip) → 返回旧 Runtime（dhcp="my-pc"）
    ├── dhcp.HostByIP(ip) → 返回空（租约已删）
    └── host == "" → 不更新 runtimeIndex，返回旧 Runtime.clone()
    ⚠️ 短暂不一致：仍返回旧 DHCP 主机名，直到下次 UpdateDHCP()

(3) 用户访问 /control/clients → handleGetClients
    └── clients.storage.UpdateDHCP(ctx)
        ├── runtimeIndex.clearSource(SourceDHCP)
        ├── dhcp.Leases() → 已无 192.168.1.100
        └── runtimeIndex.removeEmpty() → 删除该 IP 对应的 Runtime
    ✅ 缓存被刷新，状态一致
```

#### 3.4.5 总结：缓存清理的设计取舍

| 缓存 | RELEASE/DECLINE 直接清理？ | 实际清理方式 | 不一致窗口 |
|------|--------------------------|-------------|-----------|
| runtimeIndex.dhcp | ❌ 不直接清理 | `UpdateDHCP()` 批量刷新或 `ClientRuntime()` 惰性查 | 直到下次刷新/查询 |
| querylog clientCache | ❌ 不相关 | 请求结束自动 GC | 单次请求内 |
| leaseIndex 全局索引 | ✅ 立即修改 | 操作时加写锁同步修改 | 无 |
| 持久化 JSON 文件 | ✅ 立即写入 | `dbStore()` 同步写盘 | 无 |

这是一种**最终一致性**设计：DHCP 层保证权威数据立即更新，上层客户端缓存通过惰性查询和手动刷新最终收敛。考虑到 DHCP RELEASE/DECLINE 是低频操作且客户端识别非强一致需求，这种设计在性能和正确性之间取得了平衡。

> **测试中的 TODO 注释印证**：`internal/client/storage_test.go:438-439` 和 `storage_test.go:483-484` 中明确标注了 TODO：
> ```go
> // TODO(a.garipov):  Consider adding ways of explicitly clearing runtime
> // sources by source.
> ```
> 说明开发者已意识到缺少按来源精确清理 runtime 缓存的机制，目前只能通过 `UpdateDHCP()` 全部清空再重建。

---

## 四、客户端识别（查询日志补全）

### 4.1 客户端信息来源优先级

**文件**：`internal/client/client.go:47-54`

客户端信息有多个来源，优先级从高到低：

```
SourcePersistent (持久化客户端) > SourceHostsFile > SourceDHCP > SourceRDNS > SourceARP > SourceWHOIS
```

### 4.2 DHCP 租约 → 运行时客户端

**批量更新**：`internal/client/storage.go:359-383` → `Storage.UpdateDHCP()`

```go
func (s *Storage) UpdateDHCP(ctx context.Context) {
    // 清空 DHCP 来源的旧数据
    s.runtimeIndex.clearSource(SourceDHCP)
    
    // 遍历所有 DHCP 租约，添加到运行时索引
    for _, l := range s.dhcp.Leases() {
        s.runtimeIndex.setInfo(l.IP, SourceDHCP, []string{l.Hostname})
    }
}
```

**按需查询**：`internal/client/storage.go:687-712` → `Storage.ClientRuntime()`

```go
func (s *Storage) ClientRuntime(ip netip.Addr) (rc *Runtime) {
    // 先查缓存的运行时客户端
    rc = s.runtimeIndex.client(ip)
    
    // 若 hosts 文件已有信息，直接返回（优先级更高）
    if rc != nil && rc.hostsFile != nil {
        return rc.clone()
    }
    
    // 否则实时查 DHCP 服务
    host := s.dhcp.HostByIP(ip)
    if host != "" {
        rc = s.runtimeIndex.setInfo(ip, SourceDHCP, []string{host})
    }
    
    return rc.clone()
}
```

### 4.3 查询日志中的客户端补全

#### 日志写入时

**文件**：`internal/dnsforward/stats.go:99-140` → `Server.logQuery()`

写入查询日志时，只记录原始标识：
- `ClientID`（DoH/DoT/DoQ 客户端 ID）
- `ClientIP`（客户端 IP 地址）

**不**立即补全客户端名称。

#### 日志搜索时

**文件**：`internal/querylog/search.go:20-47` → `queryLog.client()`

查询日志搜索时，通过 `findClient` 回调函数补全客户端信息：

```go
func (l *queryLog) client(clientID, ip string, cache clientCache) (c *Client, err error) {
    // 先查缓存
    cck := clientCacheKey{clientID: clientID, ip: ip}
    if c, ok = cache[cck]; ok {
        return c, nil
    }
    
    // 构造 ID 列表：ClientID 优先，IP 其次
    var ids []string
    if clientID != "" {
        ids = append(ids, clientID)
    }
    if ip != "" {
        ids = append(ids, ip)
    }
    
    // 调用外部查找函数
    c, err = l.findClient(ids)
    
    // 缓存结果（包括空结果）
    cache[cck] = c
    
    return c, nil
}
```

**快速匹配优化**：`internal/querylog/searchcriterion.go:138-159`

在文件扫描的快速匹配阶段，也会调用 `findClient` 获取客户端名称用于关键词匹配，避免完整解码后再过滤。

### 4.4 持久化客户端查找链路

**入口**：`internal/client/storage.go:529-560` → `Storage.Find()`

按优先级依次尝试：
1. ClientID → `index.findByClientID()`
2. RemoteIP → `findByIP()`
3. Subnet → `index.findByCIDR()`
4. MAC → `index.findByMAC()`

**IP → MAC 转换（关键链路）**：`internal/client/storage.go:564-576`

```go
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    // 1. 直接按 IP 查找持久化客户端
    p, ok = s.index.findByIP(addr)
    if ok {
        return p, true
    }
    
    // 2. 从 DHCP 租约查 MAC 地址，再按 MAC 查找
    foundMAC := s.dhcp.MACByIP(addr)
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC)
    }
    
    return nil, false
}
```

> **关键衔接点**：DHCP 租约提供了 IP→MAC 的映射桥梁，使得仅配置了 MAC 地址的持久化客户端也能通过 IP 被识别。

---

## 五、策略叠加（客户端过滤策略应用）

### 5.1 策略叠加入口

**位置**：DNS 请求处理流水线

**文件**：`internal/dnsforward/requesthandler.go:33-43`

```go
mods := []modProcessFunc{
    s.processInitial,          // 1. 初始处理（含客户端设置加载）
    s.processDDRQuery,
    s.processDHCPHosts,
    s.processDHCPAddrs,
    s.processFilteringBeforeRequest,
    s.processUpstream,
    s.processFilteringAfterResponse,
    s.ipset.process,
    s.processQueryLogsAndStats, // 8. 查询日志与统计
}
```

### 5.2 客户端过滤设置加载

**文件**：`internal/dnsforward/process.go:143-145` → `processInitial()`

```go
// 获取客户端特定的过滤设置
dctx.setts = s.clientRequestFilteringSettings(dctx)
```

**文件**：`internal/dnsforward/filter.go:18-24` → `clientRequestFilteringSettings()`

```go
func (s *Server) clientRequestFilteringSettings(dctx *dnsContext) (setts *filtering.Settings) {
    setts = s.dnsFilter.Settings()
    setts.ProtectionEnabled = dctx.protectionEnabled
    s.dnsFilter.ApplyAdditionalFiltering(dctx.proxyCtx.Addr.Addr(), dctx.clientID, setts)
    return setts
}
```

### 5.3 过滤设置叠加过程

**文件**：`internal/filtering/filter.go:710-722` → `DNSFilter.ApplyAdditionalFiltering()`

```go
func (d *DNSFilter) ApplyAdditionalFiltering(cliAddr netip.Addr, clientID string, setts *Settings) {
    setts.ClientIP = cliAddr
    
    d.ApplyBlockedServices(setts)       // 全局阻塞服务
    d.applyClientFiltering(clientID, cliAddr, setts)  // 客户端特定设置
    
    // ... 阻塞服务日程处理
}
```

### 5.4 客户端策略实际应用

`applyClientFiltering` 是一个注入的函数指针，实际实现在客户端存储中：

**文件**：`internal/client/storage.go:770-806` → `Storage.ApplyClientFiltering()`

```go
func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings) {
    // 1. 按 ClientID 查找
    c, ok := s.index.findByClientID(ClientID(id))
    if !ok {
        // 2. 按 IP 查找
        c, ok = s.index.findByIP(addr)
    }
    
    if !ok {
        // 3. 通过 DHCP 租约将 IP 转为 MAC，再按 MAC 查找
        foundMAC := s.dhcp.MACByIP(addr)
        if foundMAC != nil {
            c, ok = s.index.findByMAC(foundMAC)
        }
    }
    
    if !ok {
        return  // 未找到客户端，使用全局默认设置
    }
    
    // 应用客户端设置
    if c.UseOwnBlockedServices {
        setts.BlockedServices = c.BlockedServices.Clone()
    }
    setts.ClientName = c.Name
    setts.ClientTags = slices.Clone(c.Tags)
    
    if !c.UseOwnSettings {
        return
    }
    
    // 若使用自定义设置，则覆盖过滤开关
    setts.FilteringEnabled = c.FilteringEnabled
    setts.SafeSearchEnabled = c.SafeSearchConf.Enabled
    setts.ClientSafeSearch = c.SafeSearch
    setts.SafeBrowsingEnabled = c.SafeBrowsingEnabled
    setts.ParentalEnabled = c.ParentalEnabled
}
```

### 5.5 叠加后的设置使用

过滤设置 `setts` 会贯穿整个 DNS 处理流程：

1. **请求过滤**：`filterDNSRequest()` → `dnsFilter.CheckHost(host, qtype, setts)`
2. **响应过滤**：`filterDNSResponse()` → 遍历 Answer 记录逐一检查
3. **查询日志**：记录过滤结果和原因
4. **统计**：按客户端维度统计

---

## 六、完整链路时序图

### 6.1 DHCP 租约写入时序

```
客户端           dhcpsvc           leaseIndex         netInterface          DB
  │                 │                   │                   │                │
  │─ DHCPDISCOVER ─▶│                   │                   │                │
  │                 │─ handleDiscover ─▶│                   │                │
  │                 │                   │─ 查找 byMAC ─────▶│                │
  │                 │                   │                   │─ 找到旧租约 ──▶│
  │                 │                   │◀── 返回租约 ──────│                │
  │                 │  updateExpiry()   │                   │                │
  │                 │                   │                   │                │
  │◀── DHCPOFFER ───│                   │                   │                │
  │                 │                   │                   │                │
  │─ DHCPREQUEST ──▶│                   │                   │                │
  │                 │─ handleSelecting ─▶│                  │                │
  │                 │                   │─ updateLease() ──▶│                │
  │                 │                   │  byAddr, byName   │                │
  │                 │                   │                   │                │
  │                 │                   │──── dbStore() ───────────────────▶│
  │                 │                   │                   │                │
  │◀─── DHCPACK ────│                   │                   │                │
```

### 6.2 DNS 请求中客户端识别与策略叠加

```
DNS 请求        dnsforward          filtering          client/storage        dhcpsvc
   │                │                   │                   │                   │
   │─ ServeDNS ───▶│                   │                   │                   │
   │                │─ processInitial ─│                   │                   │
   │                │                   │                   │                   │
   │                │ clientRequestFilteringSettings()     │                   │
   │                │                   │                   │                   │
   │                │─ ApplyAdditionalFiltering() ───────▶│                   │
   │                │                   │                   │                   │
   │                │                   │  findByClientID()│                   │
   │                │                   │  findByIP()      │                   │
   │                │                   │                   │─ MACByIP(ip) ───▶│
   │                │                   │                   │◀── 返回 MAC ─────│
   │                │                   │  findByMAC()     │                   │
   │                │                   │                   │                   │
   │                │                   │◀── 返回设置 ─────│                   │
   │                │                   │                   │                   │
   │                │─ processFilteringBeforeRequest ─────▶│                   │
   │                │                   │ CheckHost()      │                   │
   │                │                   │                   │                   │
   │                │─ processQueryLogsAndStats ─│         │                   │
   │                │  queryLog.Add() │         │         │                   │
```

### 6.3 查询日志搜索时客户端补全

```
前端查询        querylog           findClient 回调      client/storage        dhcpsvc
   │                │                   │                   │                   │
   │─ Search ─────▶│                   │                   │                   │
   │                │ searchMemory()    │                   │                   │
   │                │ 遍历内存日志      │                   │                   │
   │                │   │               │                   │                   │
   │                │   └─ client() ───▶│                   │                   │
   │                │    (CID, IP)      │                   │                   │
   │                │                   │─ findClient(ids) ─▶│                  │
   │                │                   │                   │ Find(params)      │
   │                │                   │                   │  findByIP()       │
   │                │                   │                   │   MACByIP(ip) ───▶│
   │                │                   │                   │  ◀── 返回 MAC ────│
   │                │                   │                   │  findByMAC()      │
   │                │                   │◀── 返回 Client ───│                   │
   │                │◀── logEntry.client 已填充 ─│         │                   │
   │                │                   │         │         │                   │
   │                │─ 返回结果 ────────│         │         │                   │
```

---

## 七、关键代码索引

| 功能 | 文件 | 关键函数/方法 |
|------|------|-------------|
| DHCP 租约结构 | `internal/dhcpsvc/lease.go` | `Lease` 结构体 |
| 租约索引 | `internal/dhcpsvc/leaseindex.go` | `leaseIndex.add/remove/update` |
| DHCPv4 处理器 | `internal/dhcpsvc/handler4.go` | `handleDiscover/handleRequest/handleRelease/handleDecline` |
| 租约分配与过期回收 | `internal/dhcpsvc/interface.go` | `allocateLease/reserveLease/findExpiredLease/blockLease` |
| 全局读写锁 | `internal/dhcpsvc/server.go` | `DHCPServer.leasesMu`（所有接口共享） |
| 租约查询接口 | `internal/dhcpsvc/server.go` | `Leases/HostByIP/MACByIP/IPByHost` |
| 持久化 | `internal/dhcpsvc/db.go` | `dbLoad/dbStore` |
| 运行时客户端缓存 | `internal/client/runtimeindex.go` | `runtimeIndex.setInfo/clearSource/removeEmpty` |
| 客户端存储 | `internal/client/storage.go` | `Find/ApplyClientFiltering/UpdateDHCP/ClientRuntime` |
| 运行时客户端 | `internal/client/client.go` | `Runtime.Info()`（来源优先级） |
| DNS 过滤设置 | `internal/dnsforward/filter.go` | `clientRequestFilteringSettings` |
| 查询日志补全 | `internal/querylog/search.go` | `client()` |
| 查询日志请求级缓存 | `internal/querylog/client.go` | `clientCache/clientCacheKey` |
| 策略叠加 | `internal/client/storage.go` | `ApplyClientFiltering()` |
| DHCP 刷新触发 | `internal/home/clientshttp.go` | `handleGetClients`（访问 `/control/clients` 时调用 `UpdateDHCP`） |

---

## 八、设计特点总结

1. **三层索引设计**：MAC 键、IP 地址、主机名三种索引，支持不同场景的快速查找

2. **IP→MAC 桥接**：通过 DHCP 租约的 `MACByIP()` 方法，实现 IP 到 MAC 的转换，使得按 MAC 配置的持久化客户端也能通过 IP 被识别

3. **延迟补全策略**：查询日志写入时不补全客户端信息，搜索时才通过回调函数补全，减少写入路径的开销

4. **依赖倒置**：过滤模块通过 `ApplyClientFiltering` 函数指针与客户端存储解耦，符合依赖倒置原则

5. **多来源优先级**：客户端信息支持多个来源（持久化、hosts 文件、DHCP、rDNS、ARP、WHOIS），按优先级合并

6. **粗粒度单锁并发模型**：所有网络接口共享同一个 `*sync.RWMutex`，DHCP 写操作（租约分配/释放/回收）和客户端读操作（HostByIP/MACByIP）通过读写锁分离。同一接口内串行处理，不同接口间共享全局锁，简化并发正确性

7. **最终一致性缓存设计**：DHCP 权威数据立即修改并持久化，上层客户端缓存（runtimeIndex）通过 `UpdateDHCP()` 批量刷新和 `ClientRuntime()` 惰性查询实现最终收敛。DHCP 层不主动推送变更通知到 client 层，缺少按来源精确清理 runtime 缓存的机制（代码中有 TODO 标注）

8. **阻塞租约的设计**：DHCPDECLINE 不直接删除租约，而是将 MAC 置全零、Hostname 清空后保留在全局索引中，通过 `IsBlocked()` 标记。`Leases()` 导出时会跳过阻塞租约，既防止冲突 IP 被立即复用，又不暴露给上层客户端识别

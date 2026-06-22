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

### 3.5 长租约（多天/周）下缓存淘汰与续约时间窗口的协作

#### 3.5.1 续约时间窗口的实现

DHCP 协议定义了两个续约时间点：
- **T1 (Renewing)**：租约时长的 50%，客户端开始向原服务器续约
- **T2 (Rebinding)**：租约时长的 80%，客户端向任意服务器广播续约

**DHCPv6 的实现**（明确计算 T1/T2）：

`internal/dhcpsvc/v6.go:156-214`

```go
type dhcpInterfaceV6 struct {
    t1 time.Duration  // 0.5 × LeaseDuration
    t2 time.Duration  // 0.8 × LeaseDuration
}

// 创建时预计算
t1: conf.LeaseDuration / 2,
t2: conf.LeaseDuration * 4 / 5,
```

响应时将 T1/T2 放入 IA_NA 选项（`v6.go:511-512`）：

```go
return iaNAOption{
    nested: []iaAddrOption{{
        addr:              lease.IP,
        preferredLifetime: iface.common.leaseTTL,
        validLifetime:     iface.common.leaseTTL,
    }},
    iaid: iaid,
    t1:   iface.t1,   // 50% 时间点
    t2:   iface.t2,   // 80% 时间点
}.Encode()
```

**DHCPv4 的实现**（未发送 T1/T2，有 TODO）：

`internal/dhcpsvc/options4.go:329-349`

```go
// TODO(e.burkov):  Add also renewal (T1) and rebinding (T2) time options, see
// RFC 2131 Section 4.4.5, and RFC 2132 Sections 9.11 and 9.12.
func (iface *dhcpInterfaceV4) appendTimeOptions(
    opts layers.DHCPOptions,
    lease *Lease,
) (res layers.DHCPOptions) {
    var dur time.Duration
    if lease.IsStatic {
        dur = iface.common.leaseTTL
    } else {
        dur = lease.Expiry.Sub(iface.clock.Now())  // 仅发送剩余时间
    }
    // 只写入 IPAddressLeaseTime 选项，不写 RenewalTime/RebindingTime
    ...
}
```

> **关键差异**：DHCPv4 客户端只能使用操作系统默认的续约策略（通常也是 50%/80%），但 AdGuard Home 不主动发送 T1/T2 选项；DHCPv6 则明确发送 50%/80% 的 T1/T2。

#### 3.5.2 长租约场景下的续约时间轴

以 LeaseDuration = **7 天**（一周）为例：

```
T0              T1(3.5天)          T2(5.6天)          T0+7天(过期)
 ├─────────────────┼──────────────────┼──────────────────┤
 │                 │                  │                  │
 └─ 分配租约       └─ 客户端 RENEW    └─ 客户端 REBIND   └─ Expiry
                    (单播给原服务器)    (广播给所有服务器)
```

AdGuard Home 对续约的处理（`internal/dhcpsvc/handler4.go:283-320` → `handleRenew`）：

```go
func (iface *dhcpInterfaceV4) handleRenew(ctx, req, fd, ip) {
    iface.common.indexMu.Lock()           // 全局写锁
    defer iface.common.indexMu.Unlock()

    lease, hasLease := iface.common.leases[mk]
    if !hasLease {
        return  // 无租约记录则静默丢弃
    }
    if lease.IP != ip {
        iface.respondNAK(...)             // IP 不匹配则 NAK
        return
    }
    iface.updateAndRespond(ctx, l, req, lease, fd, idOpt)
}
```

`updateAndRespond`（`internal/dhcpsvc/v4.go:355-374`）会更新租约：

```go
func (iface *dhcpInterfaceV4) updateAndRespond(...) {
    lease.Hostname = cmp.Or(hostname4(req), lease.Hostname)  // 主机名可能更新
    err := iface.updateLease(ctx, lease)                     // → leaseIndex.update()
    if err != nil {
        iface.respondNAK(...)
        return
    }
    iface.respondACK(ctx, req, fd, lease, idOpt)
}
```

#### 3.5.3 租约续约时 Expiry 的更新逻辑

**`internal/dhcpsvc/lease.go:69-82` → `Lease.updateExpiry()`**：

```go
func (l *Lease) updateExpiry(clock timeutil.Clock, ttl time.Duration) {
    if l.IsStatic {
        return
    }
    now := clock.Now()
    if now.Before(l.Expiry) {
        return  // ⚠️ 租约未过期则不更新 Expiry！
    }
    l.Expiry = now.Add(ttl)  // 过期后才重置为 now+TTL
}
```

**但注意**：`updateExpiry` 仅在 `handleDiscover` 中被调用（续约时不调用）。续约走的是 `updateAndRespond` → `leaseIndex.update()`，这个更新过程中 **Expiry 保持不变**。

实际的 Expiry 更新在响应构造时才计算剩余时间（`options4.go:342`）：

```go
dur = lease.Expiry.Sub(iface.clock.Now())
```

这意味着：
- 租约记录中的 `Expiry` 始终是**初次分配时设置的绝对过期时间**
- 每次续约 ACK 中返回给客户端的是**剩余时间**（`lease.Expiry - now`）
- 客户端收到剩余时间后，会重置自己的本地计时器为 `now + 剩余时间`，从而实现续约

**长租约下的实际效果**：假设 7 天租约在 T1（3.5 天）续约成功，客户端的本地租期会被重置为 `now + 3.5天剩余 ≈ now + 3.5天`，但服务器端 `lease.Expiry` 仍然是 T0+7天。下一次续约时客户端会在 `now + 1.75天`（新租期的 50%）再次发起，此时服务器端剩余时间约为 1.75 天。

#### 3.5.4 长租约与 runtimeIndex 缓存淘汰的协作矛盾

**核心问题**：runtimeIndex 没有自动过期机制，而长租约意味着长时间不触发 `UpdateDHCP()`。

| 淘汰触发条件 | 触发时机 | 长租约下的频率 |
|------------|---------|--------------|
| `UpdateDHCP()` 批量刷新 | 用户访问 `/control/clients` HTTP API | 可能数天/数周一次 |
| `ClientRuntime()` 惰性查询 | 每次 DNS 请求时实时查 `HostByIP` | 高频，但只查不删 |
| `removeEmpty()` 清理空 Runtime | 仅在批量刷新后调用 | 依赖上面的刷新 |

**协作时序分析（7天租约）**：

```
T0:  客户端拿到 192.168.1.100，租约7天
     → runtimeIndex[192.168.1.100].dhcp = "my-pc"  (由 UpdateDHCP 写入)

T1 (3.5天): 客户端 RENEW，续约成功
     → 服务器 leaseIndex 更新（Hostname 可能变化）
     → ⚠️ runtimeIndex 不会收到通知，仍是旧值

T3 (5天):   用户访问 /control/clients
     → UpdateDHCP() 被调用
     → clearSource(SourceDHCP) 清空所有 DHCP 来源
     → 重新从 leaseIndex 拉取所有租约
     → ✅ runtimeIndex 与租约同步

T4 (8天):   客户端关机未续约，租约过期
     → leaseIndex 中租约仍存在（不会自动清除）
     → ⚠️ runtimeIndex 中也仍存在

T5 (9天):   另一个客户端通过 findExpiredLease 回收该 IP
     → leaseIndex 中 IP 映射到新 MAC/Hostname
     → ⚠️ runtimeIndex 不会被通知

T6 (9天+):  DNS 请求触发 ClientRuntime(192.168.1.100)
     → dhcp.HostByIP(ip) 返回新 Hostname
     → runtimeIndex.setInfo() 覆盖为新值
     → ✅ 通过惰性查询纠正（但中间 DNS 请求可能用了旧 Hostname）

T7 (10天):  用户访问 /control/clients
     → UpdateDHCP() 全量刷新，最终一致性达成
```

#### 3.5.5 长租约下的设计局限

1. **续约期间 Hostname 变更不感知**：如果客户端续约时上报了不同的 Hostname，`updateAndRespond` 会更新租约记录，但 runtimeIndex 直到下一次 `UpdateDHCP()` 或 `ClientRuntime()` 才会看到变化。

2. **过期租约不会自动清理**：leaseIndex 中过期的租约会一直保留，直到被 `findExpiredLease()` 回收复用或被 `Reset()` 清除。runtimeIndex 同理。

3. **租约回收复用存在竞态窗口**：当长租约过期被回收分配给新客户端时，在惰性查询触发前，runtimeIndex 可能短暂指向旧客户端信息。

4. **DHCPv4 T1/T2 缺失**：由于代码 TODO 未实现 RenewalTime/RebindingTime 选项，DHCPv4 客户端完全依赖操作系统默认续约策略（通常是 50%/80%），无法在服务端精细控制长租约的续约时机。

---

### 3.6 多 DHCP 服务器并存部署下的客户端识别冲突

AdGuard Home 支持三种多服务器并存场景，每种场景的冲突风险不同：

```
场景 A: IPv4 + IPv6 双栈（同一台 AdGuard Home 实例）
场景 B: 主备部署（两台 AdGuard Home，各自独立运行）
场景 C: 与其他 DHCP 服务器共存（如路由器自带 DHCP）
```

#### 3.6.1 场景 A：IPv4 + IPv6 双栈（同实例）

**部署形态**：同一个 `DHCPServer` 实例同时管理 IPv4 和 IPv6 接口。

`internal/dhcpsvc/v4.go:200-207` 和 `internal/dhcpsvc/v6.go:202-207`：

```go
// IPv4 接口
common: &netInterface{
    indexMu:       srv.leasesMu,     // 共享全局锁
    index:         srv.leases,       // 共享全局租约索引
    leases:        map[macKey]*Lease{},  // 接口独立的 MAC 索引
    ...
}

// IPv6 接口
common: &netInterface{
    indexMu:       srv.leasesMu,     // 同一个全局锁
    index:         srv.leases,       // 同一个全局索引
    leases:        map[macKey]*Lease{},  // 另一个独立的 MAC 索引
    ...
}
```

**双栈共享的全局数据结构**：`leaseIndex`

`internal/dhcpsvc/leaseindex.go:17-25`

```go
type leaseIndex struct {
    byAddr map[netip.Addr]*Lease     // IP → Lease（v4+v6 地址天然不冲突）
    byName map[string]*Lease         // hostname → Lease（⚠️ 可能冲突）
    ...
}
```

**冲突点分析**：

| 数据结构 | 是否冲突 | 原因 |
|---------|---------|------|
| `leaseIndex.byAddr` | ❌ 不冲突 | IPv4 和 IPv6 地址空间完全分离，netip.Addr 内部编码区分 v4/v6 |
| `leaseIndex.byName` | ⚠️ **冲突** | 同一个 hostname 只能对应一个 Lease，后写入的覆盖先写入的 |
| `iface.leases[macKey]` | ❌ 不冲突 | v4 和 v6 接口有各自独立的 map |
| `leasedOffsets` 位图 | ❌ 不冲突 | 各接口独立维护 |

**hostname 冲突的实际影响**：

假设同一台客户端（同一个 MAC）同时获取了 IPv4 和 IPv6 租约，且上报了相同 Hostname：

```go
// leaseIndex.add() 中的冲突检测
func (idx *leaseIndex) add(ctx, logger, l, iface) error {
    loweredName := strings.ToLower(l.Hostname)

    if _, ok := idx.byAddr[l.IP]; ok {
        return fmt.Errorf("lease for ip %s already exists", l.IP)
    } else if _, ok = idx.byName[loweredName]; ok {
        return fmt.Errorf("lease for hostname %s already exists", l.Hostname)  // ← 会报错！
    }
    ...
}
```

实际表现：
- v4 租约先写入 → 成功，`byName["my-pc"] = v4Lease`
- v6 租约后写入 → 失败，返回 `"lease for hostname my-pc already exists"`
- **但 v6 的 IP 仍会通过其他方式分配给客户端**，只是 AdGuard Home 内部的租约索引中缺少 hostname→v6IP 的反向映射

**客户端识别链路的影响**：

`ApplyClientFiltering` / `findByIP` 通过 IP 查 MAC：

```go
// storage.go:564-573
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    p, ok = s.index.findByIP(addr)      // 先按 IP 查持久化客户端
    if ok {
        return p, true
    }
    foundMAC := s.dhcp.MACByIP(addr)    // 再通过 DHCP 租约查 MAC
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC)  // 按 MAC 查持久化客户端
    }
    return nil, false
}
```

`MACByIP` 走 `byAddr` 索引（`server.go:225-234`），不受 hostname 冲突影响，所以 **v4/v6 的 MAC 解析都是正确的**。

受影响的是 `HostByIP` / `ClientRuntime` 获取主机名：
- v4 IP → `byAddr` 命中 → 返回正确 Hostname ✅
- v6 IP → `byAddr` 未命中（因为 add 失败没写入）→ 返回空字符串 ❌
- `IPByHost("my-pc")` → 只返回 v4 IP，丢失 v6 IP ❌

**双栈冲突总结**：MAC 解析不受影响，但 hostname→IP 反向映射和 v6 的主机名补全会丢失。这是代码级别的 BUG。

#### 3.6.2 场景 B：主备部署（两台 AdGuard Home）

**部署形态**：两台独立的 AdGuard Home 作为 DHCP 主备服务器，各自维护独立的租约数据库。

客户端在 T1（50% 租期）单播给主服务器，T2（80% 租期）广播给任意服务器。可能出现：
- 主服务器响应 → 主的租约更新
- 备服务器响应 → 备的租约更新
- 两台同时响应 → 客户端选第一个，另一台的租约成为"幽灵租约"

**冲突分析**：

两台服务器之间**没有租约同步机制**（AdGuard Home 本身不提供 DHCP 故障转移协议）。

客户端识别链路只连接到**当前 AdGuard Home 实例**的 DHCP 服务：

```go
// client/storage.go:90-97  StorageConfig
type StorageConfig struct {
    ...
    DHCP DHCP  // 指向当前实例的 DHCPServer
    ...
}
```

实际影响：
1. **备服务器分配的租约在主服务器上不可见** → 客户端从备拿到 IP，主的查询日志/策略叠加无法识别该客户端
2. **两台都有同一 MAC 的租约但 IP 不同** → 取决于 DNS 请求到哪台 AGH，识别到的客户端信息不同
3. **持久化客户端（按 MAC 配置）不受影响** → 只要 `MACByIP` 能在本机租约中找到 MAC，后续 `findByMAC` 就能匹配到持久化策略

**应对方式**：主备部署场景下，如果依赖 DHCP 租约做客户端识别，必须确保：
- 两台 AGH 的地址池不重叠（避免 IP 冲突）
- 持久化客户端**按 MAC 配置**而非按 IP 配置（MAC 在两台机器上都能匹配）
- 不依赖 DHCP 租约的 Hostname 进行策略匹配（Hostname 可能只存在于分配租约的那台）

#### 3.6.3 场景 C：与第三方 DHCP 服务器共存

**部署形态**：AdGuard Home 只做 DNS 过滤，网络中另有路由器/Windows Server 等负责 DHCP。

此场景下 `client.DHCP` 接口使用 `EmptyDHCP` 实现：

```go
// dhcpsvc/dhcpsvc.go:99-109
func (Empty) HostByIP(_ netip.Addr) (host string) { return "" }
func (Empty) MACByIP(_ netip.Addr) (mac net.HardwareAddr) { return nil }
func (Empty) Leases() (leases []*Lease) { return nil }
```

**客户端识别链路完全绕过 DHCP 租约**：

```
ApplyClientFiltering(id, addr, setts)
  ├── findByClientID() → 可能命中
  ├── findByIP() → 只查持久化客户端 IP（不是 DHCP）
  │     └── 失败 → dhcp.MACByIP() → 返回 nil → 无法转 MAC 查询
  └── findByCIDR/findByMAC → 不触发 DHCP
```

因此这种场景下：
- ✅ 按 ClientID 配置的持久化客户端：正常识别
- ✅ 按 MAC 配置的持久化客户端：**无法识别**（没有 DHCP 租约提供 IP→MAC 桥接）
- ✅ 按 IP/子网配置的持久化客户端：正常识别
- ❌ DHCP 租约 Hostname：完全不可用（只能依赖 rDNS/ARP 等其他来源）

#### 3.6.4 多服务器冲突矩阵

| 部署场景 | byAddr | byName (hostname) | MAC 解析 | Hostname 补全 | 策略叠加可靠性 |
|---------|--------|-------------------|----------|--------------|--------------|
| 单 IPv4 | ✅ | ✅ | ✅ | ✅ | 高 |
| 单 IPv6 | ✅ | ✅ | ✅ | ✅ | 高 |
| IPv4+IPv6 双栈 | ✅ | ⚠️ v6 覆盖丢失 | ✅ 都正常 | ⚠️ v6 Hostname 丢失 | 中（按 MAC 配置没问题） |
| 双 AGH 主备 | ⚠️ 各管各的 | ⚠️ 各管各的 | ⚠️ 仅本机可见 | ⚠️ 仅本机可见 | 低（必须按 MAC 持久化） |
| 第三方 DHCP | ❌ 无 | ❌ 无 | ❌ 无 | ❌ 无 | 中高（按 IP/ClientID 没问题） |

---

### 3.7 DHCP relay 中继代理转发时客户端识别链路拼接

#### 3.7.1 DHCPv4 relay 支持情况

AdGuard Home 作为 DHCPv4 服务器**支持**接收经过中继代理转发的请求，但仅做最基础的 giaddr 处理。

**关键标识：`giaddr`（RelayAgentIP 字段）**

当客户端与服务器不在同一子网时，DHCP relay 代理会在 BOOTP 头的 `giaddr` 字段填入自己的接口地址，然后将请求单播给 DHCP 服务器。

**代码位置**：`internal/dhcpsvc/v4.go:400-413` → `newIPv4UDPLayers()`

```go
switch {
case isSpecified(req.RelayAgentIP.To4()):
    // giaddr 非零 → 发回 relay 代理的服务器端口
    dstIP, dstPort = req.RelayAgentIP.To4(), ServerPortV4
case isSpecified(req.ClientIP.To4()):
    // ciaddr 非零 → 单播给客户端
    dstIP, dstPort = req.ClientIP.To4(), ClientPortV4
default:
    // 广播给本地链路
    ...
}
```

**NAK 响应的特殊处理**（`v4.go:293-301`）：

```go
// 如果 giaddr 非零，必须设广播位，让 relay 把 NAK 广播给客户端
// 因为客户端可能还没有正确的 IP 地址，无法单播回应
if isSpecified(req.RelayAgentIP) {
    flags = flags | FlagsBroadcast
}
```

#### 3.7.2 relay 场景下客户端真实 MAC 的保留

**核心要点：relay 转发不修改 CHADDR 字段**

DHCPv4 协议规定，中继代理只能修改 `giaddr`、`hops` 等字段，**不能修改 `chaddr`（客户端硬件地址）**。因此即使经过多级 relay 转发，请求到达 AdGuard Home 时，`req.ClientHWAddr` 仍然是客户端的真实 MAC 地址。

**租约写入链路完全正常**：

```
客户端 → DHCP relay(giaddr=relayIP, chaddr=clientMAC) → AdGuard Home
    │
    └─ handleDiscover/handleSelecting
        ├── req.ClientHWAddr  →  仍是客户端真实 MAC
        ├── mk := macKey{...} →  用真实 MAC 生成键
        └── lease.HWAddr = ... →  存入真实 MAC
```

#### 3.7.3 客户端识别链路在 relay 场景下的表现

**完全不受影响**，因为客户端识别依赖的是 `byAddr[ip].HWAddr`，而这个 HWAddr 在租约创建时就已经从 `chaddr` 正确写入了。

**完整调用链验证**：

```
DNS 请求 (源 IP = 客户端 IP)
  │
  └─ ApplyClientFiltering(id, addr, setts)
        ├── findByClientID() → 未命中
        ├── findByIP() → 未命中
        │     └─ s.index.findByIP(addr) → 持久化客户端无
        ├── s.dhcp.MACByIP(addr) → 查 leaseIndex.byAddr
        │     └─ 命中 → 返回 Lease.HWAddr (即客户端真实 MAC)
        └─ s.index.findByMAC(foundMAC) → 按 MAC 查持久化客户端
              └─ 命中 → 叠加该客户端的策略设置
```

#### 3.7.4 DHCPv4 relay 的已知局限

1. **不支持 Option 82（Relay Agent Information）**：代码中完全没有解析 Option 82（中继代理信息选项，包含 Circuit ID、Remote ID 等）的逻辑，无法基于 relay 端口标识做更细粒度的客户端区分。

2. **不处理多个 giaddr 叠加**：仅使用最外层的 giaddr 做响应路由，多级 relay 场景下依赖标准协议行为。

3. **地址池子网选择逻辑**：从现有代码看，`dhcpInterfaceV4` 绑定到具体接口，没有基于 giaddr 选择不同地址池的能力。所有经过 relay 转发的请求都由**监听该接口的 DHCP 服务**分配同一地址池的 IP。

#### 3.7.5 DHCPv6 relay 的支持状态

**完全不支持**。证据：

- **`handleDHCPv6` 消息分发**（`internal/dhcpsvc/handler6.go:47-66`）：

```go
switch typ {
case layers.DHCPv6MsgTypeSolicit:     // ✅
case layers.DHCPv6MsgTypeRequest:     // ✅
case layers.DHCPv6MsgTypeConfirm:     // ✅
case layers.DHCPv6MsgTypeRenew:       // ✅
case layers.DHCPv6MsgTypeRebind:      // ✅（stub 实现）
case layers.DHCPv6MsgTypeInformationRequest:  // ✅
case layers.DHCPv6MsgTypeRelease:     // ✅
case layers.DHCPv6MsgTypeDecline:     // ✅
default:
    return fmt.Errorf("dhcpv6: request type: %w: %d", errors.ErrBadEnumValue, typ)
}
```

- 没有 `DHCPv6MsgTypeRelayForward` / `DHCPv6MsgTypeRelayReply` 的 case
- 没有 `RelayForw` / `RelayRepl` 消息的解封装和封装逻辑
- 没有 hop count、link-address 等 relay 字段处理

此外 `serveEther6` 上还有 `lint:ignore U1000 TODO(e.burkov): Use.` 注释（`handle6.go:42`），说明 DHCPv6 服务端整体仍处于开发阶段。

**DHCPv6 relay 场景下客户端识别的影响**：

如果 DHCPv6 请求经过 relay 转发到达 AdGuard Home，会直接走进 `default` 分支报错返回，**不会创建租约**。因此客户端识别链路中也不会有这些 IPv6 地址的 MAC 映射。IPv6 客户端只能依赖 SLAAC + ARP/NDP + rDNS 等其他识别路径。

---

### 3.8 IPv6 SLAAC 与 DHCPv6 混合环境下客户端识别

#### 3.8.1 SLAAC 的三种配置模式

AdGuard Home 的 DHCPv6 支持三种 SLAAC 相关模式，由 `IPv6Config` 中的两个布尔字段控制：

**文件**：`internal/dhcpsvc/v6.go:82-88`

```go
// RASlaacOnly: 只发 RA，不启动 DHCPv6 服务器（纯 SLAAC 环境）
RASLAACOnly bool

// RAAllowSlaac: RA 中设置 M/O 标志，允许 SLAAC 与 DHCPv6 共存（混合模式）
RAAllowSLAAC bool
```

**三种模式对应关系**：

| 模式 | RASLAACOnly | RAAllowSLAAC | DHCPv6 服务器 | RA 标志位 |
|------|-------------|--------------|-------------|-----------|
| 纯 DHCPv6 | false | false | ✅ 启动 | M=1, O=1（仅 DHCP） |
| 混合模式 | false | true | ✅ 启动 | M=0, O=0 或 M=1, O=1（SLAAC + DHCPv6） |
| 纯 SLAAC | true | 任意 | ❌ 不启动 | M=0, O=0（仅 SLAAC） |

**纯 SLAAC 模式下跳过 DHCPv6 启动**（`internal/dhcpd/v6_unix.go:735-740`）：

```go
if s.conf.RASLAACOnly {
    log.Debug("not starting dhcpv6 server due to ra_slaac_only=true")
    return nil
}
```

#### 3.8.2 SLAAC 地址的本质：不在 DHCP 租约中

SLAAC（Stateless Address Autoconfiguration）是 IPv6 的无状态地址自动配置机制：
- 客户端从 RA 消息中获取前缀
- 自己生成接口标识（EUI-64 或隐私扩展临时地址）
- 通过 NDP（邻居发现协议）做地址冲突检测
- **不经过 DHCPv6 服务器，不生成 DHCP 租约**

因此：
- `leaseIndex.byAddr` 中**没有**这些 SLAAC 地址
- `s.dhcp.MACByIP(slaacAddr)` → 返回 `nil`
- `s.dhcp.HostByIP(slaacAddr)` → 返回 `""`
- 按 MAC 配置的持久化客户端**无法通过 SLAAC 地址匹配**（IP→MAC 桥接断裂）

#### 3.8.3 SLAAC 环境下客户端识别的四条替代路径

当 DHCP 租约不可用时，客户端识别降级到以下四条路径，按优先级排列：

```
来源优先级（高 → 低）:
  SourcePersistent (持久化客户端)
  SourceHostsFile  (hosts 文件)
  SourceDHCP       (DHCP 租约)  ← SLAAC 下不可用
  SourceRDNS       (rDNS 反向解析)
  SourceARP        (ARP/NDP 邻居表)
  SourceWHOIS      (WHOIS 查询)
```

**路径 1：持久化客户端（按 IP / 子网匹配）**

`internal/client/index.go` → `findByIP()` / `findBySubnet()`

如果管理员手动为 SLAAC 地址配置了持久化客户端（按 IP 或子网），则直接命中。这是最可靠的方式，但需要手动维护。

**路径 2：hosts 文件匹配**

`internal/client/runtimeindex.go` → `SourceHostsFile`

系统 hosts 文件中如果配置了 IPv6 地址到主机名的映射，会被 `aghnet.HostsContainer` 加载并注入 runtimeIndex。

**路径 3：rDNS 反向解析（PTR 查询）**

**文件**：`internal/client/addrproc.go` → `DefaultAddrProc`

触发时机：**每次 DNS 请求时**异步触发

```go
// dnsforward/process.go:150-165
func (s *Server) processClientIP(ctx context.Context, l *slog.Logger, addr netip.Addr) {
    ...
    s.addrProc.Process(ctx, addr)  // 放入异步队列
}
```

处理流程：

```
DNS 请求到达
  └─ processClientIP(ip)
        └─ addrProc.Process(ip) → 放入 clientIPs channel（队列大小 255）
              │
              └─ process goroutine 消费队列
                    ├── p.rdns.Process(ip) → PTR 查询 + 缓存（TTL 1 小时）
                    │     └─ 有变化 → 返回 host
                    ├── p.whois.Process(ip) → WHOIS 查询
                    └── p.addrUpdater.UpdateAddress(ctx, ip, host, info)
                          └── storage.UpdateAddress()
                                └── runtimeIndex.setInfo(ip, SourceRDNS, []string{host})
```

rDNS 关键参数（`addrproc.go:129-141`）：
- `defaultQueueSize = 255`：IP 处理队列大小
- `defaultCacheSize = 10_000`：rDNS 缓存容量
- `defaultIPTTL = 1 * time.Hour`：rDNS 结果缓存 1 小时

**路径 4：ARP/NDP 邻居表**

**文件**：`internal/arpdb/arpdb.go` → `Neighbor` 结构

```go
type Neighbor struct {
    Name string          // 主机名（非所有平台都能获取）
    IP   netip.Addr      // IPv4 或 IPv6
    MAC  net.HardwareAddr // 硬件地址
}
```

触发时机：**每 10 分钟定时刷新**

`internal/home/clients.go:311` → `arpClientsUpdatePeriod = 10 * time.Minute`

`internal/client/storage.go:244-270` → `refreshARP()`

```go
func (s *Storage) refreshARP(ctx) {
    ...
    ns := s.arpDB.Neighbors()  // 从系统 NDP/ARP 表读取
    ...
    src := SourceARP
    s.runtimeIndex.clearSource(src)  // 先清空所有 ARP 来源

    for _, n := range ns {
        s.runtimeIndex.setInfo(n.IP, src, []string{n.Name})
        // ⚠️ 注意：这里只写入了 Name（主机名），没有写入 MAC！
    }

    s.runtimeIndex.removeEmpty()
}
```

> **重要发现**：ARP/NDP 刷新时 `setInfo` 只传了 `Name`，**没有将 MAC 地址写入 runtimeIndex**。这意味着 SLAAC 环境下，即使通过 NDP 知道了 IPv6 地址对应的 MAC，也无法用于 `findByMAC` 匹配持久化客户端。ARP 来源在 runtimeIndex 中只提供主机名，不提供 IP→MAC 的桥接能力。

#### 3.8.4 混合模式下的完整识别路径对比

同一台客户端同时拥有 DHCPv6 地址和 SLAAC 地址时，两条路径并行：

| 识别维度 | DHCPv6 地址 | SLAAC 地址 |
|---------|------------|-----------|
| IP→MAC 桥接 | ✅ `MACByIP()` 直接返回 | ❌ 需通过 ARP/NDP（但不写入 MAC 到 runtimeIndex） |
| Hostname 补全 | ✅ `HostByIP()` 从租约读取 | ✅ 通过 rDNS 或 ARP/NDP 的 Name 字段 |
| 匹配按 MAC 的持久化客户端 | ✅ 能匹配 | ❌ 不能匹配（无 MAC 桥接） |
| 匹配按 IP 的持久化客户端 | ✅ 能匹配 | ✅ 能匹配（直接按 IP） |
| 匹配按子网的持久化客户端 | ✅ 能匹配 | ✅ 能匹配 |
| 信息更新延迟 | 租约更新即更新 | rDNS 1 小时缓存 / ARP 10 分钟刷新 |
| 信息可靠性 | 高（DHCP 协议保证） | 中（依赖 DNS/邻居表） |

#### 3.8.5 实际请求路径时序（SLAAC 地址首次 DNS 查询）

```
T0: 客户端通过 SLAAC 生成 2001:db8::abcd，首次发送 DNS 查询到 AdGuard Home

T0.001s: processInitial 阶段
        ├── processClientIP(2001:db8::abcd) → addrProc 入队（异步）
        └── clientRequestFilteringSettings()
              └── ApplyClientFiltering(id, addr, setts)
                    ├── findByClientID() → 未命中
                    ├── findByIP() → 未命中
                    ├── findBySubnet() → 可能命中（按子网配置）
                    ├── s.dhcp.MACByIP(addr) → 返回 nil（无 DHCPv6 租约）
                    └── findByMAC → 不触发（没有 MAC）
              → 应用全局默认设置或子网级设置
        → DNS 请求被正常处理

T0.05s: addrProc goroutine 从队列取出 2001:db8::abcd
        ├── rdns.Process() → 发起 PTR 查询
        └── WHOIS 查询（如果启用）

T0.1s: rDNS 返回结果 "client-pc.localdomain"
        └── addrUpdater.UpdateAddress()
              └── runtimeIndex.setInfo(2001:db8::abcd, SourceRDNS, ["client-pc.localdomain"])

T1: 客户端第二次 DNS 查询
        └── ApplyClientFiltering → 仍走相同路径
              └── ClientRuntime() → 现在有 SourceRDNS 的主机名
                    → 但 Hostname 仅用于日志展示，不用于策略匹配
                    → 策略叠加仍依赖 IP/子网/ClientID
```

#### 3.8.6 SLAAC 环境下的策略匹配限制

**核心限制：SLAAC 地址无法通过 MAC 匹配持久化客户端**

原因链：
1. SLAAC 地址不在 DHCP 租约中 → `dhcp.MACByIP()` 返回 nil
2. ARP/NDP 邻居表虽然有 MAC，但 `refreshARP()` 只写入 Name，不写入 MAC 到 runtimeIndex
3. `ApplyClientFiltering` 中的 `findByIP` 失败后，没有其他 IP→MAC 的转换路径
4. 最终 `findByMAC` 不触发 → 按 MAC 配置的持久化客户端对 SLAAC 地址无效

**SLAAC 环境下有效的策略配置方式**：
- ✅ 按 IP 地址配置（手动指定 SLAAC 地址）
- ✅ 按子网/CIDR 配置（匹配整个前缀）
- ✅ 按 ClientID 配置（DNS-over-HTTPS/QUIC 等带 ClientID 的协议）
- ❌ 按 MAC 配置（DHCP 链路不通，ARP/NDP 链路不用于策略匹配）

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
| DHCP 租约结构 | `internal/dhcpsvc/lease.go` | `Lease` 结构体、`updateExpiry` |
| 租约索引 | `internal/dhcpsvc/leaseindex.go` | `leaseIndex.add/remove/update` |
| DHCPv4 处理器 | `internal/dhcpsvc/handler4.go` | `handleDiscover/handleRenew/handleRelease/handleDecline` |
| DHCPv6 处理器 | `internal/dhcpsvc/handler6.go` | `handleSolicit/handleRequest/handleRenew/handleRebind` |
| 租约分配与过期回收 | `internal/dhcpsvc/interface.go` | `allocateLease/reserveLease/findExpiredLease/blockLease` |
| 续约响应 | `internal/dhcpsvc/v4.go` | `updateAndRespond/respondACK` |
| DHCPv4 时间选项 | `internal/dhcpsvc/options4.go` | `appendTimeOptions`（T1/T2 TODO） |
| DHCPv6 T1/T2 | `internal/dhcpsvc/v6.go` | `t1/2` 字段（0.5×/0.8×LeaseDuration） |
| 全局读写锁 | `internal/dhcpsvc/server.go` | `DHCPServer.leasesMu`（所有接口共享） |
| 租约查询接口 | `internal/dhcpsvc/server.go` | `Leases/HostByIP/MACByIP/IPByHost` |
| 持久化 | `internal/dhcpsvc/db.go` | `dbLoad/dbStore` |
| 运行时客户端缓存 | `internal/client/runtimeindex.go` | `runtimeIndex.setInfo/clearSource/removeEmpty` |
| 客户端存储 | `internal/client/storage.go` | `Find/findByIP/ApplyClientFiltering/UpdateDHCP/ClientRuntime` |
| 运行时客户端 | `internal/client/client.go` | `Runtime.Info()`（来源优先级）、`Runtime.unset/isEmpty` |
| 空 DHCP 实现 | `internal/dhcpsvc/dhcpsvc.go` | `EmptyDHCP`（第三方 DHCP 场景） |
| DNS 过滤设置 | `internal/dnsforward/filter.go` | `clientRequestFilteringSettings` |
| 查询日志补全 | `internal/querylog/search.go` | `client()` |
| 查询日志请求级缓存 | `internal/querylog/client.go` | `clientCache/clientCacheKey` |
| 策略叠加 | `internal/client/storage.go` | `ApplyClientFiltering()` |
| DHCP 刷新触发 | `internal/home/clientshttp.go` | `handleGetClients`（访问 `/control/clients` 时调用 `UpdateDHCP`） |
| DHCPv4 relay 支持 | `internal/dhcpsvc/v4.go` | `newIPv4UDPLayers()`（giaddr 路由）、`respondNAK`（广播位处理） |
| rDNS 反向解析地址处理器 | `internal/client/addrproc.go` | `DefaultAddrProc/processRDNS/Process`（异步队列 + 1h 缓存） |
| ARP/NDP 邻居表 | `internal/arpdb/arpdb.go` | `Neighbor/Interface`（支持 IPv4+IPv6） |
| ARP 刷新定时 | `internal/client/storage.go` | `refreshARP()`（每 10 分钟全量刷新） |
| DNS 请求触发 rDNS | `internal/dnsforward/process.go` | `processClientIP()`（每次 DNS 请求异步入队） |
| SLAAC 模式配置 | `internal/dhcpsvc/v6.go` | `RASLAACOnly/RAAllowSLAAC`（三模式） |

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

9. **续约时间不对称实现**：DHCPv6 明确计算并发送 T1(50%)/T2(80%) 续约时间窗口，DHCPv4 仅发送剩余租期、缺少 T1/T2 选项（代码 TODO）。服务器端 lease.Expiry 始终保留初次分配的绝对过期时间，不随续约前移，通过响应时计算 `Expiry - now` 剩余时间返回给客户端实现续约

10. **长租约缓存惰性收敛**：runtimeIndex 无 TTL 自动过期，长租约（多天/周）场景下续约期间 Hostname 变更、过期租约回收复用等变更只能通过 `ClientRuntime()` 每次 DNS 请求时的惰性查询或用户访问 `/control/clients` 触发的全量 `UpdateDHCP()` 刷新收敛，存在分钟级到天级的不一致窗口

11. **双栈 hostname 索引冲突 BUG**：IPv4 和 IPv6 共享同一个 `leaseIndex.byName` 哈希表，同一客户端（同 MAC 同 Hostname）同时获取 v4/v6 租约时，v6 的 `byName` 写入会因冲突检测失败被丢弃，导致 v6 IP 的 Hostname 补全和 `IPByHost` 反向映射失效（仅 v4 可见），但 `byAddr` 的 MAC 解析不受影响

12. **主备部署识别割裂**：多台 AdGuard Home 作为 DHCP 主备部署时，实例之间无租约同步机制，客户端识别链路仅连接当前实例的 DHCP 服务，备机分配的租约在主机上不可见，按 IP/Hostname 匹配策略会失效，仅按 MAC 配置的持久化客户端在两台机器上都能可靠匹配

13. **DHCPv4 relay 透明支持**：DHCPv4 中继场景下 CHADDR 字段保留客户端真实 MAC，租约写入和客户端识别链路完全不受影响，`MACByIP`/`HostByIP` 正常工作。但不支持 Option 82 中继代理信息，无法基于 relay 端口做细粒度区分；DHCPv6 relay 完全不支持（消息类型未实现），IPv6 跨子网环境下租约无法创建

14. **SLAAC 环境下 IP→MAC 桥接断裂**：SLAAC 地址不在 DHCP 租约中，`dhcp.MACByIP()` 直接失效。替代路径有四条：持久化客户端（按 IP/子网）、hosts 文件、rDNS 反向解析（每次 DNS 请求异步触发，1 小时缓存）、ARP/NDP 邻居表（每 10 分钟刷新）。核心限制是 **ARP/NDP 刷新只写入主机名不写入 MAC**，导致 SLAAC 地址无法通过 MAC 匹配持久化客户端，按 MAC 配置的策略在纯 SLAAC 环境下完全失效

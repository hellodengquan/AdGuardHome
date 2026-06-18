# AdGuard Home DHCP 模块运作机制分析

## 一、模块架构概述

AdGuard Home 中存在两套 DHCP 实现并存：

| 实现版本 | 目录位置 | 依赖库 | 特点 |
|---------|---------|--------|------|
| 旧版 | `internal/dhcpd/` | `insomniacslk/dhcp` | 功能完整，生产使用 |
| 新版 | `internal/dhcpsvc/` | `google/gopacket` | 重构中，更底层的数据包处理 |

两套实现共享相同的 `Lease` 数据结构定义（位于 `internal/dhcpsvc/lease.go`）。

---

## 二、DHCP 请求识别与分流

### 2.1 数据包捕获入口

**新版实现（dhcpsvc）**：
- `DHCPServer.Start()` 为每个启用的网络接口启动独立 goroutine
- `serveEther4()` 持续读取网络数据包（`handle.go:18-33`）
- 使用 `gopacket.PacketSource` 从网络设备读取原始数据包

```go
// handle.go:18-33
func (srv *DHCPServer) serveEther4(ctx context.Context, iface *dhcpInterfaceV4, nd NetworkDevice) {
    src := gopacket.NewPacketSource(nd, nd.LinkType())
    for pkt := range src.Packets() {
        fd := newFrameData4(ctx, srv.logger, pkt, nd)
        if fd == nil { continue }
        err := srv.serveV4(ctx, iface, pkt, fd)
    }
}
```

**旧版实现（dhcpd）**：
- 使用 `insomniacslk/dhcp` 库的 `server4.Server`
- 通过 `server4.ListenAndServe()` 启动服务

### 2.2 协议层识别

`newFrameData4()` 执行多层过滤（`handle.go:64-104`）：

1. **以太网层检查**：提取 Ethernet 层，过滤非以太网包
2. **IPv4 层检查**：提取 IPv4 层，过滤非 IPv4 包
3. **本地地址匹配**：确认目标 IP 是本机地址

### 2.3 DHCP 消息类型识别

`serveV4()` 进行 DHCP 特定识别（`handler4.go:17-52`）：

```go
// handler4.go:17-52
func (srv *DHCPServer) serveV4(ctx context.Context, iface *dhcpInterfaceV4, pkt gopacket.Packet, fd *frameData4) (err error) {
    // 1. 提取 DHCPv4 层
    req, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
    
    // 2. 检查操作码（必须是 Request）
    if req.Operation != layers.DHCPOpRequest { return nil }
    
    // 3. 提取消息类型选项
    typ, ok := msg4Type(req)
    
    // 4. 分流到具体处理器
    return iface.handleDHCPv4(ctx, typ, req, fd)
}
```

### 2.4 请求分流逻辑

`handleDHCPv4()` 根据消息类型分流（`handler4.go:63-84`）：

| 消息类型 | 处理函数 | 说明 |
|---------|---------|------|
| `DHCPMsgTypeDiscover` | `handleDiscover()` | 客户端首次发现 |
| `DHCPMsgTypeRequest` | `handleRequest()` | 包含 SELECTING/INIT-REBOOT/RENEW 三种状态 |
| `DHCPMsgTypeRelease` | `handleRelease()` | 客户端主动释放 |
| `DHCPMsgTypeDecline` | `handleDecline()` | 客户端拒绝分配的 IP |

### 2.5 REQUEST 消息二次分流

`handleRequest()` 根据选项进一步分流（`handler4.go:133-181`）：

```go
switch {
case hasSrvID && !srvID.IsUnspecified():
    // SELECTING 状态 - 响应 DHCPOFFER
    iface.handleSelecting(ctx, req, fd, reqIP)
case hasReqIP && !reqIP.IsUnspecified():
    // INIT-REBOOT 状态 - 客户端重启后验证配置
    iface.handleInitReboot(ctx, req, fd, reqIP)
default:
    // RENEWING/REBINDING 状态 - 续约请求
    iface.handleRenew(ctx, req, fd, ip)
}
```

---

## 三、租约信息存储位置

### 3.1 核心数据结构

`Lease` 结构体定义（`lease.go:24-41`）：

```go
type Lease struct {
    IP       netip.Addr        // 分配的 IP 地址
    Expiry   time.Time         // 过期时间（静态租约忽略）
    Hostname string            // 客户端主机名
    HWAddr   net.HardwareAddr  // MAC 地址（6/8/20 字节）
    IsStatic bool              // 是否为静态绑定
}
```

### 3.2 内存存储结构

#### 新版实现（dhcpsvc）三层索引：

1. **全局索引 `leaseIndex`**（`leaseindex.go:17-32`）：
   - `byAddr map[netip.Addr]*Lease` - IP 快速查找
   - `byName map[string]*Lease` - 主机名快速查找（小写）
   - `dbFilePath string` - 持久化文件路径

2. **接口级存储 `netInterface`**（`interface.go:47-74`）：
   - `leases map[macKey]*Lease` - 按 MAC 索引的租约表
   - `leasedOffsets *bitSet` - 已分配 IP 偏移位图
   - `addrSpace ipRange` - IP 地址范围

3. **MAC 键转换**（`interface.go:28-42`）：
   - 根据 MAC 长度转换为定长数组作为 map key
   - 支持 6 字节（EUI-48）、8 字节（EUI-64）、20 字节（InfiniBand）

#### 旧版实现（dhcpd）三层索引（`v4_unix.go:52-60`）：
- `leases []*dhcpsvc.Lease` - 租约数组
- `hostsIndex map[string]*dhcpsvc.Lease` - 主机名索引
- `ipIndex map[netip.Addr]*dhcpsvc.Lease` - IP 索引
- `leasedOffsets *bitSet` - 已分配位图

### 3.3 持久化存储

#### 存储位置：
- 配置项：`Config.DBFilePath`（`config.go:38`）
- 默认路径：`{DataDir}/leases.json`（`dhcpd.go:122`）

#### 文件格式（`db.go:28-46`）：

```json
{
    "version": 1,
    "leases": [
        {
            "ip": "192.168.1.100",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "my-laptop",
            "expires": "2024-01-15T10:30:00Z",
            "static": false
        }
    ]
}
```

#### 序列化规则：
- 静态租约 `expires` 字段为空字符串（`db.go:56-62`）
- 动态租约使用 RFC3339 格式时间
- 按主机名字典序排序存储（`db.go:187-188`）

### 3.4 持久化触发时机

每次租约变更立即写入磁盘：
- `leaseIndex.add()` → `dbStore()`（`leaseindex.go:98`）
- `leaseIndex.remove()` → `dbStore()`（`leaseindex.go:135`）
- `leaseIndex.update()` → `dbStore()`（`leaseindex.go:170`）
- `leaseIndex.clear()` → `dbStore()`（`leaseindex.go:64`）

使用 `renameio/maybe.WriteFile` 原子写入，避免文件损坏（`db.go:197`）。

---

## 四、续约与静态绑定到期清理的衔接

### 4.1 续约机制

#### 续约触发场景：

1. **RENEW 状态**（`handler4.go:286-320`）：
   - 客户端在租期 50% 时单播发送续约请求
   - `ciaddr` 字段包含当前 IP
   - 无 `ServerID` 和 `RequestedIP` 选项

2. **REBIND 状态**：
   - 租期 87.5% 时仍未收到确认，广播请求
   - 处理逻辑与 RENEW 相同

#### 续约处理流程（`handleRenew`）：

```go
// handler4.go:286-320
func (iface *dhcpInterfaceV4) handleRenew(ctx context.Context, req *layers.DHCPv4, fd *frameData4, ip netip.Addr) {
    // 1. 按 MAC 查找租约
    lease, hasLease := iface.common.leases[mk]
    
    // 2. 验证 IP 匹配
    if lease.IP != ip {
        iface.respondNAK(ctx, req, fd, idOpt)
        return
    }
    
    // 3. 更新租期并响应 ACK
    iface.updateAndRespond(ctx, l, req, lease, fd, idOpt)
}
```

#### 租期更新逻辑（`updateAndRespond`）：

```go
// v4.go:355-374
func (iface *dhcpInterfaceV4) updateAndRespond(...) {
    // 合并主机名（优先使用客户端提供的）
    lease.Hostname = cmp.Or(hostname4(req), lease.Hostname)
    
    // 更新租期（静态租约跳过）
    err := iface.updateLease(ctx, lease)
}
```

#### 关键方法 `updateExpiry`（`lease.go:71-82`）：

```go
func (l *Lease) updateExpiry(clock timeutil.Clock, ttl time.Duration) {
    // 静态租约不更新过期时间
    if l.IsStatic { return }
    
    // 仅在过期后更新（续约时总是会更新）
    now := clock.Now()
    if now.Before(l.Expiry) { return }
    
    l.Expiry = now.Add(ttl)
}
```

### 4.2 静态绑定特性

#### 静态租约定义：
- `IsStatic = true`
- `Expiry` 字段被忽略（`lease.go:72-73`）
- 不受租期限制，永久有效

#### 静态租约管理（`v4_unix.go:385-439`）：

```go
func (s *v4Server) AddStaticLease(l *dhcpsvc.Lease) (err error) {
    l.IsStatic = true
    
    // 1. 先删除同 MAC/IP 的动态租约
    err = s.rmDynamicLease(l)
    
    // 2. 添加静态租约
    err = s.addLease(l)
}
```

#### 静态与动态租约的冲突处理（`v4_unix.go:291-314`）：

`rmDynamicLease()` 确保静态租约添加时：
- 删除同 MAC 的动态租约
- 删除同 IP 的动态租约
- 清空冲突主机名的动态租约主机名

### 4.3 到期清理机制

#### 惰性清理策略：

**没有独立的后台清理 goroutine**，清理发生在需要分配新 IP 时：

```go
// interface.go:229-267
func (iface *netInterface) reserveLease(ctx context.Context, mac net.HardwareAddr, clock timeutil.Clock) (lease *Lease, err error) {
    // 1. 尝试分配新 IP
    nextIP := iface.nextIP()
    if nextIP != (netip.Addr{}) {
        // 有空闲 IP，直接分配
        return &Lease{...}, nil
    }
    
    // 2. 无空闲 IP，查找过期租约
    lease = iface.findExpiredLease(clock.Now())
    if lease == nil {
        return nil, errors.Error("no addresses available")
    }
    
    // 3. 回收过期租约
    err = iface.index.remove(ctx, iface.logger, lease, iface)
    
    // 4. 重用该 IP 分配给新客户端
    lease.HWAddr = slices.Clone(mac)
    lease.Hostname = ""
    lease.IsStatic = false
    lease.updateExpiry(clock, iface.leaseTTL)
    
    return lease, nil
}
```

#### `findExpiredLease` 逻辑（`interface.go:173-181`）：

```go
func (iface *netInterface) findExpiredLease(now time.Time) (l *Lease) {
    for _, lease := range iface.leases {
        // 静态租约永不过期
        if !lease.IsStatic && lease.Expiry.Before(now) {
            return lease
        }
    }
    return nil
}
```

### 4.4 阻塞租约机制

当 ICMP 检测发现 IP 已被占用时（`interface.go:188-224`）：

```go
func (iface *netInterface) allocateLease(...) {
    for {
        lease, err = iface.reserveLease(...)
        
        // 检查 IP 可用性
        ok, err = checker.IsAvailable(lease.IP)
        if ok {
            // 可用，正常分配
            return lease, nil
        }
        
        // 不可用，标记为阻塞
        err = iface.blockLease(ctx, lease, clock)
    }
}
```

`blockLease()` 将租约转为阻塞状态（`interface.go:132-153`）：
- MAC 设为全零（`blockedHardwareAddr`）
- 主机名清空
- 设置一个租期的阻塞时间
- 保留在全局索引中，避免再次分配

### 4.5 主动释放处理

`handleRelease()` 处理客户端主动释放（`handler4.go:374-412`）：

```go
func (iface *dhcpInterfaceV4) handleRelease(ctx context.Context, req *layers.DHCPv4) {
    // 1. 验证 IP 在子网内
    // 2. 查找租约并验证匹配
    // 3. 从索引和接口中移除
    err := iface.common.index.remove(ctx, l, lease, iface.common)
}
```

---

## 五、完整数据流转图

```
客户端请求
    ↓
[serveEther4] 数据包捕获（goroutine/接口）
    ↓
[newFrameData4] 协议层过滤（Ethernet→IPv4）
    ↓
[serveV4] DHCP 层识别 → 提取消息类型
    ↓
[handleDHCPv4] 按消息类型分流
    ├─ DISCOVER → handleDiscover → 查找/分配租约 → OFFER
    ├─ REQUEST  → 二次分流
    │   ├─ SELECTING    → handleSelecting    → 确认租约 → ACK
    │   ├─ INIT-REBOOT  → handleInitReboot  → 验证配置 → ACK/NAK
    │   └─ RENEW        → handleRenew        → 更新租期 → ACK/NAK
    ├─ RELEASE  → handleRelease  → 移除租约
    └─ DECLINE  → handleDecline  → 阻塞租约
        ↓
内存索引更新（leaseIndex + netInterface）
    ↓
[dbStore] 原子写入 leases.json
```

---

## 七、租约索引的并发保护机制

### 7.1 多并发方分析

DHCP 模块存在三类并发读写方：

| 并发方 | 来源 | 典型操作 | 读写类型 |
|-------|------|---------|---------|
| 接口 goroutine | `DHCPServer.Start()` 中每个接口启动一个 `serveEther4`（`server.go:166`） | DISCOVER/REQUEST/RELEASE/DECLINE 处理 | 读 + 写 |
| HTTP API 线程 | Web 管理后台调用 `/control/dhcp/*` 端点（`http_unix.go:787-800`） | 查询租约、增删改静态租约、重置配置 | 读 + 写 |
| DNS 查询线程 | 域名反查时调用 `HostByIP`/`MACByIP`/`IPByHost` | 通过 IP 查主机名等 | 只读 |

### 7.2 新版实现（dhcpsvc）：全局共享读写锁

#### 锁的层级结构——单把全局锁

核心设计是**所有接口共享同一把读写锁**，而非每接口独立一把：

```go
// server.go:46-50
type DHCPServer struct {
    // leasesMu protects the leases index as well as leases in the interfaces.
    leasesMu *sync.RWMutex

    // leases stores the DHCP leases for quick lookups.
    leases *leaseIndex
}
```

在创建接口时，各接口的 `indexMu` 直接**指向同一把锁**：

```go
// v4.go:202-217
iface = &dhcpInterfaceV4{
    common: &netInterface{
        indexMu:       srv.leasesMu,   // 指针赋值，所有接口共用同一把锁
        index:         srv.leases,
        leases:        map[macKey]*Lease{},
        leasedOffsets: newBitSet(),
        // ...
    },
}
```

#### 锁的使用模式

| 操作类型 | 锁模式 | 使用位置 |
|---------|--------|---------|
| 读操作 | `RLock` / `RUnlock` | `server.go:198-246` |
| 写操作 | `Lock` / `Unlock` | `server.go:252-403` |
| 请求处理 | `Lock` / `Unlock` | `handler4.go` 所有 handler |
| 持久化写入 | `Lock` / `Unlock` | `dbStore()` 调用方需持有锁（`db.go:175` 注释） |

**读操作示例** — DNS 查询场景：

```go
// server.go:212-222
func (srv *DHCPServer) HostByIP(ip netip.Addr) (host string) {
    srv.leasesMu.RLock()
    defer srv.leasesMu.RUnlock()

    if l, ok := srv.leases.leaseByAddr(ip); ok {
        return l.Hostname
    }
    return ""
}
```

**写操作示例** — 添加租约：

```go
// server.go:272-301
func (srv *DHCPServer) AddLease(ctx context.Context, l *Lease) (err error) {
    srv.leasesMu.Lock()
    defer srv.leasesMu.Unlock()

    err = srv.leases.add(ctx, srv.logger, l, iface)
    // add() 内部会调用 dbStore() 写磁盘
}
```

**请求处理示例** — DISCOVER 处理：

```go
// handler4.go:88-125
func (iface *dhcpInterfaceV4) handleDiscover(ctx context.Context, req *layers.DHCPv4, fd *frameData4) {
    iface.common.indexMu.Lock()   // 本质是 srv.leasesMu.Lock()
    defer iface.common.indexMu.Unlock()

    lease, hasLease := iface.common.leases[mk]
    if hasLease {
        lease.updateExpiry(iface.clock, iface.common.leaseTTL)
        iface.respondOffer(...)
        return
    }
    lease, err := iface.common.allocateLease(ctx, mac, ...)
    // ...
}
```

#### 设计权衡

**优势**：
- 简单正确：全局索引 `leaseIndex`（`byAddr`/`byName`）天然跨接口，一把锁避免了多锁死锁风险
- 读并发友好：DNS 查询等只读操作可并行，不阻塞彼此

**劣势**：
- 多接口串行化：`eth0` 和 `eth1` 同时处理 DHCP 请求时需要排队，无法真正并行
- 粗粒度：任何接口的写操作都会阻塞其他所有接口的读写

### 7.3 旧版实现（dhcpd）：协议独立互斥锁

旧版实现采用**每个协议版本一把互斥锁**：

```go
// v4_unix.go:45-46
// leasesLock protects leases, hostsIndex, ipIndex, and leasedOffsets.
leasesLock sync.Mutex
```

v4 和 v6 各自有独立的 `leasesLock`，互不影响。所有操作（无论读写）都使用同一把互斥锁，没有读写锁区分。

```go
// v4_unix.go:124-133
func (s *v4Server) HostByIP(ip netip.Addr) (host string) {
    s.leasesLock.Lock()
    defer s.leasesLock.Unlock()

    if l, ok := s.ipIndex[ip]; ok {
        return l.Hostname
    }
    return ""
}
```

### 7.4 HTTP API 与接口 goroutine 的竞争场景

以添加静态租约为例，完整并发时序：

```
HTTP 线程 (POST /control/dhcp/add_static_lease)
  └─ handleDHCPAddStaticLease()
       └─ s.srv4.AddStaticLease(lease)                dhcpd/v4_unix.go
            └─ s.leasesLock.Lock()                    ▓▓ 持有写锁
                 ├─ s.rmDynamicLease(l)               删除冲突的动态租约
                 ├─ s.addLease(l)                     添加静态租约到内存索引
                 └─ s.leasesLock.Unlock()              ░░ 释放锁
            └─ s.conf.notify(LeaseChangedDBStore)
                 └─ s.dbStore()                       写入 leases.json

接口 A goroutine (处理 DHCPREQUEST RENEW)
  └─ handleRenew()                                    dhcpsvc/handler4.go
       └─ iface.common.indexMu.Lock()                 ▓▓ 等待锁获取
            ├─ 查找租约、验证 IP
            ├─ updateAndRespond() → updateLease()
            │    └─ leaseIndex.update() → dbStore()  写入 leases.json
            └─ iface.common.indexMu.Unlock()          ░░ 释放锁

DNS 查询线程 (HostByIP)
  └─ srv.leasesMu.RLock()                              ▓▓ 持有读锁（与其他读并行）
  └─ srv.leases.leaseByAddr(ip)                        只读操作
  └─ srv.leasesMu.RUnlock()                            ░░ 释放
```

### 7.5 锁保护范围覆盖

内存索引中以下所有数据结构都受同一把锁保护：

```
┌─ leaseIndex ──────────────────────────┐
│  byAddr  map[netip.Addr]*Lease        │  ← 全局
│  byName  map[string]*Lease            │  ← 全局
└───────────────────────────────────────┘
         ▲ 都通过 leasesMu 保护
┌─ netInterface(eth0) ─────────────────┐   ┌─ netInterface(eth1) ──────────┐
│  leases         map[macKey]*Lease    │   │  leases         map[...]*... │
│  leasedOffsets  *bitSet              │   │  leasedOffsets  *bitSet       │
│  addrSpace      ipRange              │   │  addrSpace      ipRange       │
└───────────────────────────────────────┘   └───────────────────────────────┘
```

### 7.6 注意事项：持久化写入的锁前置条件

`dbStore()` 本身不加锁，它要求**调用方必须已经持有 `leasesMu` 写锁**：

```go
// db.go:174-175
// writeDB writes leases to the database file.  It expects the
// [DHCPServer.leasesMu] to be locked.
func (idx *leaseIndex) dbStore(ctx context.Context, logger *slog.Logger) (err error) {
    for l := range idx.rangeLeases {
        // 遍历 byName map，无需额外加锁
    }
    // 原子写磁盘
}
```

所有调用路径（`add`/`remove`/`update`/`clear`）都从 `server.go` 的 `Lock()`/`Unlock()` 块内进入，满足该约束。

---

## 八、服务重启时租约恢复与过期校验

### 8.1 整体启动时序

服务启动（或配置变更重启）时的完整流程：

```
Create() / handleDHCPSetConfig()
    │
    ├─ 1. 数据迁移（如有旧版 db）
    │     └─ migrateDB()                        dhcpd/migrate.go
    │           └─ 读取 leases.db → 转换格式 → 写入 leases.json → 删除旧文件
    │
    ├─ 2. 从 JSON 加载租约
    │     └─ dbLoad()                           dhcpd/db.go:93-149
    │           ├─ 读取 leases.json 文件
    │           ├─ JSON 反序列化为 []*dbLease
    │           ├─ 逐个转换为 *dhcpsvc.Lease
    │           ├─ 按 IP 版本分流 v4/v6
    │           └─ ResetLeases() 重建内存索引
    │
    └─ 3. 启动 DHCP 服务（Start → serveEther4 goroutine）
```

### 8.2 数据迁移（首次升级场景）

`migrateDB()` 处理历史遗留的旧格式数据库：

```go
// migrate.go:63-105
func migrateDB(conf *ServerConfig) (err error) {
    // 1. 检查是否存在旧格式文件 leases.db
    oldLeasesPath := filepath.Join(conf.WorkDir, "leases.db")
    oldLeases, err := readOldDB(oldLeasesPath)
    if oldLeases == nil {
        return nil  // 无需迁移
    }

    // 2. 格式转换：旧 leaseJSON → 新 dbLease
    for _, l := range oldLeases {
        leases = append(leases, &dbLease{
            Expiry:   time.Unix(l.Expiry, 0).Format(time.RFC3339),  // Unix → RFC3339
            HWAddr:   net.HardwareAddr(l.HWAddr).String(),         // []byte → 字符串
            // 静态租约识别：旧版用 Expiry==1 标记
            IsStatic: l.Expiry == leaseExpireStatic,  // leaseExpireStatic = 1
        })
    }

    // 3. 写入新格式 leases.json，删除旧文件
    err = writeDB(dataDirPath, leases)
    return os.Remove(oldLeasesPath)
}
```

### 8.3 dbLoad() 加载流程

核心加载逻辑在 `dhcpd/db.go:93-149`：

```go
func (s *server) dbLoad() (err error) {
    // 步骤1: 读取文件
    data, err := os.ReadFile(s.conf.dbFilePath)
    if errors.Is(err, os.ErrNotExist) {
        return nil  // 文件不存在则跳过，首次启动
    }

    // 步骤2: JSON 解码
    dl := &dataLeases{}
    err = json.Unmarshal(data, dl)

    // 步骤3: 逐条转换与校验
    leases4 := []*dhcpsvc.Lease{}
    leases6 := []*dhcpsvc.Lease{}
    for i, l := range dl.Leases {
        // 3a. MAC 地址解析
        lease, err = l.toLease()  // db.go:69-90
        if err != nil {
            log.Info("dhcp: invalid lease: %s", err)  // 转换失败仅记录日志
            continue                                   // 跳过坏条目，不中断整体加载
        }

        // 3b. 按 IP 版本分类
        if lease.IP.Is4() {
            leases4 = append(leases4, lease)
        } else {
            leases6 = append(leases6, lease)
        }
    }

    // 步骤4: 重建内存索引
    err = s.srv4.ResetLeases(leases4)
    if s.srv6 != nil {
        err = s.srv6.ResetLeases(leases6)
    }

    log.Info("dhcp: loaded leases v4:%d  v6:%d  total-read:%d from DB", ...)
    return nil
}
```

### 8.4 dbLease → Lease 转换与字段校验

`toLease()` 执行核心字段校验（`dhcpd/db.go:69-90`）：

```go
func (dl *dbLease) toLease() (l *dhcpsvc.Lease, err error) {
    // MAC 格式校验：xx:xx:xx:xx:xx:xx
    mac, err := net.ParseMAC(dl.HWAddr)
    if err != nil {
        return nil, fmt.Errorf("parsing hardware address: %w", err)
    }

    expiry := time.Time{}
    if !dl.IsStatic {
        // 动态租约：RFC3339 时间格式校验
        expiry, err = time.Parse(time.RFC3339, dl.Expiry)
        if err != nil {
            return nil, fmt.Errorf("parsing expiry time: %w", err)
        }
    }

    return &dhcpsvc.Lease{
        Expiry:   expiry,
        IP:       dl.IP,
        Hostname: dl.Hostname,
        HWAddr:   mac,
        IsStatic: dl.IsStatic,
    }, nil
}
```

**可能跳过加载的场景**：
- MAC 格式非法（如 `invalid:mac:format`）
- 动态租约的 `expires` 时间格式不是 RFC3339
- 单个条目解析异常 → 日志告警 + 跳过

### 8.5 ResetLeases()：内存索引重建

加载的租约通过 `ResetLeases()` 注入内存并重建位图（`dhcpd/v4_unix.go:147-177`）：

```go
func (s *v4Server) ResetLeases(leases []*dhcpsvc.Lease) (err error) {
    s.leasesLock.Lock()
    defer s.leasesLock.Unlock()

    // 1. 清空所有旧索引
    s.leasedOffsets = newBitSet()
    s.hostsIndex = make(map[string]*dhcpsvc.Lease, len(leases))
    s.ipIndex = make(map[netip.Addr]*dhcpsvc.Lease, len(leases))
    s.leases = nil

    // 2. 动态租约主机名规范化
    for _, l := range leases {
        if !l.IsStatic {
            l.Hostname = s.validHostnameForClient(l.Hostname, l.IP)
        }

        // 3. 重新添加：校验唯一性、更新位图
        err = s.addLease(l)
        if err != nil {
            log.Error("dhcpv4: reset: re-adding a lease for %s (%s): %s",
                l.IP, l.HWAddr, err)  // 重复 IP/MAC 记错误日志，跳过
            continue
        }
    }

    return nil
}
```

`addLease()` 内部会：
- 检查 IP 是否在地址范围内（动态租约）
- 检查 IP 是否在子网内（静态租约）
- 检查主机名唯一性
- 分配 `leasedOffsets` 位图对应的 bit

### 8.6 过期项的处理策略

**重启加载时不主动清理过期动态租约**，原因如下：

1. **无显式过期校验**：`dbLoad()` 和 `ResetLeases()` 代码中没有任何 `lease.Expiry.Before(now)` 的判断逻辑
2. **过期项保留的影响可控**：
   - 对外 API 查询时过滤：`GetLeases()` 只返回 `l.Expiry.After(now)` 的动态租约（`v4_unix.go:215-226`）
   - DNS 反查时过滤：`FindMACbyIP()` 只返回有效租约（`v4_unix.go:242-244`）
3. **最终通过惰性回收清理**：如第四章所述，当地址耗尽时 `findExpiredLease()` + `reserveLease()` 会逐步回收

因此重启后的内存中可能存在大量"僵尸"过期租约，但它们：
- 不影响外部 API 可见性
- 占用少量内存（每条约 100 字节）
- 在需要分配新 IP 时被自动回收或复用

### 8.7 配置变更时的重载

`handleDHCPSetConfig()` 执行"停服务 → 重建实例 → 重载 DB → 启动"的全流程（`http_unix.go:318-380`）：

```go
func (s *server) handleDHCPSetConfig(w http.ResponseWriter, r *http.Request) {
    // 1. 创建新 DHCPv4/v6 服务器实例（新配置）
    srv4, srv6, err := s.createServers(conf)

    // 2. 停止旧服务
    err = s.Stop()

    // 3. 替换配置
    s.setConfFromJSON(conf, srv4, srv6)
    s.conf.ConfModifier.Apply(ctx)

    // 4. 从 leases.json 重新加载所有租约
    err = s.dbLoad()   // ← 完整执行 8.3~8.5 流程

    // 5. 启动新服务
    if s.conf.Enabled {
        code, err = s.enableDHCP(ctx, conf.InterfaceName)
    }
}
```

配置变更导致的重载特点：
- 完全抛弃旧内存索引，从零重建
- `leases.json` 作为唯一真源（source of truth）
- 启动间隙的 DHCP 请求会丢失（无缓冲），取决于客户端重试机制

---

## 九、三条路径的加锁顺序对比与死锁风险

### 9.1 三条路径的操作范围

| 路径 | 典型调用入口 | 操作性质 | 触发来源 |
|------|------------|---------|---------|
| HTTP API | `AddStaticLease` / `RemoveStaticLease` / `UpdateStaticLease` / `Leases` | 读写混合 | Web 管理后台 POST/GET 请求 |
| 配置接口 | `handleDHCPSetConfig` → `ResetLeases` / `dbLoad` → `ResetLeases` | 批量写 | 配置变更、服务启动/重启 |
| DNS 查询 | `HostByIP` / `MACByIP` / `IPByHost` | 只读 | DNS 引擎域名反查查询 |

### 9.2 新版 dhcpsvc：加锁顺序一致，无交叉

新版三条路径统一使用同一把 `leasesMu` 全局读写锁，加锁顺序完全一致：

#### 路径一：DNS 查询（只读）

```go
// server.go:213-222  HostByIP 示例
func (srv *DHCPServer) HostByIP(ip netip.Addr) (host string) {
    srv.leasesMu.RLock()      // ① 加读锁
    defer srv.leasesMu.RUnlock()
    // 读取 srv.leases.leaseByAddr(ip)  ← ② 仅访问内存
    return l.Hostname
}
```

`Leases()`、`HostByIP()`、`MACByIP()`、`IPByHost()` 四个查询方法模式完全相同：
- 第一步：`RLock()`
- 第二步：直接访问内存索引
- 第三步：`defer RUnlock()`
- **全程无嵌套锁、无磁盘 IO**

#### 路径二：HTTP API（写操作）

```go
// server.go:273-300  AddLease 示例
func (srv *DHCPServer) AddLease(ctx context.Context, l *Lease) (err error) {
    // ... ifaceForAddr() 先查接口（无锁） ...

    srv.leasesMu.Lock()         // ① 加写锁
    defer srv.leasesMu.Unlock()

    err = srv.leases.add(ctx, srv.logger, l, iface)
    // add() 内部:
    //   ② 修改内存: iface.addLease() + idx.byAddr[]/byName[]
    //   ③ 写磁盘:   idx.dbStore()  ← 持锁状态下写盘
    return nil
}
```

`AddLease`、`UpdateStaticLease`、`RemoveLease` 写操作模式：
- 第一步：`Lock()` 加写锁
- 第二步：修改 `netInterface.leases` 等内存数据结构
- 第三步：调用 `dbStore()` 写磁盘（**持锁状态下执行**）
- 第四步：`defer Unlock()`

#### 路径三：配置接口 — `Reset()` 全量清空

```go
// server.go:249-269
func (srv *DHCPServer) Reset(ctx context.Context) (err error) {
    srv.leasesMu.Lock()          // ① 加写锁
    defer srv.leasesMu.Unlock()

    for _, iface := range srv.interfaces4 {
        iface.common.reset()     // ② 清空各接口 leasedOffsets、leases
    }
    err = srv.leases.clear(ctx, srv.logger)
    // clear() 内部:
    //   ③ 清空 idx.byAddr、idx.byName
    //   ④ idx.dbStore()  ← 持锁状态下写空 JSON
    return nil
}
```

#### 加锁顺序结论（新版）

三条路径的加锁顺序严格一致：

```
DNS 查询:       RLock → 读内存 → RUnlock
HTTP API:       Lock  → 改内存 → 写盘(dbStore) → Unlock
配置 Reset:     Lock  → 清内存 → 写盘(dbStore) → Unlock
请求 goroutine: Lock  → 改内存 → 写盘(dbStore) → Unlock  (handler4.go/handler6.go)
```

**特征**：
- 所有路径都只获取**一把锁**：`leasesMu`
- 无任何嵌套锁（获取 A 锁后再获取 B 锁）
- 所有 `dbStore()` 调用都发生在持有 `leasesMu` 的状态下，满足 `db.go:175` 的前置条件
- 读操作之间可并行（RLock 共享），读/写、写/写之间互斥

### 9.3 旧版 dhcpd：加锁顺序有微妙差异

旧版三条路径的加锁顺序**不完全一致**，但由于只有一把 `leasesLock` 互斥锁，结构相对简单。

#### 路径一：DNS 查询

```go
// v4_unix.go:238-250  FindMACbyIP 示例
func (s *v4Server) FindMACbyIP(ip netip.Addr) (mac net.HardwareAddr) {
    s.leasesLock.Lock()           // ① 加互斥锁（无读写区分）
    defer s.leasesLock.Unlock()

    l, ok := s.ipIndex[ip]        // ② 访问内存索引
    if ok { return l.HWAddr }
    return nil
}
```

特点：使用互斥锁而非读写锁，读操作之间也需串行。

#### 路径二：HTTP API — 关键时序差异

`AddStaticLease` 的加锁/写盘时序与新版不同：

```go
// v4_unix.go:385-438
func (s *v4Server) AddStaticLease(l *dhcpsvc.Lease) (err error) {
    // ... 前置参数校验（MAC/hostname/IP 合法性，无锁） ...

    err = s.updateStaticLease(l)
    // updateStaticLease() 内部（v4_unix.go:518-533）:
    //   s.leasesLock.Lock()        ① 加锁
    //   s.rmDynamicLease(l)        ② 改内存
    //   s.addLease(l)              ③ 改内存
    //   s.leasesLock.Unlock()      ④ ← 在这里就释放锁了！

    // ⑤ 锁已释放，此时才触发通知写盘
    s.conf.notify(LeaseChangedDBStore)  // → onNotify() → s.dbStore()
    s.conf.notify(LeaseChangedAddedStatic)
    return nil
}
```

**与新版的根本差异**：
- 新版：`Lock → 改内存 → dbStore(持锁写盘) → Unlock`
- 旧版：`Lock → 改内存 → Unlock → dbStore(无锁读内存写盘)`

`dbStore()` 在旧版中读取内存时**不持有任何锁**：

```go
// db.go:152-167
func (s *server) dbStore() (err error) {
    leases := []*dbLease{}
    for _, l := range s.srv4.getLeasesRef() {  // ← 直接读 s.srv4.leases 切片，无锁
        leases = append(leases, fromLease(l))
    }
    // ... v6 同理 ...
    return writeDB(s.conf.dbFilePath, leases)
}

// v4_unix.go:180-182
func (s *v4Server) getLeasesRef() []*dhcpsvc.Lease {
    return s.leases   // 直接返回内部切片引用，不做复制
}
```

#### 路径三：配置接口 — dbLoad → ResetLeases

```go
// db.go:138-147（dbLoad 的最后几步）
func (s *server) dbLoad() (err error) {
    // ... JSON 解析（无锁）...
    err = s.srv4.ResetLeases(leases4)  // ← ResetLeases 内部持有 leasesLock
    // ...
}

// v4_unix.go:148-177
func (s *v4Server) ResetLeases(leases []*dhcpsvc.Lease) (err error) {
    s.leasesLock.Lock()              // ① 加锁
    defer s.leasesLock.Unlock()

    s.leasedOffsets = newBitSet()    // ② 全部清空
    s.hostsIndex = make(map[...], ...)
    s.ipIndex = make(map[...], ...)
    s.leases = nil

    for _, l := range leases {       // ③ 逐条重建
        err = s.addLease(l)
    }
    // ④ defer Unlock() — 全程无磁盘 IO
    return nil
}
```

注意：`ResetLeases` 本身不写盘，写盘由其调用方在外部完成：
- 冷启动时 `dbLoad()` 只负责加载，加载完成后不立即写盘（读盘后回写无意义）
- 配置变更时 `handleDHCPSetConfig` 流程结束后，**dbLoad 也不写盘**
- 只有 `resetLeases()`（HTTP `/control/dhcp/reset`）会在 `ResetLeases` 之后显式调用 `dbStore()`，此时也不持锁

### 9.4 死锁风险分析

#### 新版 dhcpsvc：无死锁风险

```
结论：死锁风险 = 0
```

**理由**：
1. **单把锁**：整个 DHCP 模块只使用 `leasesMu` 一把锁（`sync.RWMutex`），所有路径都只获取这一把锁
2. **无嵌套**：没有任何代码路径出现 "持有 A 锁 → 获取 B 锁" 的嵌套加锁模式
3. **锁时序一致**：所有写路径都是 `Lock → 内存操作 + dbStore → Unlock`，读路径 `RLock → 内存读 → RUnlock`
4. **无回调环路**：`dbStore` 内部通过 `rangeLeases` 遍历只读，不会反过来触发需要锁的操作
5. **defer 安全**：所有 `Lock()` 都紧跟 `defer Unlock()`，即使中间 `return` 或 panic 也能正确释放

典型死锁所需的四个条件（互斥、持有并等待、不可抢占、循环等待）中，**循环等待**不成立，因此不可能发生死锁。

#### 旧版 dhcpd：无死锁风险，但存在 data race

```
结论：死锁风险 = 0，但存在并发读写下的 data race
```

**死锁安全理由**：
- 同样是单把锁架构（v4 的 `leasesLock` 和 v6 的 `leasesLock` 完全独立，互不影响）
- v4 和 v6 之间没有互相调用的代码路径

**data race 风险（旧版独有）**：

时序图如下：

```
线程 A (HTTP API /control/dhcp/add_static_lease)
  s.leasesLock.Lock()                              ▓▓ 持锁
  s.rmDynamicLease() + s.addLease()                改内存
  s.leasesLock.Unlock()                            ░░ 释放
  s.conf.notify(DBStore)
    → onNotify() → s.dbStore()
       for _, l := range s.srv4.getLeasesRef() {   ░░ 无锁读 s.leases 切片
           ... 读取 l.Hostname / l.Expiry ...      ← 正在遍历
       }

                    ← 时间线 →

线程 B (eth0 goroutine 处理 DISCOVER)
  s.leasesLock.Lock()                              ▓▓ 获取锁
  s.addLease(l)
    s.leases = append(s.leases, l)                 ← 修改 s.leases 切片！
  s.leasesLock.Unlock()                            ░░ 释放
```

线程 A 在 **无锁状态** 下遍历 `s.leases` 切片，同时线程 B 可能持有锁正在 `append` 该切片 —— 这构成了 Go 的 data race（并发读写切片）。

实际后果：
- **理论最坏**：Go 运行时检测到并发 map 写入会直接 panic，但切片 append 的并发写通常不会被检测
- **实际后果**：
  - 遍历到的 `*Lease` 指针本身是内存安全的（指针复制是原子的）
  - 可能漏掉刚 append 的租约，或读到重复的条目
  - 但由于写 `leases.json` 是原子的（`maybe.WriteFile`），**磁盘文件不会损坏**
  - 最坏情况是这次 `dbStore` 写入的数据不完整（少几条租约），下次变更时会纠正

这是一个**可以工作但理论上不严谨**的设计，新版 dhcpsvc 通过持锁写盘消除了这个 race。

### 9.5 加锁时序对比总表

| 维度 | 新版 dhcpsvc | 旧版 dhcpd |
|------|------------|-----------|
| 锁类型 | `sync.RWMutex`（读写分离） | `sync.Mutex`（互斥） |
| 锁数量 | 1 把全局锁 | v4/v6 各 1 把，互不干扰 |
| DNS 查询加锁 | `RLock`（读之间可并行） | `Lock`（读也互斥） |
| HTTP API 写盘时机 | **持锁状态下** dbStore | **锁释放后** dbStore |
| 死锁风险 | 无 | 无 |
| data race | 无 | 有（dbStore 无锁读切片） |
| 锁持有时间 | 较长（含磁盘 IO） | 较短（仅内存操作） |
| 吞吐量 | 读密集场景更优 | 写密集场景写锁释放更快 |

---

## 十、ResetLeases 重建索引过程的锁状态还原逻辑

### 10.1 触发场景

`ResetLeases` 在三种场景下被调用：

| 场景 | 调用路径 | 输入来源 |
|------|---------|---------|
| 服务冷启动 | `dhcpd.Create()` → `dbLoad()` → `ResetLeases` | `leases.json` 文件解析结果 |
| 配置变更重启 | `handleDHCPSetConfig()` → `dbLoad()` → `ResetLeases` | `leases.json` 文件解析结果 |
| HTTP 重置 API | `/control/dhcp/reset` → `resetLeases()` → `ResetLeases(nil)` | 空切片（全部清空） |

### 10.2 锁的获取与释放

#### 新版 dhcpsvc — `Reset()`

```go
// server.go:249-269
func (srv *DHCPServer) Reset(ctx context.Context) (err error) {
    defer func() { err = errors.Annotate(err, "resetting leases: %w") }()

    srv.leasesMu.Lock()          // ① 获取写锁
    defer srv.leasesMu.Unlock()  // ② defer 注册：函数退出时必释放

    for _, iface := range srv.interfaces4 {
        iface.common.reset()     // ③ 清空各接口内存
    }
    // ... v6 同理 ...
    err = srv.leases.clear(ctx, srv.logger)
    // clear() 内部:
    //   clear(idx.byAddr) / clear(idx.byName)  ← 清空全局 map
    //   idx.dbStore(ctx, logger)               ← 持锁写空文件

    return nil                   // ④ 函数返回 → defer Unlock 执行
}
```

#### 旧版 dhcpd — `ResetLeases()`

```go
// v4_unix.go:148-177
func (s *v4Server) ResetLeases(leases []*dhcpsvc.Lease) (err error) {
    defer func() { err = errors.Annotate(err, "dhcpv4: %w") }()

    if s.conf == nil {           // 未初始化直接跳过（无锁操作）
        return nil
    }

    s.leasesLock.Lock()               // ① 获取互斥锁
    defer s.leasesLock.Unlock()       // ② defer 注册

    // ③ 全量重建 —— 先清空，再逐条加载
    s.leasedOffsets = newBitSet()
    s.hostsIndex = make(map[string]*dhcpsvc.Lease, len(leases))
    s.ipIndex = make(map[netip.Addr]*dhcpsvc.Lease, len(leases))
    s.leases = nil

    for _, l := range leases {
        if !l.IsStatic {
            l.Hostname = s.validHostnameForClient(l.Hostname, l.IP)
        }
        err = s.addLease(l)
        if err != nil {
            // 单条失败仅记录日志，不中断，继续下一条
            log.Error("dhcpv4: reset: re-adding a lease for %s (%s): %s",
                l.IP, l.HWAddr, err)
            continue   // ← continue 不触发 defer，锁仍持有
        }
    }

    return nil              // ④ 正常返回 → defer Unlock 执行
}
```

### 10.3 锁状态还原的三道防线

#### 防线一：`defer Unlock()` 兜底

无论函数以何种方式退出（正常 `return`、循环中 `continue`、中途 `return err`、甚至 panic），`defer` 注册的 `Unlock` 都会被执行：

```go
s.leasesLock.Lock()
defer s.leasesLock.Unlock()  // 只要进入了这行，退出时必执行 Unlock

// ... 任意代码路径 ...
//   return nil            → defer 执行
//   return err            → defer 执行
//   continue (循环中)     → defer 不执行，锁继续持有，正确
//   panic("xxx")          → defer 仍然执行，锁被释放
```

`continue` 在 `for` 循环中不会退出函数，所以 defer 不触发，锁继续保持——这是正确的行为，因为后续迭代仍在操作共享数据。

#### 防线二：`defer errors.Annotate` 的执行顺序

`ResetLeases` 有两个 defer 语句：

```go
defer func() { err = errors.Annotate(err, "dhcpv4: %w") }()   // 第一个注册
// ...
s.leasesLock.Lock()
defer s.leasesLock.Unlock()                                    // 第二个注册
```

Go 的 `defer` 遵循 **LIFO（后进先出）** 顺序执行。因此退出时的实际顺序是：

```
退出顺序:
  1. s.leasesLock.Unlock()            ← 先释放锁（第二个 defer）
  2. err = errors.Annotate(err, ...)  ← 后包装错误（第一个 defer）
```

这个顺序是**正确且安全**的：锁被尽早释放，错误包装不涉及共享数据，可在无锁状态下自由执行。

#### 防线三：内存操作的幂等与可恢复

`ResetLeases` 采用"先全部清空、再逐条重建"的策略，中途部分失败不影响整体状态：

```
内存变化时序（持锁状态下）:

  初始状态:  旧 leases[]、旧 ipIndex、旧 hostsIndex、旧 leasedOffsets
       ↓
  Step 1:   leasedOffsets = newBitSet()      ← 位图清零
            hostsIndex = make(map[...])      ← 主机名索引空 map
            ipIndex = make(map[...])         ← IP 索引空 map
            leases = nil                     ← 切片置空
       ↓  (此时内存处于"干净的空状态")
  Step 2:   遍历 leases 参数:
              l₁ → addLease(l₁) 成功        ← 写入 l₁
              l₂ → addLease(l₂) 成功        ← 写入 l₂
              l₃ → addLease(l₃) 失败 → continue，记录日志，跳过 l₃
              l₄ → addLease(l₄) 成功        ← 写入 l₄
       ↓
  Step 3:   函数返回 → defer Unlock

最终状态:  leases = [l₁, l₂, l₄]   (l₃ 因校验失败被丢弃，对应 JSON 文件中的坏条目)
```

这种设计的特点：
- **坏条目不污染整体**：单条 `addLease` 失败（如 IP 重复、MAC 格式错误）不影响其他条目
- **状态确定性**：清空后再重建，要么空、要么重建后的正确状态，不存在"旧数据+新数据混合"的中间状态被外部观察到
- **无局部回滚需求**：不需要事务或回滚逻辑，因为清空是第一步，中途失败也只是少加载了几条

### 10.4 无 `recover()` 的 panic 处理

代码中**没有**显式的 `recover()` 语句：

```go
// 代码中不存在类似以下的 recover:
// defer func() {
//     if r := recover(); r != nil {
//         s.leasesLock.Unlock()  // 不需要，因为 defer Unlock 已注册
//     }
// }()
```

这是因为 `defer s.leasesLock.Unlock()` **即使在 panic 时也会执行**。Go 语言保证：
- `panic` 触发后，当前 goroutine 中所有已注册的 `defer` 都会被正常执行
- 只有当 defer 本身 `panic` 才会打断后续 defer 的执行（但 `sync.Mutex.Unlock` 不会 panic，前提是不要重复解锁）

因此即便 `addLease` 内部因某种极端情况（如 nil 指针、slice 越界）panic：
1. 已注册的 `defer s.leasesLock.Unlock()` 会被执行 → 锁正确释放
2. 已注册的 `defer errors.Annotate` 会被执行 → 但 `err` 返回值在 panic 场景下无意义，panic 会向上传播到 goroutine 栈顶
3. 服务层如果有全局 recover（AdGuard Home 的 HTTP 中间件有），则请求返回 500，DHCP 服务本身不崩溃

### 10.5 重建完成后的写盘时序

#### 新版 dhcpsvc：持锁写盘

```
Reset() 流程:
  Lock → 清内存 → clear() 内部 dbStore()（持锁）→ Unlock
```

`clear()` 在 `leaseindex.go:60-70` 中：

```go
func (idx *leaseIndex) clear(ctx context.Context, logger *slog.Logger) (err error) {
    clear(idx.byAddr)
    clear(idx.byName)
    err = idx.dbStore(ctx, logger)   // ← 调用方 Reset() 已持有 leasesMu
    return err
}
```

#### 旧版 dhcpd：锁外写盘（仅 resetLeases 路径）

```
resetLeases()（HTTP /control/dhcp/reset）流程:
  ResetLeases(nil)  →  Lock → 清内存 → Unlock
    ↓
  dbStore()         →  无锁状态下读内存写盘（有 data race 风险，见 9.4）
```

而冷启动 / 配置变更路径 `dbLoad()` 调用的 `ResetLeases` **不触发写盘**，因为刚从磁盘读入的数据没有必要立即回写。

### 10.6 锁状态还原总结

| 场景 | 锁获取 | 锁释放方式 | 还原正确性 |
|------|-------|-----------|-----------|
| 正常完成全部重建 | `Lock()` 入口 | `defer Unlock` 返回时 | ✓ |
| 中途 `return err`（早期校验失败） | 不进入 Lock（`s.conf == nil`） | 无需释放 | ✓ |
| 单条 `addLease` 失败 `continue` | `Lock()` 已持有 | 不释放，继续循环（正确） | ✓ |
| 内部 panic | `Lock()` 已持有 | `defer Unlock` panic 时仍执行 | ✓ |
| 并发读操作冲突 | — | RWMutex 天然互斥，写等待读完成 | ✓ |

**设计评价**：`ResetLeases` 的锁还原机制是简洁而健壮的。它依靠 Go 的 `defer` 机制而非显式 `recover` 来保证锁释放，依靠"先清空再重建"的幂等策略避免部分状态泄露，依靠单锁架构避免死锁。唯一不够严谨的是旧版 `dbStore` 在锁外执行，但这属于写盘流程的设计缺陷，与锁还原逻辑本身无关。

---

## 十一、关键代码文件索引

| 文件 | 核心职责 |
|------|---------|
| `internal/dhcpsvc/lease.go:24-41` | `Lease` 结构体定义 |
| `internal/dhcpsvc/lease.go:71-82` | `updateExpiry` 租期更新 |
| `internal/dhcpsvc/leaseindex.go` | 全局租约索引 |
| `internal/dhcpsvc/interface.go` | 接口级租约存储 |
| `internal/dhcpsvc/interface.go:53-54` | `indexMu` 锁字段定义 |
| `internal/dhcpsvc/interface.go:132-153` | `blockLease` 阻塞租约 |
| `internal/dhcpsvc/interface.go:173-181` | `findExpiredLease` 查找过期 |
| `internal/dhcpsvc/interface.go:229-267` | `reserveLease` 分配/回收 |
| `internal/dhcpsvc/server.go:46-47` | `leasesMu` 全局读写锁 |
| `internal/dhcpsvc/server.go:198-246` | DNS 查询路径 RLock 使用 |
| `internal/dhcpsvc/server.go:249-269` | `Reset()` 配置接口路径锁还原 |
| `internal/dhcpsvc/server.go:272-300` | `AddLease` HTTP API 路径加锁 |
| `internal/dhcpsvc/server.go:303-403` | `UpdateStaticLease`/`RemoveLease` 加锁 |
| `internal/dhcpsvc/v4.go:210` | 接口 indexMu 指向全局锁 |
| `internal/dhcpsvc/handler4.go` | 请求 goroutine 加锁示例 |
| `internal/dhcpsvc/db.go:174-206` | `dbStore` 持锁前置条件 |
| `internal/dhcpd/dhcpd.go:219-232` | `onNotify` DBStore 回调 |
| `internal/dhcpd/v4_unix.go:45-46` | 旧版 `leasesLock` 互斥锁 |
| `internal/dhcpd/v4_unix.go:147-177` | `ResetLeases` 重建索引与锁还原 |
| `internal/dhcpd/v4_unix.go:179-182` | `getLeasesRef` 无锁返回切片引用 |
| `internal/dhcpd/v4_unix.go:238-250` | `FindMACbyIP` DNS 查询路径加锁 |
| `internal/dhcpd/v4_unix.go:385-438` | `AddStaticLease` HTTP API 路径加锁/写盘时序 |
| `internal/dhcpd/v4_unix.go:518-533` | `updateStaticLease` 锁内改内存 |
| `internal/dhcpd/db.go:93-149` | 旧版 `dbLoad` 完整流程 |
| `internal/dhcpd/db.go:152-167` | 旧版 `dbStore` 无锁读内存写盘 |
| `internal/dhcpd/migrate.go:63-105` | 旧格式数据迁移 |
| `internal/dhcpd/http_unix.go:318-380` | 配置变更时的重载流程 |
| `internal/dhcpd/http_unix.go:787-800` | HTTP API 端点注册 |

---

## 十二、data race 漏写租约的真实影响分析

### 12.1 问题回顾

第九章 9.4 节指出旧版 `dhcpd` 存在 data race：HTTP API 在 `Lock → 改内存 → Unlock` 后，于**无锁状态**下调用 `dbStore()` 写盘；此时接口 goroutine 可能持有锁正在 `append(s.leases, l)` 修改同一切片。

本章从代码层面深入分析该 race 的**实际业务影响**。

### 12.2 漏写的租约会被下一次 dbStore 自然覆盖回来吗？

**结论：是的，只要内存里的租约没有被提前删除，下一次 dbStore 一定会写回来。**

#### 代码证据：

`dbStore()` 每次执行时都会**全量遍历**内存切片，而非增量写入：

```go
// db.go:152-167
func (s *server) dbStore() (err error) {
    leases := []*dbLease{}

    for _, l := range s.srv4.getLeasesRef() {  // 每次全量遍历 s.leases 切片
        leases = append(leases, fromLease(l))
    }
    // ... v6 同理 ...
    return writeDB(s.conf.dbFilePath, leases)    // 整体覆盖写入
}

// v4_unix.go:180-182
func (s *v4Server) getLeasesRef() []*dhcpsvc.Lease {
    return s.leases   // 返回内存中完整切片的引用
}
```

`writeDB` 使用 `maybe.WriteFile` 做原子替换写入（`db.go:189`），每次写入都会**完全替换** `leases.json` 的内容。

#### 具体场景推演：

假设事件时序如下：
```
T0: 内存 leases = [L1, L2]，磁盘 JSON = [L1, L2]

T1: HTTP API 线程开始 AddStaticLease(L3)
      Lock → 改内存 → leases = [L1, L2, L3] → Unlock

T2: 开始执行 dbStore()，进入 for 循环遍历 s.leases
      已读出 L1、L2，正准备读 L3

T3: 接口 goroutine 抢到锁，执行 DISCOVER 分配 L4
      Lock → append(s.leases, L4) → leases = [L1, L2, L3, L4] → Unlock
                                               ↑
                                     切片底层数组可能因扩容而重分配！

T4: HTTP API 的 for 循环继续，但此时切片引用已失效
      - 如果 T3 未触发扩容：可能读到 L3、漏掉 L4，写盘 [L1, L2, L3]
      - 如果 T3 触发扩容：底层数组指针改变，for 循环仍用旧指针
                      读到旧数组的 L3、L4 为零值，写盘 [L1, L2, L3]
                      （最极端情况：完全乱序或重复）

T5: 磁盘 JSON = [L1, L2, L3]，漏掉了 L4 ✗

T6: 下一次任何变更触发 dbStore()（如 L4 续约、其他客户端请求）
      全量遍历内存 s.leases = [L1, L2, L3, L4]
      写盘 JSON = [L1, L2, L3, L4] ✓  // L4 被补回来了
```

**漏写是"一过性"的**，仅影响本次 `dbStore` 的输出文件。只要内存中的 `s.leases` 切片仍然正确持有 L4 的指针，下一次 `dbStore` 就会全量重写，把漏掉的租约补回来。

### 12.3 有没有显式的 sync 调用补刷？

**结论：没有显式的 sync/fsync 补刷机制，但变更驱动的通知系统确保了快速自愈。**

代码中不存在类似以下的补刷逻辑：
```go
// 代码中不存在：
// s.conf.notify(SyncDBStore)        // 不存在
// s.dbStoreWithRetry()              // 不存在
// s.dbStoreForceSync()              // 不存在
// s.ticklerGoroutine -> dbStore()   // 不存在后台定时刷盘
```

但实际上无需补刷，因为**每次租约变更都会触发 `notify(LeaseChangedDBStore)`**，从而调用 `dbStore()` 全量重写。

所有状态变更路径都会触发写盘：

| 操作 | 触发点 | 漏写自愈时间 |
|------|-------|------------|
| DISCOVER 分配新 IP | `handleDiscover` line 738 `defer notify(DBStore)` | 下次任何租约变更 |
| REQUEST SELECTING | `handleRequest` line 973 `defer notify(DBStore)` | 下次任何租约变更 |
| REQUEST RENEW 续约 | `handleRequest` line 973（同一 defer） | 下次任何租约变更 |
| DECLINE 冲突换 IP | `handleDecline` line 1001 `notify(DBStore)` | 下次任何租约变更 |
| RELEASE 主动释放 | `handleRelease` line 1080 `defer notify(DBStore)` | 下次任何租约变更 |
| HTTP API 加静态租约 | `AddStaticLease` line 435 `notify(DBStore)` | 下次任何租约变更 |
| HTTP API 删静态租约 | `RemoveStaticLease` line 557 `notify(DBStore)` | 下次任何租约变更 |

**自愈窗口分析**：
- 网络正常、有客户端活动时，两次 `dbStore` 的间隔通常在秒级甚至毫秒级
- 极端安静场景（无任何 DHCP 活动、无人操作 Web），漏写状态可能持续到下次租约变更
- 服务重启时会从 `leases.json` 重新加载，**漏写的租约在重启后会永久丢失**（见 12.6 节）

### 12.4 漏写具体发生在哪条租约状态变更路径？

data race 发生在**所有调用 `notify(LeaseChangedDBStore)` 时不持有锁**的路径。让我们逐条核对 v4 的每条路径：

#### 路径一：HTTP API — 加静态租约 ✗ 有 race

```go
// v4_unix.go:385-438  AddStaticLease
func (s *v4Server) AddStaticLease(l *dhcpsvc.Lease) (err error) {
    err = s.updateStaticLease(l)
    // updateStaticLease() 内部：
    //   Lock() → rmDynamicLease() + addLease() → Unlock()   锁已释放

    s.conf.notify(LeaseChangedDBStore)     // ← 无锁状态下调用 dbStore()
    s.conf.notify(LeaseChangedAddedStatic)
    return nil
}
```

#### 路径二：HTTP API — 删静态租约 ✗ 有 race

```go
// v4_unix.go:536-565  RemoveStaticLease
defer func() {
    s.conf.notify(LeaseChangedDBStore)      // ← defer 在 Unlock 之后执行
    s.conf.notify(LeaseChangedRemovedStatic)
}()
s.leasesLock.Lock()
defer s.leasesLock.Unlock()
return s.rmLease(l)
```

#### 路径三：HTTP API — 改静态租约 ✗ 有 race

```go
// v4_unix.go:442-477  UpdateStaticLease
defer func() {
    s.conf.notify(LeaseChangedDBStore)      // ← defer 在 Unlock 之后执行
    s.conf.notify(LeaseChangedRemovedStatic)
}()
s.leasesLock.Lock()
defer s.leasesLock.Unlock()
// ... 修改内存 ...
```

#### 路径四：DISCOVER 分配新 IP ✗ 有 race

```go
// v4_unix.go:738  handleDiscover
defer s.conf.notify(LeaseChangedDBStore)   // ← defer 在 Unlock 之后执行

s.leasesLock.Lock()
defer s.leasesLock.Unlock()
l, err = s.allocateLease(mac)   // 内部 append(s.leases, l)
```

#### 路径五：REQUEST 分配/续约 ✗ 有 race

```go
// v4_unix.go:971-974  handleRequest
defer func() {
    s.conf.notify(LeaseChangedAdded)
    s.conf.notify(LeaseChangedDBStore)     // ← defer 在 Unlock 之后执行
}()

s.leasesLock.Lock()
defer s.leasesLock.Unlock()
s.commitLease(lease, hostname)
```

#### 路径六：DECLINE 冲突换 IP ✗ 有 race（更严重的位置）

```go
// v4_unix.go:1001  handleDecline
s.conf.notify(LeaseChangedDBStore)        // ← 在 Lock() 之前调用！

s.leasesLock.Lock()
defer s.leasesLock.Unlock()
// rmDynamicLease(oldLease) + allocateLease(new) + addLease(newLease)
```

`handleDecline` 的问题最严重：`notify` 放在 `Lock()` **之前**，意味着 `dbStore` 读取内存时，本次 Decline 导致的租约变更**还没发生**！写入的是变更前的状态。

#### 路径七：RELEASE 主动释放 ✗ 有 race

```go
// v4_unix.go:1080  handleRelease
defer s.conf.notify(LeaseChangedDBStore)   // ← defer 在 Unlock 之后执行

s.leasesLock.Lock()
defer s.leasesLock.Unlock()
// rmDynamicLease(l)
```

**结论：所有 7 条租约变更路径都存在 data race。** 没有任何一条旧版 v4 路径是"持锁写盘"的。

#### v6 的情况更糟糕：notify 甚至在 Lock() 内部调用

```go
// v6_unix.go:234  AddStaticLease
s.addLease(l)
s.conf.notify(LeaseChangedDBStore)   // ← Lock() 内部调用！
s.leasesLock.Unlock()

// v6_unix.go:292  RemoveStaticLease
s.rmLease(l)
s.conf.notify(LeaseChangedDBStore)   // ← Lock() 内部调用！
s.leasesLock.Unlock()

// v6_unix.go:401  commitDynamicLease
s.leasesLock.Lock()
s.conf.notify(LeaseChangedDBStore)   // ← Lock() 内部调用！
s.leasesLock.Unlock()
```

v6 中 `notify(DBStore)` 在 `Lock()` 持有状态下调用，从锁保护角度看是"安全的"，但这意味着写磁盘 IO 发生在**持有锁**的状态下，会阻塞所有其他并发操作，吞吐量问题比 v4 更严重。

### 12.5 漏写会不会导致重复签发同一 IP？

**结论：绝对不会。** 因为 IP 唯一性由**内存锁 + 位图**双重保护，与 `dbStore` 是否漏写无关。

#### 内存中的 IP 唯一性保障机制：

**第一道防线：`leasedOffsets` 位图**

```go
// v4_unix.go:326-376  addLease
func (s *v4Server) addLease(l *dhcpsvc.Lease) (err error) {
    // ... 检查 IP 是否在范围内 ...

    // 位图检查：该 IP 偏移是否已被标记
    if !l.IsStatic {
        s.leasedOffsets.set(offset)       // 标记位图，防止重复分配
    }

    // 唯一性检查
    if dup, ok := s.ipIndex[l.IP]; ok {   // IP 索引检查
        return ErrDupIP
    }
    if hostname != "" {
        if dup, ok := s.hostsIndex[hostname]; ok {  // 主机名索引检查
            return ErrDupHostname
        }
    }

    s.leases = append(s.leases, l)       // 加入切片
    s.ipIndex[l.IP] = l
    s.hostsIndex[lowercaseHostname] = l
    return nil
}
```

**第二道防线：`reserveLease` 的分配逻辑**

```go
// v4_unix.go:653-681  reserveLease
func (s *v4Server) reserveLease(mac net.HardwareAddr) (l *dhcpsvc.Lease, err error) {
    nextIP := s.nextIP()                  // 从未标记的位图中找下一个
    if nextIP == nil {
        i := s.findExpiredLease()         // 无空闲 IP 时回收过期租约
        if i < 0 { return nil, nil }
        copy(s.leases[i].HWAddr, mac)
        return s.leases[i], nil
    }

    l.IP = netIP
    err = s.addLease(l)                   // addLease 内部会 set 位图
    return l, nil
}
```

**为什么漏写不会导致重复分配：**

```
内存正确性是 IP 分配的唯一依据，磁盘只是异步镜像：

  内存状态：leases = [L1(192.168.1.100), L2(192.168.1.101)]
            leasedOffsets = [1,1,0,0,...]   ← 位图标记前两个已用
            ipIndex = {.100: L1, .101: L2}

  ↓ 发生 data race 漏写，磁盘 JSON 只写了 [L1]，漏掉了 L2

  磁盘状态：leases.json = [L1(192.168.1.100)]

  ↓ 下一个客户端 DISCOVER 请求分配

  reserveLease():
    nextIP() 检查 leasedOffsets 位图 → 前两位都是 1，返回 .102

  addLease(.102):
    检查 ipIndex[.102] → 不存在 ✓
    标记位图第三位 → leasedOffsets = [1,1,1,...]

  结果：分配 192.168.1.102 给新客户端，不会重复分配 .101
```

即使 `leases.json` 中漏掉了 L2，内存中的 `leasedOffsets` 位图和 `ipIndex` 仍然正确标记了 `.101` 已被占用，分配器绝不会把它再分配出去。

**唯一的风险场景是服务重启**：如果漏写发生后立即重启，`dbLoad()` 从磁盘加载，会漏掉 L2，此时 `.101` 的位图未被标记，可能被重新分配给新客户端。这是**重启前漏写 + 重启**两个条件同时满足才会发生的极端场景。

### 12.6 对客户端的真实影响总结

| 影响 | 发生条件 | 客户端表现 |
|------|---------|-----------|
| leases.json 漏掉几条租约 | 写盘时恰好有并发的切片 append | 无感，下次变更自动补回 |
| 重启后永久丢失租约 | 漏写发生后立即重启服务 | 已在线的客户端不受影响；已分配的 IP 可能被重新分配给新客户端 |
| 重复签发同一 IP | 仅当漏写 + 重启同时发生 | 罕见的 IP 冲突，客户端检测后会重新申请 |
| 写盘内容乱序/重复 | 切片扩容导致底层数组重分配 | 无感，下次 dbStore 自动修复 |
| HTTP API 操作响应变慢 | 写盘 IO 被阻塞 | 操作响应延迟，但功能正常 |

### 12.7 新版 dhcpsvc 的修复方案

新版通过在 `Lock()` 持有状态下调用 `dbStore()`，从根本上消除了 race：

```go
// server.go:283-286  新版 AddLease
srv.leasesMu.Lock()
defer srv.leasesMu.Unlock()

err = srv.leases.add(ctx, srv.logger, l, iface)
// add() 内部:
//   iface.addLease(l) → 改内存
//   idx.byAddr[l.IP] = l → 改全局索引
//   idx.dbStore(ctx, logger) → 持锁写盘 ✓  无 race
```

代价是写盘 IO 发生在持锁状态下，锁持有时间变长，多接口并发处理 DHCP 请求时吞吐量会有所下降。但与 data race 导致的潜在数据丢失相比，这是合理的取舍。

---

## 十三、关键代码文件索引（更新）

| 文件 | 核心职责 |
|------|---------|
| `internal/dhcpsvc/lease.go:24-41` | `Lease` 结构体定义 |
| `internal/dhcpsvc/lease.go:71-82` | `updateExpiry` 租期更新 |
| `internal/dhcpsvc/leaseindex.go` | 全局租约索引 |
| `internal/dhcpsvc/interface.go` | 接口级租约存储 |
| `internal/dhcpsvc/interface.go:53-54` | `indexMu` 锁字段定义 |
| `internal/dhcpsvc/interface.go:132-153` | `blockLease` 阻塞租约 |
| `internal/dhcpsvc/interface.go:173-181` | `findExpiredLease` 查找过期 |
| `internal/dhcpsvc/interface.go:229-267` | `reserveLease` 分配/回收 |
| `internal/dhcpsvc/server.go:46-47` | `leasesMu` 全局读写锁 |
| `internal/dhcpsvc/server.go:198-246` | DNS 查询路径 RLock 使用 |
| `internal/dhcpsvc/server.go:249-269` | `Reset()` 配置接口路径锁还原 |
| `internal/dhcpsvc/server.go:272-300` | `AddLease` HTTP API 路径加锁（持锁写盘，修复 race） |
| `internal/dhcpsvc/server.go:303-403` | `UpdateStaticLease`/`RemoveLease` 加锁 |
| `internal/dhcpsvc/v4.go:210` | 接口 indexMu 指向全局锁 |
| `internal/dhcpsvc/handler4.go` | 请求 goroutine 加锁示例 |
| `internal/dhcpsvc/db.go:174-206` | `dbStore` 持锁前置条件 |
| `internal/dhcpd/dhcpd.go:219-232` | `onNotify` DBStore 回调 |
| `internal/dhcpd/v4_unix.go:45-46` | 旧版 `leasesLock` 互斥锁 |
| `internal/dhcpd/v4_unix.go:147-177` | `ResetLeases` 重建索引与锁还原 |
| `internal/dhcpd/v4_unix.go:179-182` | `getLeasesRef` 无锁返回切片引用（race 根源） |
| `internal/dhcpd/v4_unix.go:238-250` | `FindMACbyIP` DNS 查询路径加锁 |
| `internal/dhcpd/v4_unix.go:326-376` | `addLease` IP 唯一性检查（位图 + 索引） |
| `internal/dhcpd/v4_unix.go:653-681` | `reserveLease` 分配逻辑，保障内存级 IP 唯一 |
| `internal/dhcpd/v4_unix.go:735-768` | `handleDiscover` notify 位置（race 路径 1） |
| `internal/dhcpd/v4_unix.go:960-997` | `handleRequest` notify 位置（race 路径 2） |
| `internal/dhcpd/v4_unix.go:1000-1050` | `handleDecline` notify 在 Lock 之前（最严重 race） |
| `internal/dhcpd/v4_unix.go:1071-1111` | `handleRelease` notify 位置（race 路径 4） |
| `internal/dhcpd/v4_unix.go:385-438` | `AddStaticLease` HTTP API 路径加锁/写盘时序（race 路径 5） |
| `internal/dhcpd/v4_unix.go:518-533` | `updateStaticLease` 锁内改内存 |
| `internal/dhcpd/v4_unix.go:536-565` | `RemoveStaticLease` notify 位置（race 路径 6） |
| `internal/dhcpd/db.go:93-149` | 旧版 `dbLoad` 完整流程 |
| `internal/dhcpd/db.go:152-167` | 旧版 `dbStore` 全量遍历写盘（每次覆盖） |
| `internal/dhcpd/db.go:189` | `maybe.WriteFile` 原子写入磁盘 |
| `internal/dhcpd/v6_unix.go:234` | v6 `notify` 在 Lock 内调用（吞吐量问题） |
| `internal/dhcpd/v6_unix.go:292` | v6 RemoveStaticLease notify 在 Lock 内 |
| `internal/dhcpd/v6_unix.go:401` | v6 `commitDynamicLease` notify 在 Lock 内 |
| `internal/dhcpd/migrate.go:63-105` | 旧格式数据迁移 |
| `internal/dhcpd/http_unix.go:318-380` | 配置变更时的重载流程 |
| `internal/dhcpd/http_unix.go:787-800` | HTTP API 端点注册 |

---

## 十四、异步写盘模式的可行性与代价分析

第十二章指出 v6 把 `notify(DBStore)` 放在 `Lock()` 内部调用，导致写盘 IO 阻塞所有并发操作，吞吐量受影响。本章从代码层面分析：如果改成异步写盘（把 dbStore 放到后台 goroutine），会涉及哪些问题。

### 14.1 仓库中现成的异步队列模式可参考

仓库中已有两种成熟的异步/批量写盘模式，可以直接借鉴：

#### 模式一：querylog — 阈值触发 + 异步 goroutine

**核心代码**：`internal/querylog/qlog.go:219-264`

```go
// qlog.go:255-264
if !l.flushPending && fileIsEnabled && l.buffer.Len() >= memSize {
    l.flushPending = true

    // TODO(s.chzhen):  Fix occasional rewrite of entires.
    go func() {
        flushErr := l.flushLogBuffer(ctx)
        if flushErr != nil {
            l.logger.ErrorContext(ctx, "flushing after adding", slogutil.KeyError, flushErr)
        }
    }()
}
```

**模式特点**：
- **触发条件**：内存缓冲 `buffer` 达到 `MemSize` 阈值
- **去重机制**：`flushPending` 标志位，同一时间只有一个刷盘 goroutine 在跑
- **同步锁**：`bufferLock` 保护内存缓冲，`fileFlushLock` 保护刷盘操作
- **关闭时补刷**：`Shutdown()` 调用 `flushLogBuffer()` 强制落盘（`qlog.go:99-105`）
- **数据结构**：环形缓冲 `container.RingBuffer`（用 `buffer.Push / Clear / Range` 操作）

**可套用到 DHCP 的地方**：
- `flushPending` 标志位模式可以直接复用，避免频繁触发异步刷盘
- `fileFlushLock` 模式可以防止并发写同一文件

**不适用的地方**：
- querylog 是**增量追加**（append-only），DHCP 租约是**全量覆盖**（每次 dbStore 写完整快照）
- querylog 丢几条日志问题不大，DHCP 租约丢失可能导致 IP 冲突

#### 模式二：stats — 定时周期刷盘

**核心代码**：`internal/stats/stats.go:239-242`、`stats.go:420-475`

```go
// stats.go:239-242
func (s *StatsCtx) Start() {
    s.initWeb()
    go s.periodicFlush()   // 后台 goroutine 定时刷盘
}

// stats.go:420-441  flush() 循环
func (s *StatsCtx) flush() (cont bool, sleepFor time.Duration) {
    // 检查是否跨小时单位，是则刷盘
    // 否则 sleep 1 秒再检查
}
```

**模式特点**：
- **触发条件**：按时间单位（小时）滚动，到点就刷
- **存储引擎**：bbolt 嵌入式数据库（事务性写入）
- **数据结构**：`currMu`（RWMutex）保护当前统计单元，刷盘时切换新单元

**可套用到 DHCP 的地方**：
- 定时刷盘 + 内存状态分离的思路可以借鉴
- `Close()` 时强制刷盘的模式

**不适用的地方**：
- stats 是统计数据，丢失一两个小时的统计问题不大
- DHCP 租约是状态数据，丢失有业务后果

### 14.2 add / remove 高并发下异步写盘的实际节奏

如果把 dbStore 改成异步，实际写盘节奏取决于三个因素：

#### 因素一：触发策略

| 策略 | 写盘频率 | 数据丢失窗口 | 适用场景 |
|------|---------|------------|---------|
| 每次变更都触发（debounce） | 等于变更频率 | debounce 窗口大小 | 低变更频率场景 |
| 阈值触发（类似 querylog） | 达到 N 条变更才刷 | 最多 N-1 条丢失 | 高变更频率场景 |
| 定时触发（类似 stats） | 固定时间间隔 | 最多一个时间间隔 | 对一致性要求不高 |

**DHCP 的实际变更频率**：
- 正常家庭/小型办公网络：每分钟几条到几十条 DISCOVER/REQUEST
- 大规模网络（上千客户端）：可能每秒几条
- DHCP 租约的变更都是"全量快照"式的，不像 querylog 是"增量追加"

#### 因素二：全量快照 vs 增量追加

DHCP 的 dbStore 是**全量遍历 + 整体覆盖**，这与异步模式有一个天然矛盾：

```
时间线:
  T0: 内存状态 S0 → 触发异步 dbStore()，开始遍历 s.leases
  T1: 变更 A（add L1）→ 内存状态 S1
  T2: 变更 B（remove L2）→ 内存状态 S2
  T3: 异步 dbStore 完成遍历，写入磁盘
        ↓
      写入的是哪个状态？
      - 如果遍历过程中读的是实时内存：数据混乱（部分 S0 + 部分 S2）
      - 如果遍历前拷贝了一份快照：写入的是 S0，漏掉了 A 和 B
```

**问题本质**：全量快照式写盘在异步模式下，要么读不一致（遍历中途数据被改），要么写的是过期数据（拍的是旧快照）。

相比之下，querylog 的增量追加模式没有这个问题——新数据在 buffer 里，下次 flush 自然会写。

#### 因素三：debounce 模式下的写盘合并

如果用 debounce（每次变更触发，但等一小段时间再写，期间的变更合并到同一次写盘），写盘频率会从"每次变更一次"降为"每 debounce 窗口一次"。

以 100ms debounce 窗口为例：
- 100 QPS 的变更频率 → 写盘频率降至 10 次/秒
- 500 QPS 的变更频率 → 写盘频率仍约 10 次/秒（窗口内合并）

DHCP 的变更频率通常远低于这个量级，debounce 带来的吞吐量提升有限，但实现复杂度增加不少。

### 14.3 重启时半截队列待写入会不会丢失？

**结论：会丢失，除非在 Stop/Close 时强制刷盘。**

#### querylog 的处理方式：

```go
// qlog.go:99-105  Shutdown 时强制刷盘
func (l *queryLog) Shutdown(ctx context.Context) (err error) {
    l.confMu.RLock()
    defer l.confMu.RUnlock()

    if l.conf.FileEnabled {
        err = l.flushLogBuffer(ctx)   // 强制把缓冲里的数据刷到磁盘
    }
    return err
}
```

**DHCP 如果改异步，需要做的事情**：

1. **Stop() 时同步刷盘**：在 `server.Stop()` 或 `dhcpd.Stop()` 返回前，等待所有异步 dbStore 完成，必要时强制执行一次
2. **配置变更时同步刷盘**：`handleDHCPSetConfig` 重建服务前，必须确保前一个实例的写盘都已完成
3. **context 取消处理**：如果用 context 控制生命周期，取消时需要刷盘

**极端场景下仍然可能丢失**：
- 进程被 `kill -9` 强杀 → 所有待写入都丢失（这是任何设计都无法避免的）
- 正常关闭（SIGTERM）→ 只要 Stop() 里有 flush 就不会丢

**对 DHCP 的实际影响**：
- 丢失几条动态租约 → 客户端下次 REQUEST 时找不到，走 INIT-REBOOT 重新验证，不影响使用
- 丢失静态租约 → 配置变更后立即重启才会发生，概率极低
- IP 重复分配 → 仅发生在"丢失租约 + 重启 + 该 IP 恰好被分配给新客户端"三重巧合

### 14.4 leasedOffsets 位图与 ipIndex 在异步模式下能不能继续兜底？

**结论：内存级别的 IP 唯一性保障完全不受影响，兜底能力 100% 保留。**

#### 为什么不受影响：

```
内存操作路径（同步）：
  addLease(l):
    s.leasedOffsets.set(offset)    ← 在 Lock() 内执行，同步的
    s.ipIndex[l.IP] = l             ← 在 Lock() 内执行，同步的
    s.leases = append(s.leases, l)  ← 在 Lock() 内执行，同步的

磁盘写入路径（异步）：
  dbStore():
    for _, l := range s.leases { ... }  ← 异步读取内存，可能读到不一致
    writeDB(file, leases)                ← 异步写磁盘
```

**内存状态是同步更新的**，异步的只是"把内存快照写到磁盘"这一步。只要 `leasesLock` 正确保护了所有内存操作：
- `leasedOffsets` 位图的正确性 ✔ 不受影响
- `ipIndex` 哈希表的正确性 ✔ 不受影响
- 新客户端分配 IP 时的唯一性检查 ✔ 不受影响

**磁盘可能比内存"旧"几个版本**，但这是异步模式的正常现象，不影响运行时正确性。只有重启后从磁盘加载时，才会用到磁盘上的状态（见 14.3 节）。

#### 类比理解：

```
内存 = 数据库的内存页（真实状态）
磁盘 = 数据库的 WAL / 快照（持久化状态）

异步写盘 ≈ 数据库的异步 checkpoint
内存锁    ≈ 数据库的行锁/表锁

只要锁保护了内存操作，运行时一致性就有保障；
磁盘只是异步持久化，落后几个版本不影响正确性，
最多就是崩溃恢复时丢失最后几次变更。
```

### 14.5 异步改造的取舍总结

| 维度 | 当前 v6 同步写盘（Lock 内） | 改成异步写盘 |
|------|-------------------------|-------------|
| 吞吐量 | 低（写盘 IO 阻塞所有操作） | 高（内存操作立即返回） |
| 实现复杂度 | 低 | 中（需加 flushPending、异步 goroutine、Stop 时 flush） |
| 数据一致性 | 强（磁盘=内存） | 弱（磁盘可能落后内存几个版本） |
| IP 唯一性保障 | ✔ 有 | ✔ 仍然有（内存级） |
| 重启后数据丢失 | 不会 | 正常关闭不会，异常关闭可能会 |
| 与现有代码风格一致性 | 差（v4 是同步+race） | 好（与 querylog/stats 模式一致） |
| data race 风险 | 无（持锁写盘） | 需要仔细设计，否则可能引入新 race |

**结论**：异步写盘在 DHCP 场景下是可行的，但收益有限。因为 DHCP 租约的变更频率远低于 DNS 查询/统计数据，v6 持锁写盘的吞吐量问题在实际使用中可能并不明显。如果要改，建议：
1. 采用 `flushPending` + 单次异步 goroutine 的模式（与 querylog 一致）
2. 在 `Stop()` / `Shutdown()` 中同步等待并强制刷盘
3. 写盘时做一次内存快照拷贝再写（避免遍历中途数据被改）
4. IP 分配正确性由内存锁+位图保证，不受异步写盘影响

---

## 十五、关键代码文件索引（更新）

| 文件 | 核心职责 |
|------|---------|
| `internal/dhcpsvc/lease.go:24-41` | `Lease` 结构体定义 |
| `internal/dhcpsvc/lease.go:71-82` | `updateExpiry` 租期更新 |
| `internal/dhcpsvc/leaseindex.go` | 全局租约索引 |
| `internal/dhcpsvc/interface.go` | 接口级租约存储 |
| `internal/dhcpsvc/interface.go:53-54` | `indexMu` 锁字段定义 |
| `internal/dhcpsvc/interface.go:132-153` | `blockLease` 阻塞租约 |
| `internal/dhcpsvc/interface.go:173-181` | `findExpiredLease` 查找过期 |
| `internal/dhcpsvc/interface.go:229-267` | `reserveLease` 分配/回收 |
| `internal/dhcpsvc/server.go:46-47` | `leasesMu` 全局读写锁 |
| `internal/dhcpsvc/server.go:198-246` | DNS 查询路径 RLock 使用 |
| `internal/dhcpsvc/server.go:249-269` | `Reset()` 配置接口路径锁还原 |
| `internal/dhcpsvc/server.go:272-300` | `AddLease` HTTP API 路径加锁（持锁写盘，修复 race） |
| `internal/dhcpsvc/server.go:303-403` | `UpdateStaticLease`/`RemoveLease` 加锁 |
| `internal/dhcpsvc/v4.go:210` | 接口 indexMu 指向全局锁 |
| `internal/dhcpsvc/handler4.go` | 请求 goroutine 加锁示例 |
| `internal/dhcpsvc/db.go:174-206` | `dbStore` 持锁前置条件 |
| `internal/dhcpd/dhcpd.go:219-232` | `onNotify` DBStore 回调 |
| `internal/dhcpd/v4_unix.go:45-46` | 旧版 `leasesLock` 互斥锁 |
| `internal/dhcpd/v4_unix.go:147-177` | `ResetLeases` 重建索引与锁还原 |
| `internal/dhcpd/v4_unix.go:179-182` | `getLeasesRef` 无锁返回切片引用（race 根源） |
| `internal/dhcpd/v4_unix.go:238-250` | `FindMACbyIP` DNS 查询路径加锁 |
| `internal/dhcpd/v4_unix.go:326-376` | `addLease` IP 唯一性检查（位图 + 索引） |
| `internal/dhcpd/v4_unix.go:653-681` | `reserveLease` 分配逻辑，保障内存级 IP 唯一 |
| `internal/dhcpd/v4_unix.go:735-768` | `handleDiscover` notify 位置（race 路径 1） |
| `internal/dhcpd/v4_unix.go:960-997` | `handleRequest` notify 位置（race 路径 2） |
| `internal/dhcpd/v4_unix.go:1000-1050` | `handleDecline` notify 在 Lock 之前（最严重 race） |
| `internal/dhcpd/v4_unix.go:1071-1111` | `handleRelease` notify 位置（race 路径 4） |
| `internal/dhcpd/v4_unix.go:385-438` | `AddStaticLease` HTTP API 路径加锁/写盘时序（race 路径 5） |
| `internal/dhcpd/v4_unix.go:518-533` | `updateStaticLease` 锁内改内存 |
| `internal/dhcpd/v4_unix.go:536-565` | `RemoveStaticLease` notify 位置（race 路径 6） |
| `internal/dhcpd/v6_unix.go:234` | v6 `notify` 在 Lock 内调用（吞吐量问题） |
| `internal/dhcpd/v6_unix.go:292` | v6 RemoveStaticLease notify 在 Lock 内 |
| `internal/dhcpd/v6_unix.go:401` | v6 `commitDynamicLease` notify 在 Lock 内 |
| `internal/dhcpd/db.go:93-149` | 旧版 `dbLoad` 完整流程 |
| `internal/dhcpd/db.go:152-167` | 旧版 `dbStore` 全量遍历写盘（每次覆盖） |
| `internal/dhcpd/db.go:189` | `maybe.WriteFile` 原子写入磁盘 |
| `internal/dhcpd/migrate.go:63-105` | 旧格式数据迁移 |
| `internal/dhcpd/http_unix.go:318-380` | 配置变更时的重载流程 |
| `internal/dhcpd/http_unix.go:787-800` | HTTP API 端点注册 |
| `internal/querylog/qlog.go:219-264` | querylog 异步刷盘模式（可参考） |
| `internal/querylog/qlog.go:99-105` | querylog Shutdown 时强制 flush |
| `internal/querylog/qlog.go:49-53` | querylog fileFlushLock / flushPending |
| `internal/stats/stats.go:239-242` | stats 定时刷盘 goroutine |
| `internal/stats/stats.go:420-475` | stats flush 循环逻辑 |

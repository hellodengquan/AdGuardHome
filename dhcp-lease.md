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

## 九、关键代码文件索引

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
| `internal/dhcpsvc/server.go:198-246` | 读操作 RLock 使用示例 |
| `internal/dhcpsvc/server.go:252-403` | 写操作 Lock 使用示例 |
| `internal/dhcpsvc/v4.go:210` | 接口 indexMu 指向全局锁 |
| `internal/dhcpsvc/handler4.go:63-84` | 请求类型分流 |
| `internal/dhcpsvc/handler4.go:133-181` | REQUEST 二次分流 |
| `internal/dhcpsvc/db.go:97-130` | `dbLoad` 加载逻辑 |
| `internal/dhcpsvc/db.go:174-206` | `dbStore` 持久化（调用方需持锁） |
| `internal/dhcpd/dhcpd.go:106-158` | `Create()` 启动入口 |
| `internal/dhcpd/v4_unix.go:45-46` | 旧版 `leasesLock` 互斥锁 |
| `internal/dhcpd/v4_unix.go:147-177` | `ResetLeases` 重建内存索引 |
| `internal/dhcpd/v4_unix.go:201-229` | `GetLeases` 查询时过滤过期项 |
| `internal/dhcpd/db.go:93-149` | 旧版 `dbLoad` 完整流程 |
| `internal/dhcpd/migrate.go:63-105` | 旧格式数据迁移 |
| `internal/dhcpd/http_unix.go:318-380` | 配置变更时的重载流程 |
| `internal/dhcpd/http_unix.go:787-800` | HTTP API 端点注册 |

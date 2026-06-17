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

## 六、关键代码文件索引

| 文件 | 核心职责 |
|------|---------|
| `internal/dhcpsvc/lease.go:24-41` | `Lease` 结构体定义 |
| `internal/dhcpsvc/lease.go:71-82` | `updateExpiry` 租期更新 |
| `internal/dhcpsvc/leaseindex.go` | 全局租约索引 |
| `internal/dhcpsvc/interface.go` | 接口级租约存储 |
| `internal/dhcpsvc/interface.go:132-153` | `blockLease` 阻塞租约 |
| `internal/dhcpsvc/interface.go:173-181` | `findExpiredLease` 查找过期 |
| `internal/dhcpsvc/interface.go:229-267` | `reserveLease` 分配/回收 |
| `internal/dhcpsvc/handler4.go:63-84` | 请求类型分流 |
| `internal/dhcpsvc/handler4.go:133-181` | REQUEST 二次分流 |
| `internal/dhcpsvc/db.go` | JSON 持久化 |
| `internal/dhcpd/v4_unix.go` | 旧版实现 |
| `internal/dhcpd/db.go` | 旧版持久化 |

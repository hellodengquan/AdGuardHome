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

#### DHCPDECLINE（地址冲突）

**文件**：`internal/dhcpsvc/handler4.go:328-370` → `handleDecline()`

- 调用 `iface.common.blockLease()` 标记为阻塞租约
- 阻塞租约特征：
  - HWAddr 设为全零（`blockedHardwareAddr`）
  - Hostname 清空
  - Expiry 设为 `now + leaseTTL`
  - 从 `iface.leases` 移除，但保留在 `leaseIndex` 中
- 阻塞期间该 IP 不会被重新分配

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
| DHCPv4 处理器 | `internal/dhcpsvc/handler4.go` | `handleDiscover/handleRequest/handleRelease` |
| 租约分配 | `internal/dhcpsvc/interface.go` | `allocateLease/reserveLease` |
| 持久化 | `internal/dhcpsvc/db.go` | `dbLoad/dbStore` |
| 客户端存储 | `internal/client/storage.go` | `Find/ApplyClientFiltering/UpdateDHCP` |
| 运行时客户端 | `internal/client/client.go` | `Runtime.Info()`（来源优先级） |
| DNS 过滤设置 | `internal/dnsforward/filter.go` | `clientRequestFilteringSettings` |
| 查询日志补全 | `internal/querylog/search.go` | `client()` |
| 策略叠加 | `internal/client/storage.go` | `ApplyClientFiltering()` |

---

## 八、设计特点总结

1. **三层索引设计**：MAC 键、IP 地址、主机名三种索引，支持不同场景的快速查找

2. **IP→MAC 桥接**：通过 DHCP 租约的 `MACByIP()` 方法，实现 IP 到 MAC 的转换，使得按 MAC 配置的持久化客户端也能通过 IP 被识别

3. **延迟补全策略**：查询日志写入时不补全客户端信息，搜索时才通过回调函数补全，减少写入路径的开销

4. **依赖倒置**：过滤模块通过 `ApplyClientFiltering` 函数指针与客户端存储解耦，符合依赖倒置原则

5. **多来源优先级**：客户端信息支持多个来源（持久化、hosts 文件、DHCP、rDNS、ARP、WHOIS），按优先级合并

# AdGuardHome 客户端策略与过滤逻辑分析

## 1. 客户端识别判定顺序

### 1.1 客户端信息来源优先级

AdGuardHome 从多个来源收集客户端信息，各来源具有明确的优先级顺序。

**来源优先级（从高到低）**：
```
SourcePersistent (持久化配置)
    ↓
SourceHostsFile (/etc/hosts)
    ↓
SourceDHCP (DHCP 租约)
    ↓
SourceRDNS (反向 DNS 解析)
    ↓
SourceARP (ARP 表)
    ↓
SourceWHOIS (WHOIS 信息)
```

**核心代码**：[internal/client/client.go:46-54](internal/client/client.go#L46-L54)

```go
const (
    SourceWHOIS Source = iota + 1
    SourceARP
    SourceRDNS
    SourceDHCP
    SourceHostsFile
    SourcePersistent
)
```

### 1.2 运行时客户端信息获取

`Runtime.Info()` 方法按优先级返回客户端信息：
[internal/client/client.go:123-146](internal/client/client.go#L123-L146)

```go
func (r *Runtime) Info() (cs Source, host string) {
    switch {
    case r.hostsFile != nil:
        cs, info = SourceHostsFile, r.hostsFile
    case r.dhcp != nil:
        cs, info = SourceDHCP, r.dhcp
    case r.rdns != nil:
        cs, info = SourceRDNS, r.rdns
    case r.arp != nil:
        cs, info = SourceARP, r.arp
    case r.whois != nil:
        cs = SourceWHOIS
    }
}
```

### 1.3 持久化客户端查找顺序

当需要定位持久化客户端配置时，按以下顺序查找：

**查找顺序**：
```
1. ClientID (DoH/DoT/DoQ 客户端标识)
    ↓
2. RemoteIP (客户端 IP 地址)
    ↓
3. Subnet (CIDR 子网匹配，按前缀长度排序，优先更具体的子网)
    ↓
4. MAC (通过 DHCP 获取 MAC 后查找)
```

**核心代码**：[internal/client/storage.go:529-560](internal/client/storage.go#L529-L560)

```go
func (s *Storage) Find(params *FindParams) (p *Persistent, ok bool) {
    for {
        switch {
        case isClientID:
            p, ok = s.index.findByClientID(params.ClientID)
        case isRemoteIP:
            p, ok = s.findByIP(params.RemoteIP)
        case isSubnet:
            p, ok = s.index.findByCIDR(params.Subnet)
        case isMAC:
            p, ok = s.index.findByMAC(params.MAC)
        default:
            return nil, false
        }
        if ok {
            return p.ShallowClone(), true
        }
    }
}
```

### 1.4 IP 地址查找细节

通过 IP 查找时还会进行 DHCP MAC 关联查找：
[internal/client/storage.go:564-576](internal/client/storage.go#L564-L576)

```go
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    p, ok = s.index.findByIP(addr)
    if ok {
        return p, true
    }
    // 通过 DHCP 获取 MAC 后再次查找
    foundMAC := s.dhcp.MACByIP(addr)
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC)
    }
    return nil, false
}
```

## 2. 策略匹配优先级

### 2.1 DNS 请求过滤检查顺序

AdGuardHome 对 DNS 请求按以下顺序执行检查，**任何一步匹配成功立即返回结果，不再执行后续检查**：

**过滤检查器顺序**：
```
1. processRewrites (DNS 重写规则)
    ↓
2. matchSysHosts (系统 hosts 文件)
    ↓
3. matchHost (过滤规则：先白名单，后黑名单)
    ↓
4. matchBlockedServicesRules (阻塞服务)
    ↓
5. checkSafeBrowsing (安全浏览)
    ↓
6. checkParental (家长控制)
    ↓
7. checkSafeSearch (安全搜索)
```

**核心代码**：[internal/filtering/filtering.go:505-536](internal/filtering/filtering.go#L505-L536) 和 [internal/filtering/filtering.go:994-1012](internal/filtering/filtering.go#L994-L1012)

```go
d.hostCheckers = []hostChecker{{
    check: d.matchSysHosts,
    name:  "hosts container",
}, {
    check: d.matchHost,
    name:  "filtering",
}, {
    check: d.matchBlockedServicesRules,
    name:  "blocked services",
}, {
    check: d.checkSafeBrowsing,
    name:  "safe browsing",
}, {
    check: d.checkParental,
    name:  "parental",
}, {
    check: d.checkSafeSearch,
    name:  "safe search",
}}
```

### 2.2 过滤规则内部优先级

在 `matchHost` 过滤规则检查中，内部还有子优先级：

```
1. 白名单匹配 (filteringEngineAllow)
    → 匹配成功则直接放行 (NotFilteredAllowList)
    ↓
2. DNS 重写规则检查
    ↓
3. 黑名单匹配 (filteringEngine)
    → NetworkRule > HostRulesV4 > HostRulesV6
```

**核心代码**：[internal/filtering/filtering.go:884-949](internal/filtering/filtering.go#L884-L949)

### 2.3 各检查模块启用条件

每个检查模块都有独立的启用开关：

| 检查模块 | 启用条件 | 配置位置 |
|---------|---------|---------|
| DNS 重写 | `setts.FilteringEnabled` && `conf.RewritesEnabled` | [filtering.go:554](internal/filtering/filtering.go#L554) |
| 系统 hosts | 永久启用，无开关 | - |
| 过滤规则 | `setts.FilteringEnabled` && `setts.ProtectionEnabled` | [filtering.go:889](internal/filtering/filtering.go#L889) |
| 阻塞服务 | `setts.ProtectionEnabled` | [filtering.go:628](internal/filtering/filtering.go#L628) |
| 安全浏览 | `setts.ProtectionEnabled` && `setts.SafeBrowsingEnabled` | [filtering.go:1143](internal/filtering/filtering.go#L1143) |
| 家长控制 | `setts.ProtectionEnabled` && `setts.ParentalEnabled` | [filtering.go:1179](internal/filtering/filtering.go#L1179) |
| 安全搜索 | `setts.ProtectionEnabled` && `setts.SafeSearchEnabled` | 由上层控制 |

### 2.4 阻塞服务的时间调度

阻塞服务支持按周调度，只有在非调度时间才会应用阻塞：
[internal/filtering/blocked.go:134-136](internal/filtering/blocked.go#L134-L136)

```go
if !bsvc.Schedule.Contains(time.Now()) {
    d.ApplyBlockedServicesList(setts, bsvc.IDs)
}
```

## 3. 配置生效路径

### 3.1 DNS 请求处理完整流程

```
DNS 请求到达
    ↓
processInitial() [internal/dnsforward/process.go:104-148]
    ├─ 处理客户端 IP
    ├─ 提取 ClientID (DoH/DoT/DoQ)
    ├─ 获取保护状态
    └─ clientRequestFilteringSettings() → 生成 setts
        ├─ dnsFilter.Settings() → 全局默认设置
        ├─ 设置 protectionEnabled
        └─ ApplyAdditionalFiltering() → 应用客户端配置
            ├─ 设置 ClientIP
            ├─ ApplyBlockedServices() → 应用全局阻塞服务
            ├─ applyClientFiltering() → 应用客户端自定义设置
            │   ├─ 查找持久化客户端
            │   ├─ 应用 UseOwnBlockedServices
            │   ├─ 应用 UseOwnSettings
            │   └─ 设置 ClientName/ClientTags
            └─ 应用客户端阻塞服务调度
    ↓
filterDNSRequest() [internal/dnsforward/filter.go:28-77]
    └─ dnsFilter.CheckHost() → 执行过滤检查
        ├─ processRewrites() → DNS 重写
        └─ 顺序执行 hostCheckers → 见 2.1 节
    ↓
命中过滤规则？
    ├─ 是 → 生成过滤响应，直接返回
    └─ 否 → 继续转发到上游 DNS
        ↓
收到上游响应
    ↓
filterDNSResponse() [internal/dnsforward/filter.go:116-169]
    └─ 检查响应中的 CNAME/A/AAAA/HTTPS 记录是否需要过滤
    ↓
返回最终响应
```

### 3.2 客户端设置应用逻辑

`ApplyClientFiltering` 是客户端自定义设置的核心应用入口：
[internal/client/storage.go:767-806](internal/client/storage.go#L767-L806)

```go
func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings) {
    // 1. 按 ClientID → IP → MAC 顺序查找客户端
    c, ok := s.index.findByClientID(ClientID(id))
    if !ok {
        c, ok = s.index.findByIP(addr)
    }
    if !ok {
        if foundMAC := s.dhcp.MACByIP(addr); foundMAC != nil {
            c, ok = s.index.findByMAC(foundMAC)
        }
    }
    if !ok {
        return // 未找到客户端，使用全局设置
    }

    // 2. 应用自定义阻塞服务
    if c.UseOwnBlockedServices {
        setts.BlockedServices = c.BlockedServices.Clone()
    }

    // 3. 设置客户端标识（用于规则中的 client 修饰符）
    setts.ClientName = c.Name
    setts.ClientTags = slices.Clone(c.Tags)

    // 4. 应用自定义过滤设置
    if !c.UseOwnSettings {
        return // 不使用自定义设置，直接返回
    }

    setts.FilteringEnabled = c.FilteringEnabled
    setts.SafeSearchEnabled = c.SafeSearchConf.Enabled
    setts.ClientSafeSearch = c.SafeSearch
    setts.SafeBrowsingEnabled = c.SafeBrowsingEnabled
    setts.ParentalEnabled = c.ParentalEnabled
}
```

### 3.3 持久化客户端配置结构

[internal/client/persistent.go:59-132](internal/client/persistent.go#L59-L132)

```go
type Persistent struct {
    // 基础标识
    Name        string
    IPs         []netip.Addr
    Subnets     []netip.Prefix
    MACs        []net.HardwareAddr
    ClientIDs   []ClientID
    Tags        []string

    // 自定义开关
    UseOwnSettings        bool  // 是否使用自定义过滤设置
    UseOwnBlockedServices bool  // 是否使用自定义阻塞服务

    // 自定义过滤设置（UseOwnSettings = true 时生效）
    FilteringEnabled    bool
    SafeBrowsingEnabled bool
    ParentalEnabled     bool
    SafeSearchConf      filtering.SafeSearchConfig

    // 自定义阻塞服务（UseOwnBlockedServices = true 时生效）
    BlockedServices *filtering.BlockedServices

    // 其他配置
    Upstreams              []string
    UpstreamsCacheEnabled  bool
    IgnoreQueryLog         bool
    IgnoreStatistics       bool
}
```

### 3.4 过滤设置 Settings 结构

[internal/filtering/filtering.go:45-67](internal/filtering/filtering.go#L45-L67)

```go
type Settings struct {
    ClientName string
    ClientIP   netip.Addr
    ClientTags []string

    ServicesRules   []ServiceEntry
    BlockedServices *BlockedServices

    ProtectionEnabled   bool  // 总开关
    FilteringEnabled    bool  // 过滤规则开关
    SafeSearchEnabled   bool  // 安全搜索开关
    SafeBrowsingEnabled bool  // 安全浏览开关
    ParentalEnabled     bool  // 家长控制开关

    ClientSafeSearch SafeSearch
}
```

## 4. 缓存机制与影响

### 4.1 安全浏览/家长控制 Hash-Prefix 缓存

**缓存结构**：[internal/filtering/hashprefix/cache.go:13-19](internal/filtering/hashprefix/cache.go#L13-L19)

```go
type cacheItem struct {
    expiry time.Time       // 过期时间
    hashes []hostnameHash  // 缓存的完整 hash 列表
}
```

**缓存查询流程**：[internal/filtering/hashprefix/cache.go:60-93](internal/filtering/hashprefix/cache.go#L60-L93)

```
查询 host → hostnameToHashes() → 生成多级子域名 hash
    ↓
对每个 hash 取前 2 字节作为 prefix 查询缓存
    ↓
缓存命中？
    ├─ 是 → 检查是否过期
    │   ├─ 未过期 → 检查完整 hash 匹配
    │   │   ├─ 匹配 → 返回 blocked=true
    │   │   └─ 不匹配 → 继续下一个 hash
    │   └─ 已过期 → 需要重新查询
    └─ 否 → 收集需要查询的 hash prefix
        ↓
DNS 查询 TXT 记录（{prefix}.{suffix}）
    ↓
解析响应中的完整 hash 列表
    ↓
storeInCache() → 缓存结果
    ↓
返回是否匹配
```

**缓存配置**：
- `SafeBrowsingCacheSize` / `ParentalCacheSize`：缓存大小（字节）
- `CacheTime`：缓存 TTL（分钟）

### 4.2 安全搜索缓存

**缓存实现**：[internal/filtering/safesearch/safesearch.go:102-107](internal/filtering/safesearch/safesearch.go#L102-L107)

```go
type Default struct {
    cache    cache.Cache  // LRU 缓存
    cacheTTL time.Duration
}
```

**缓存键**：`host + qtype` 组合  
**缓存值**：过滤结果（`filtering.Result`）

**缓存流程**：[internal/filtering/safesearch/safesearch.go:193-219](internal/filtering/safesearch/safesearch.go#L193-L219)

```
查询 host → 检查缓存
    ├─ 命中 → 直接返回缓存结果
    └─ 未命中 → 执行 DNS 重写规则匹配
        ↓
        生成结果 → 写入缓存 → 返回
```

### 4.3 过滤引擎与规则缓存

**规则存储**：
- `rulesStorage` / `filteringEngine`：黑名单规则引擎
- `rulesStorageAllow` / `filteringEngineAllow`：白名单规则引擎

**异步更新机制**：[internal/filtering/filtering.go:354-391](internal/filtering/filtering.go#L354-L391)

```
过滤器更新 → setFilters(async=true)
    ↓
发送到 filtersInitializerChan 通道
    ↓
updatesLoop 协程接收并执行 initFiltering()
    ↓
原子替换 rulesStorage 和 filteringEngine
    ↓
旧引擎继续服务直到新引擎就绪 → 无缝切换
```

### 4.4 运行时客户端信息更新

各来源的客户端信息定期更新：

| 来源 | 更新机制 | 代码位置 |
|-----|---------|---------|
| ARP | 定时器定期刷新（默认 1 分钟） | [storage.go:224-237](internal/client/storage.go#L224-L237) |
| Hosts | 文件变更监听 | [storage.go:285-304](internal/client/storage.go#L285-L304) |
| DHCP | 主动调用 UpdateDHCP() | [storage.go:359-383](internal/client/storage.go#L359-L383) |
| rDNS | 请求处理时异步更新 | [storage.go:340-356](internal/client/storage.go#L340-L356) |

### 4.5 缓存对策略生效的影响

1. **安全浏览/家长控制缓存**：
   - 缓存命中时直接返回，避免 DNS 查询开销
   - 缓存过期后才会重新查询，可能导致新加入黑名单的域名在缓存期内仍可访问
   - 缓存大小配置影响内存占用和命中率

2. **安全搜索缓存**：
   - 搜索引擎域名变更不频繁，缓存命中率高
   - 修改安全搜索配置后，已缓存结果不受影响，需等待缓存过期

3. **过滤规则引擎缓存**：
   - 异步更新时旧规则继续生效，直到新引擎就绪
   - 规则更新不会导致服务中断，但有短暂延迟
   - 大量规则时，引擎初始化需要时间，异步更新可避免阻塞

4. **客户端信息缓存**：
   - 运行时客户端信息定期更新，配置变更后需等待下一次刷新
   - 持久化客户端配置变更立即生效（因为是直接查询索引）

## 5. 关键模块交互图

```
┌──────────────────────────────────────────────────────────────────┐
│                      DNS 请求处理流程                           │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │   dnsforward.Server    │
                    │   processInitial()     │
                    └───────────┬────────────┘
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │ clientRequestFiltering │
                    │    Settings()          │  ← 全局默认配置
                    └───────────┬────────────┘
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │ ApplyAdditionalFiltering│
                    └───────────┬────────────┘
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │ ApplyBlockedServ │ │ applyClientFilter│ │  阻塞服务调度    │
    │   (全局)         │ │    (客户端)      │ │  Schedule.Check  │
    └──────────────────┘ └──────────┬───────┘ └──────────────────┘
                                     │
                                     ▼
                          ┌────────────────────┐
                          │  持久化客户端索引  │
                          │  index.findByXXX() │
                          └──────────┬─────────┘
                                     │
             ┌───────────────────────┼───────────────────────┐
             ▼                       ▼                       ▼
    ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
    │ UseOwnSettings │      │UseOwnBlockedServ│      │ ClientName/Tags│
    │  过滤开关      │      │  自定义阻塞    │      │  规则修饰符    │
    └────────────────┘      └────────────────┘      └────────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────┐
                    │   filtering.CheckHost()    │
                    └───────────┬────────────────┘
        ┌───────────┬───────────┼───────────┬───────────┬───────────┐
        ▼           ▼           ▼           ▼           ▼           ▼
    ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐
    │ hosts │   │filter │   │blocked│   │ safe  │   │parent │   │ safe  │
    │       │   │ rules │   │ serv  │   │browsing│   │control│   │search │
    └───┬───┘   └───┬───┘   └───┬───┘   └───┬───┘   └───┬───┘   └───┬───┘
        │           │           │           │           │           │
        └───────────┴───────────┴───────────┴───────────┴───────────┘
                                     │
                                  命中？
                                  ┌─┴─┐
                                  │是 │ → 生成过滤响应
                                  └─┬─┘
                                  │否 │
                                  └─┬─┘
                                     ▼
                          转发到上游 DNS
                                     │
                                     ▼
                    ┌────────────────────────────┐
                    │ filterDNSResponse()        │
                    │ 检查响应中的 CNAME/A/AAAA  │
                    └────────────────────────────┘
```

## 6. PersistentClient 与 RuntimeClient 的优先级

### 6.1 双重索引架构

Storage 内部维护两套独立的索引：

```
┌─────────────────────────────────────────────────────────┐
│                    Storage                               │
│  ┌───────────────────┐    ┌───────────────────────────┐ │
│  │   index           │    │   runtimeIndex            │ │
│  │  (Persistent)     │    │   (Runtime)               │ │
│  │                   │    │                           │ │
│  │  - byClientID     │    │   index: map[Addr]*Runtime│ │
│  │  - byIP           │    │                           │ │
│  │  - byCIDR         │    │  信息来源：                │ │
│  │  - byMAC          │    │   - WHOIS                  │ │
│  │  - byMAC          │    │   - ARP                    │ │
│  │                   │    │   - rDNS                   │ │
│  └───────────────────┘    │   - DHCP                   │ │
│                           │   - /etc/hosts              │ │
│                           └───────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**代码位置**：[internal/client/storage.go:126-169](internal/client/storage.go#L126-L169)

### 6.2 优先级判定规则

**应用过滤设置时（ApplyClientFiltering）**：**PersistentClient 完全优先，RuntimeClient 不参与过滤决策**。

```go
// [internal/client/storage.go:767-806]
func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings) {
    // 仅在 Persistent 索引中查找
    c, ok := s.index.findByClientID(ClientID(id))
    if !ok {
        c, ok = s.index.findByIP(addr)
    }
    if !ok {
        if foundMAC := s.dhcp.MACByIP(addr); foundMAC != nil {
            c, ok = s.index.findByMAC(foundMAC)
        }
    }
    if !ok {
        return // 未找到 Persistent，直接使用全局设置
    }
    // 后续只使用 c (Persistent) 的配置
}
```

**展示客户端信息时（FindLoose / querylog）**：两者互补，但 Persistent 的信息展示优先级更高。

```go
// [internal/client/storage.go:587-607]
func (s *Storage) FindLoose(ip netip.Addr, id string) (p *Persistent, ok bool) {
    // 先查 Persistent
    p, ok = s.index.find(id)
    if ok {
        return p.ShallowClone(), ok
    }
    // 再尝试 MAC 关联
    foundMAC := s.dhcp.MACByIP(ip)
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC)
    }
    // 最后尝试去除 zone 的 IP 匹配
    p = s.index.findByIPWithoutZone(ip)
    if p != nil {
        return p.ShallowClone(), true
    }
    return nil, false
}
```

**在 clientOrArtificial 中**：
```go
// [internal/home/clients.go:340-372]
func (clients *clientsContainer) clientOrArtificial(ip, id string) (c *querylog.Client, art bool) {
    cli, ok := clients.storage.FindLoose(ip, id)
    if ok {
        // Persistent 存在：使用 Persistent 的 Name、Tags 等
        return &querylog.Client{
            Name:           cli.Name,
            IgnoreQueryLog: cli.IgnoreQueryLog,
            WHOIS:          nil, // Persistent 不用 WHOIS
        }, false
    }
    // Persistent 不存在：使用 RuntimeClient 的信息
    src, host := clients.storage.findRuntime(ip)
    if host != "" {
        return &querylog.Client{Name: host}, false
    }
    return artificialClient, true
}
```

### 6.3 RuntimeClient 信息来源优先级（仅用于展示）

当 PersistentClient 不存在时，RuntimeClient.Info() 按以下优先级返回 host：

```
SourceHostsFile (5) > SourceDHCP (4) > SourceRDNS (3) > SourceARP (2) > SourceWHOIS (1)
```

**代码**：[internal/client/client.go:123-146](internal/client/client.go#L123-L146)

---

## 7. 多 Client Tag 合并匹配

### 7.1 Tag 白名单与校验

系统内置了一套固定的允许 Tag 列表，客户端配置时只能从列表中选择：

**代码位置**：[internal/client/storage.go:25-69](internal/client/storage.go#L25-L69)

```go
var allowedTags = []string{
    // 设备类型
    "device_audio", "device_camera", "device_gameconsole",
    "device_laptop", "device_nas", "device_other",
    "device_pc", "device_phone", "device_printer",
    "device_securityalarm", "device_tablet", "device_tv",
    // 操作系统
    "os_android", "os_ios", "os_linux", "os_macos", "os_windows",
    // 用户角色
    "user_admin", "user_child", "user_guest", "user_other", "user_parent",
    // 角色
    "device_virtual", "device_router", "device_wearable",
}
```

### 7.2 Tag 传递链路

```
PersistentClient.Tags ([]string)
    ↓ ApplyClientFiltering
Settings.ClientTags = slices.Clone(c.Tags)  // 深拷贝
    ↓ matchHost
urlfilter.DNSRequest.ClientTags = container.NewSortedSliceSet(setts.ClientTags...)
    ↓ urlfilter 规则引擎
规则中的 $client 修饰符匹配
```

**代码**：[internal/filtering/filtering.go:895-901](internal/filtering/filtering.go#L895-L901)

```go
ufReq := &urlfilter.DNSRequest{
    Hostname:          host,
    ClientTags:        container.NewSortedSliceSet(setts.ClientTags...),
    ClientIP:          setts.ClientIP,
    ClientIdentifiers: container.NewSortedSliceSet(setts.ClientName),
    DNSType:           rrtype,
}
```

### 7.3 多 Tag 匹配逻辑（urlfilter 规则引擎行为）

`$client` 修饰符支持两种语法：

| 语法 | 含义 | 匹配逻辑 |
|-----|------|---------|
| `$client=tag1` | 单 Tag | 客户端包含 `tag1` 即匹配 |
| `$client=tag1|tag2` | 多 Tag | **OR 逻辑**，客户端包含任一 Tag 即匹配 |
| `$client=tag1&tag2` | 多 Tag | **AND 逻辑**，客户端必须同时包含所有 Tag |
| `$client=~tag1` | 排除 Tag | 客户端不包含 `tag1` 才匹配 |

同时，`ClientIdentifiers` 字段包含客户端 Name，也参与 `$client` 匹配：
- `$client=MyClientName`：可按客户端名称精确匹配
- `$client=tag1|MyClientName`：Tag 或 Name 任一匹配即可

### 7.4 规则内多修饰符优先级

当规则同时包含多个修饰符时，匹配顺序为：
```
1. $client (Tag/Name/ID)
2. $ctag (响应内容类型)
3. $dnsrewrite (重写)
4. $important (优先级标记)
5. ... 其他修饰符
```

`$important` 修饰的规则会跳过白名单规则的覆盖。

---

## 8. ConfigReload 期间正在响应请求的过渡

### 8.1 Reconfigure 完整流程

**代码位置**：[internal/dnsforward/dnsforward.go:848-900](internal/dnsforward/dnsforward.go#L848-L900)

```go
func (s *Server) Reconfigure(ctx context.Context, conf *ServerConfig) error {
    s.serverLock.Lock()         // 1. 全局互斥锁
    defer s.serverLock.Unlock()

    s.stopLocked(ctx)           // 2. 停止旧的 proxy 实例
    time.Sleep(100 * time.Millisecond) // 3. 等待 fd 关闭（100ms grace period）

    // 4. 关闭旧的地址处理器
    if s.addrProc != nil {
        s.addrProc.Close()
    }

    s.conf = conf               // 5. 替换配置

    // 6. 初始化新的 upstream、cache 等组件
    s.conf.UpstreamConfig, err = proxy.ParseUpstreamsConfig(...)
    s.conf.CacheConfig = newDefaultCacheConfig(conf)
    s.initCache(ctx)
    s.initAddrProc(ctx)
    s.initDNS64(ctx)
    s.initEcs()

    // 7. 启动新 proxy（新 listener 接管端口）
    return s.startLocked(ctx)
}
```

### 8.2 正在处理请求的安全过渡

| 阶段 | 行为 | 对在途请求的影响 |
|-----|------|----------------|
| `stopLocked()` | 调用 `dnsproxy.Shutdown(ctx)` | 等待 `shutdownTimeout` 内的请求完成，超时则强制关闭 |
| 100ms Sleep | 等待 socket fd 释放 | 旧连接的 FIN 包处理窗口 |
| `startLocked()` | 新 proxy 实例监听端口 | 新请求立即路由到新配置实例 |

**请求级保护**：每个 DNS 请求处理过程中使用读锁保护 `dnsProxy` 指针：

```go
// [internal/dnsforward/dnsforward.go:838-843]
func (s *Server) proxy() (p *proxy.Proxy) {
    s.serverLock.RLock()           // 读锁：允许多个请求并发读取
    defer s.serverLock.RUnlock()
    return s.dnsProxy              // Reconfigure 期间不会替换为 nil
}
```

这意味着：
- **Reconfigure 前**开始的请求：使用旧配置的 `dnsProxy` 完成处理（读锁防止 `dnsProxy` 被置 nil）
- **Reconfigure 后**开始的请求：使用新配置的 `dnsProxy`
- **最坏情况**：100ms sleep + 端口切换窗口内，新连接可能短暂失败（TCP重试/UDP重发可自愈）

### 8.3 TLS 配置变更的特殊路径（证书热加载）

当仅 TLS 证书变更时，通过独立的 `tlsConfigChanged` 通道，影响范围更小：

```go
// [internal/home/web.go:215-260]
func (web *webAPI) tlsConfigChanged(ctx context.Context, tlsConf *tlsConfigSettings) {
    web.httpsServer.cond.L.Lock()
    if web.httpsServer.server != nil {
        // 优雅关闭旧 HTTPS 服务（带超时）
        ctx, cancel = context.WithTimeout(ctx, shutdownTimeout)
        shutdownSrv(ctx, ...)
        cancel()
    }
    // 启动新 HTTPS listener
    web.httpsServer.server = httpsServer
    go httpsServer.Serve(listener)
    web.httpsServer.cond.Broadcast()  // 通知等待的 goroutine
}
```

---

## 9. 配置变更触发的 dnscache 局部失效

### 9.1 缓存分层架构

```
┌────────────────────────────────────────────────────────────┐
│                      DNS Cache 层级                        │
├────────────────────────────────────────────────────────────┤
│  ① dnsProxy.Cache (dnsproxy 内置)                          │
│     - 按域名+类型缓存上游响应                               │
│     - 全局共享                                             │
│     - 全量清空：ClearCache()                                │
├────────────────────────────────────────────────────────────┤
│  ② 每个 PersistentClient 自定义 upstream 缓存              │
│     - uidToCustomConf[uid].proxyConf.ClearCache()          │
│     - 独立隔离，互不影响                                    │
│     - 局部失效：遍历所有 client 逐个 ClearCache()          │
├────────────────────────────────────────────────────────────┤
│  ③ SafeSearch/SafeBrowsing/Parental 专用缓存               │
│     - 各自独立的 LRU cache                                  │
│     - 按 TTL 自然过期，不主动失效                           │
└────────────────────────────────────────────────────────────┘
```

### 9.2 手动/API 触发的缓存清空

**代码位置**：[internal/dnsforward/http.go:764-770](internal/dnsforward/http.go#L764-L770)

```go
func (s *Server) handleCacheClear(w http.ResponseWriter, _ *http.Request) {
    s.dnsProxy.ClearCache()                     // ①全局缓存全清空
    s.conf.ClientsContainer.ClearUpstreamCache() // ②所有 client 缓存清空
}
```

客户端自定义 upstream 缓存清空实现：
```go
// [internal/client/upstreammanager.go:164-172]
func (m *upstreamManager) clearUpstreamCache() {
    for _, c := range m.uidToCustomConf {
        if c.proxyConf != nil {
            c.proxyConf.ClearCache()  // 逐个客户端独立清空
        }
    }
}
```

### 9.3 配置变更时的自动缓存失效策略

| 配置变更 | 缓存影响 | 实现方式 |
|---------|---------|---------|
| 全局 upstream 变更 | 清空 `dnsProxy.Cache` | `Reconfigure()` → 新 proxy 实例自带空 cache |
| 某客户端 upstream 变更 | 仅清空该客户端的 `proxyConf.Cache` | `upstreamManager.update()` → `c.proxyConf.ClearCache()` |
| 过滤规则变更 | **不清空 DNS cache** | 仅影响后续 CheckHost()，缓存的 DNS 响应仍命中 |
| 客户端开关（UseOwnSettings 等）变更 | **不直接影响缓存** | 后续请求直接用新 Settings，旧 cache 仍可能被使用 |
| TLS 证书变更 | **无影响** | 仅影响传输层 |
| 阻塞服务列表变更 | **不直接影响缓存** | 仅影响后续 CheckHost() |

### 9.4 局部失效 vs 全量失效的权衡

- **自定义 upstream 变更** → **局部失效**：只清空受影响客户端的缓存，避免全局缓存雪崩
- **Reconfigure() 全局变更** → **全量失效**：通过重建 proxy 实例自然获得干净缓存
- **过滤规则更新** → **不主动失效**：过滤与 DNS 缓存分层，受 DNS TTL 控制（设计取舍）

---

## 10. services.json 加载与运行时合并

### 10.1 构建时编译注入（非运行时加载）

`blocked-services` 列表**不是运行时从 `services.json` 下载**，而是在构建时通过脚本编译进 Go 二进制：

```
构建流程：
┌─────────────────┐     HTTP GET      ┌─────────────────────────────┐
│ HostlistsRegistry│ ──────────────→  │ https://.../services.json   │
└─────────────────┘                   └──────────────┬──────────────┘
                                                      │ JSON 解析
                                                      ▼
┌──────────────────────────────────────────────────────────────┐
│ scripts/blocked-services/main.go                             │
│   hlServices struct { BlockedServices[], ServiceGroups[] }   │
└──────────────────────────────┬───────────────────────────────┘
                               │ template.Execute()
                               ▼
                 ┌───────────────────────────┐
                 │ internal/filtering/        │
                 │   servicelist.go (生成)    │
                 │                            │
                 │ var blockedServices =      │
                 │   []blockedService{        │
                 │     {ID:"4chan", Rules:[], │
                 │      IconSVG:"<svg>...",   │
                 │      GroupID:"social_..."} │
                 │     ... 100+ 服务          │
                 │   }                        │
                 └─────────────┬─────────────┘
                               │ go build
                               ▼
                 编译进 AdGuardHome 二进制文件
```

**脚本位置**：[scripts/blocked-services/main.go:27-114](scripts/blocked-services/main.go#L27-L114)

### 10.2 包级初始化：blockedServices → serviceRules

程序启动时 `InitModule()` 将原始规则文本编译为 NetworkRule：

**代码位置**：[internal/filtering/blocked.go:27-60](internal/filtering/blocked.go#L27-L60)

```go
// 包级变量
var serviceRules map[string][]*rules.NetworkRule  // ID → 编译后的规则
var serviceIDs []string                            // 排序的 ID 列表

func initBlockedServices(ctx context.Context, l *slog.Logger) {
    svcLen := len(blockedServices)
    serviceIDs = make([]string, svcLen)
    serviceRules = make(map[string][]*rules.NetworkRule, svcLen)

    for i, s := range blockedServices {
        netRules := make([]*rules.NetworkRule, 0, len(s.Rules))
        for _, text := range s.Rules {
            // 将文本规则（如 "||4cdn.org^"）编译为 NetworkRule 对象
            rule, err := rules.NewNetworkRule(text, rulelist.IDBlockedService)
            if err == nil {
                netRules = append(netRules, rule)
            }
        }
        serviceIDs[i] = s.ID
        serviceRules[s.ID] = netRules  // 存入 map，O(1) 查找
    }
    slices.Sort(serviceIDs)
}
```

### 10.3 运行时合并：全局 + 客户端

**每个 DNS 请求独立合并**，不修改全局 `serviceRules`：

```
请求到达
    ↓
ApplyAdditionalFiltering()
    ├─ ① ApplyBlockedServices(setts)
    │     全局 BlockedServices.IDs
    │     → ApplyBlockedServicesList(setts, globalIDs)
    │     → setts.ServicesRules = serviceRules[id]... 的副本
    │
    ├─ ② applyClientFiltering(clientID, ip, setts)
    │     找到 PersistentClient
    │     if UseOwnBlockedServices {
    │         setts.BlockedServices = c.BlockedServices.Clone()  // 替换全局配置
    │         setts.ServicesRules = nil                         // 清空前面的全局规则
    │     }
    │
    └─ ③ if setts.BlockedServices 有值：
          Schedule 检查通过 → ApplyBlockedServicesList(setts, setts.BlockedServices.IDs)
          → setts.ServicesRules = 追加对应服务的规则
```

**关键代码**：[internal/filtering/filter.go:710-724](internal/filtering/filter.go#L710-L724)

```go
func (d *DNSFilter) ApplyAdditionalFiltering(cliAddr netip.Addr, clientID string, setts *Settings) {
    d.ApplyBlockedServices(setts)        // 先应用全局
    d.applyClientFiltering(clientID, cliAddr, setts)  // 再应用客户端（可能替换）
    if setts.BlockedServices != nil {
        setts.ServicesRules = nil
        svcs := setts.BlockedServices.IDs
        if !setts.BlockedServices.Schedule.Contains(time.Now()) {
            d.ApplyBlockedServicesList(setts, svcs)  // 重新加载（覆盖或新增）
        }
    }
}
```

### 10.4 ApplyBlockedServicesList 实现

```go
// [internal/filtering/blocked.go:139-158]
func (d *DNSFilter) ApplyBlockedServicesList(setts *Settings, list []string) {
    for _, name := range list {
        rules, ok := serviceRules[name]  // 从预编译 map 获取规则
        if !ok {
            continue  // 未知 ID 跳过（FilterUnknownIDs 会提前过滤）
        }
        setts.ServicesRules = append(setts.ServicesRules,
            ServiceEntry{Rules: rules, ID: name})
    }
}
```

---

## 11. DoH 与 DoT 客户端识别特殊性

### 11.1 三种加密协议的 ClientID 提取方式

| 协议 | ClientID 来源 | 提取方式 | 代码位置 |
|-----|--------------|---------|---------|
| **DoH (DNS-over-HTTPS)** | URL Path 前缀 | `https://dns.example.com/{clientID}/dns-query` | [middleware.go:105-113](internal/dnsforward/middleware.go#L105-L113) |
| **DoT (DNS-over-TLS)** | SNI 子域名前缀 | `{clientID}.dns.example.com` | [middleware.go:128-135](internal/dnsforward/middleware.go#L128-L135) |
| **DoQ (DNS-over-QUIC)** | SNI 子域名前缀 | `{clientID}.dns.example.com` | [middleware.go:114](internal/dnsforward/middleware.go#L114) |

### 11.2 提取流程完整实现

**代码位置**：[internal/dnsforward/middleware.go:99-138](internal/dnsforward/middleware.go#L99-L138)

```go
func (s *Server) clientIDFromDNSContext(
    ctx context.Context, l *slog.Logger, pctx *proxy.DNSContext,
) (clientID string, err error) {
    proto := pctx.Proto

    // ── DoH：先尝试从 URL Path 提取 ────────────────
    if proto == proxy.ProtoHTTPS {
        clientID, err = clientIDFromDNSContextHTTPS(pctx)
        // URL 示例：/dns-query/{clientID} 或 /{clientID}/dns-query
        if err != nil {
            return "", err
        } else if clientID != "" {
            return clientID, nil  // ✅ 路径匹配成功，直接返回
        }
        // 路径中没有 ClientID → 继续尝试 SNI 子域名方式
    }

    // ── DoT/DoQ 或 DoH fallback：从 SNI 提取 ──────
    if proto != proxy.ProtoTLS && proto != proxy.ProtoQUIC && proto != proxy.ProtoHTTPS {
        return "", nil  // 普通 UDP/TCP 无 ClientID
    }

    hostSrvName := s.conf.TLSConf.ServerName  // 配置的基准域名
    if hostSrvName == "" {
        return "", nil  // 未配置 ServerName，无法提取
    }

    // 从 TLS ClientHello 获取客户端实际的 SNI
    cliSrvName := clientServerName(pctx)

    // 对比 cliSrvName 与 hostSrvName，提取前缀
    clientID, err = clientIDFromClientServerName(
        hostSrvName,           // 如 "dns.example.com"
        cliSrvName,            // 如 "myphone.dns.example.com"
        s.conf.TLSConf.StrictSNICheck,
    )
    return clientID, err
}
```

### 11.3 DoH Path 解析规则

`clientIDFromDNSContextHTTPS` 的 URL Path 匹配规则：

| Path 示例 | 提取的 ClientID | 说明 |
|----------|----------------|------|
| `/dns-query` | `""` | 标准路径，无 ClientID |
| `/dns-query/myphone` | `"myphone"` | ClientID 作为路径后缀 |
| `/myphone/dns-query` | `"myphone"` | ClientID 作为路径前缀 |
| `/resolve` | `""` | 兼容 JSON API 路径 |
| `/resolve/myphone` | `"myphone"` | JSON API + ClientID |

### 11.4 StrictSNICheck 对 DoT/DoQ 的影响

| StrictSNICheck 值 | 行为 | 匹配示例 |
|------------------|------|---------|
| `false`（宽松） | SNI 后缀匹配 `hostSrvName` 即可，提取前缀 | `myphone.dns.example.com` → `"myphone"` |
| `true`（严格） | SNI 必须精确等于 `{clientID}.{hostSrvName}`，否则返回错误 | `random.example.com` → 错误，拒绝连接 |

### 11.5 ClientID 传递到请求处理链

```
Middleware 提取 ClientID
    ↓
contextWithClientID(ctx, id)  // 存入 Context
    ↓
processInitial()
    ↓
clientIDFromContext(ctx)  // 从 Context 取出
    ↓
dctx.clientID = clientID
    ↓
clientRequestFilteringSettings(dctx)
    ↓
ApplyClientFiltering(clientID, ip, setts)  // 用于查找 PersistentClient
    ↓
s.index.findByClientID(ClientID(clientID))  // 最高优先级查找
```

### 11.6 UDP/TCP（明文）无 ClientID 机制

普通 DNS 请求只能通过 **IP → PersistentClient** 查找，无法通过 ClientID 标识：
- DoH/DoT/DoQ：ClientID 查找优先级 **高于** IP
- UDP/TCP：只能通过 IP/MAC/CIDR 匹配

---

## 12. CleanupClients 周期性清理算法

### 12.1 清理对象与触发时机

**清理对象**：RuntimeClient（运行时客户端），PersistentClient 永久保留。

**触发时机**：每次从各来源更新 Runtime 信息后，执行 `removeEmpty()`。

### 12.2 removeEmpty 清理实现

**代码位置**：[internal/client/runtimeindex.go:61-72](internal/client/runtimeindex.go#L61-L72)

```go
func (ri *runtimeIndex) removeEmpty() (n int) {
    for ip, rc := range ri.index {
        if rc.isEmpty() {
            delete(ri.index, ip)  // 从 map 删除
            n++
        }
    }
    return n
}
```

`isEmpty()` 判定：**所有来源字段都为 nil**（即没有任何信息）
```go
// [internal/client/client.go:193-200]
func (r *Runtime) isEmpty() (ok bool) {
    return r.whois == nil &&
        r.arp == nil &&
        r.rdns == nil &&
        r.dhcp == nil &&
        r.hostsFile == nil
}
```

### 12.3 按来源增量清理

每次更新某来源前，先清除该来源的旧信息，再重新填充：

```go
// [internal/client/storage.go:595-620]
func (s *Storage) addFromSystemARP(ctx context.Context) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.arpDB.Refresh(ctx)

    s.runtimeIndex.clearSource(SourceARP)  // 先清除 ARP 来源的所有信息

    for _, neighbor := range s.arpDB.Neighbors() {
        s.runtimeIndex.setInfo(neighbor.IP, SourceARP, []string{neighbor.Name})
        // 如果该 IP 没有其他来源信息，会在最后被清理
    }

    removed := s.runtimeIndex.removeEmpty()  // 最后统一清理空的 RuntimeClient
    s.logger.DebugContext(ctx, "cleaned up arp clients", "n", removed)
}
```

`clearSource` 实现：
```go
// [internal/client/runtimeindex.go:54-59]
func (ri *runtimeIndex) clearSource(src Source) {
    for _, rc := range ri.index {
        rc.unset(src)  // 仅清除该来源的字段，保留 Runtime 对象
    }
}
```

### 12.4 各来源更新时的清理联动

| 更新来源 | 清理动作 | 代码位置 |
|---------|---------|---------|
| ARP 更新 | `clearSource(ARP)` → `removeEmpty()` | [storage.go:595-620](internal/client/storage.go#L595-L620) |
| DHCP 更新 | `clearSource(DHCP)` → `removeEmpty()` | [storage.go:700-715](internal/client/storage.go#L700-L715) |
| hosts 文件变更 | `clearSource(HostsFile)` → `removeEmpty()` | [storage.go:650-680](internal/client/storage.go#L650-L680) |
| rDNS 异步更新 | 单个 IP 级别的 setInfo/unset | [storage.go:340-356](internal/client/storage.go#L340-L356) |
| WHOIS 更新 | 单个 IP 级别的 setWHOIS/unset | 异步单条更新，不批量清理 |

### 12.5 清理算法的设计考量

**优点**：
1. **原子性**：清除旧数据 + 填充新数据在同一锁内完成，无中间状态
2. **惰性删除**：先清除某来源字段，最后统一判断 isEmpty，避免同一 IP 被反复删除创建
3. **跨来源保留**：某 IP 有 DHCP 信息但 ARP 表中消失时，仍保留（不会误删）

**潜在问题**：
- RuntimeClient 不会因「长时间未活跃」被自动清理，仅在来源数据消失时被清理
- 如果某 IP 仅出现在 ARP 表一次后消失，会在下一次 ARP 更新周期（10分钟）被清理

### 12.6 ARP 更新周期

默认 ARP 表刷新间隔：**10 分钟**
```go
// [internal/home/clients.go:311-312]
const arpClientsUpdatePeriod = 10 * time.Minute

// [internal/client/storage.go:224-236]
func (s *Storage) periodicARPUpdate(ctx context.Context) {
    t := time.NewTicker(s.arpClientsUpdatePeriod)
    for {
        select {
        case <-t.C:
            s.ReloadARP(ctx)  // 触发清理
        case <-s.done:
            return
        }
    }
}
```

---

## 13. 关键配置参数

| 参数 | 类型 | 说明 | 代码位置 |
|-----|------|------|---------|
| `ProtectionEnabled` | bool | 总保护开关 | [filtering.go:193](internal/filtering/filtering.go#L193) |
| `FilteringEnabled` | bool | 过滤规则开关 | [filtering.go:184](internal/filtering/filtering.go#L184) |
| `SafeBrowsingEnabled` | bool | 安全浏览开关 | [filtering.go:190](internal/filtering/filtering.go#L190) |
| `ParentalEnabled` | bool | 家长控制开关 | [filtering.go:189](internal/filtering/filtering.go#L189) |
| `SafeSearchConf.Enabled` | bool | 安全搜索总开关 | [filtering.go:126](internal/filtering/filtering.go#L126) |
| `CacheTime` | uint | 缓存 TTL（分钟） | [filtering.go:166](internal/filtering/filtering.go#L166) |
| `SafeBrowsingCacheSize` | uint | 安全浏览缓存大小 | [filtering.go:162](internal/filtering/filtering.go#L162) |
| `ParentalCacheSize` | uint | 家长控制缓存大小 | [filtering.go:164](internal/filtering/filtering.go#L164) |
| `SafeSearchCacheSize` | uint | 安全搜索缓存大小 | [filtering.go:163](internal/filtering/filtering.go#L163) |
| `FiltersUpdateIntervalHours` | uint32 | 规则更新间隔（小时） | [filtering.go:177](internal/filtering/filtering.go#L177) |
| `ARPClientsUpdatePeriod` | time.Duration | ARP 表刷新周期 | [storage.go:119](internal/client/storage.go#L119) |

## 14. 调试与排错要点

1. **客户端识别问题**：
   - 检查 `Source` 优先级，确认客户端信息来源是否正确
   - 查看 `FindParams` 的查找顺序，确认标识是否匹配
   - 注意 IP 地址的 zone 索引可能导致匹配失败
   - **DoH/DoT ClientID 不匹配**：检查 URL Path 格式或 SNI 子域名，是否符合提取规则
   - **Persistent vs Runtime 混淆**：过滤决策只看 PersistentClient，RuntimeClient 仅用于展示

2. **规则不生效问题**：
   - 检查 `ProtectionEnabled` 和 `FilteringEnabled` 开关
   - 确认 `hostCheckers` 执行顺序，前面的检查可能短路后续检查
   - 白名单规则优先级高于黑名单，检查是否被误放行
   - 客户端 `UseOwnSettings` 开关会覆盖全局设置
   - **Tag 不匹配**：确认 Tag 是否在 `allowedTags` 白名单内
   - **多 Tag 语法**：`|` 是 OR 逻辑，`&` 是 AND 逻辑，注意不要搞混
   - **$important 修饰符**：会跳过白名单覆盖，检查是否误加

3. **缓存相关问题**：
   - 修改规则后注意缓存 TTL，可临时减小 `CacheTime` 测试
   - 异步更新规则时，需等待新引擎初始化完成
   - 安全浏览/家长控制缓存基于 hash prefix，清除需等待过期
   - **过滤规则变更不立即生效**：DNS proxy cache 不会主动失效，需手动调用 `/control/cache_clear`
   - **客户端 upstream 缓存**：仅受影响客户端的缓存被清空，全局缓存不受影响

4. **阻塞服务问题**：
   - 检查 `Schedule.Contains(time.Now())`，调度时间内不阻塞
   - 客户端 `UseOwnBlockedServices` 会替换全局阻塞服务列表
   - `ServicesRules` 字段是生效的规则列表
   - **services.json 构建时注入**：运行时不会动态下载，规则随二进制版本更新
   - **ApplyBlockedServicesList 执行顺序**：先全局→再客户端覆盖→最后按 Schedule 决定是否加载

5. **ConfigReload 期间问题**：
   - **100ms 端口切换窗口**：新连接可能短暂失败，TCP/UDP 会自动重试
   - **Reconfigure 全局锁**：`serverLock.Lock()` 期间所有新请求排队等待
   - **TLS 证书热加载**：仅重启 HTTPS/TLS listener，不影响 DNS 明文请求

6. **CleanupClients 清理时机问题**：
   - RuntimeClient 不会因「不活跃」被清理，仅在来源数据消失时清理
   - ARP 更新周期默认 10 分钟，离线设备最长需 10 分钟才被清掉
   - 某 IP 仅出现在 ARP 中：下一次 `periodicARPUpdate` 时会被先 `clearSource(ARP)` 再 `removeEmpty()` 删除

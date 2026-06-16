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

## 13. MAC 与 IP 同时匹配但 Name 不同的歧义解决

### 13.1 冲突场景

当一个 DNS 请求同时满足以下条件时，存在歧义：
1. 请求来源 IP 匹配 PersistentClient-A 的 IP
2. DHCP 服务器查到该 IP 对应的 MAC 地址，MAC 又匹配 PersistentClient-B 的 MAC
3. Client-A 与 Client-B 是两个不同的持久化客户端，Name 不同

### 13.2 PersistentClient 侧的根本防止：标识符全局唯一约束

AdGuardHome **在存储层就杜绝了这种歧义**，通过 `clashes()` 系列检查在 `Add()` 和 `Update()` 时阻止标识符被多个客户端共享：

```go
// [internal/client/index.go:105-137]
func (ci *index) clashes(c *Persistent) (err error) {
    if p := ci.clashesName(c); p != nil {
        return fmt.Errorf("another client uses the same name %q", p.Name)
    }
    for _, id := range c.ClientIDs {
        existing, ok := ci.clientIDToUID[id]
        if ok && existing != c.UID {
            return fmt.Errorf("another client %q uses the same ClientID %q", p.Name, id)
        }
    }
    p, ip := ci.clashesIP(c)
    if p != nil {
        return fmt.Errorf("another client %q uses the same IP %q", p.Name, ip)
    }
    p, s := ci.clashesSubnet(c)
    if p != nil {
        return fmt.Errorf("another client %q uses the same subnet %q", p.Name, s)
    }
    p, mac := ci.clashesMAC(c)
    if p != nil {
        return fmt.Errorf("another client %q uses the same MAC %q", p.Name, mac)
    }
    return nil
}
```

完整校验链路：
```
Storage.Add()
  └─ p.validate()          // 字段合法性
  └─ s.index.clashesUID()  // UID 不能重复
  └─ s.index.clashes()     // Name / ClientID / IP / Subnet / MAC 任一重复 → 拒绝
      ├─ clashesName()
      ├─ clashesIP()
      ├─ clashesSubnet()
      └─ clashesMAC()

Storage.Update(name, p)
  └─ p.validate()
  └─ p.UID = stored.UID    // 复用旧 UID
  └─ s.index.clashes(p)    // 与其他所有客户端比对（自身 UID 豁免）
  └─ index.remove(stored)
  └─ index.add(p)
```

### 13.3 查找顺序中的隐性歧义：DHCP MAC 反查

虽然标识符冲突被 `clashes()` 杜绝，但 `ApplyClientFiltering` 和 `findByIP` 中仍存在「先 IP 匹配，再查 DHCP 找 MAC」的两步查找逻辑：

```go
// [internal/client/storage.go:564-576]
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    p, ok = s.index.findByIP(addr)  // 第 1 步：直接 IP 匹配
    if ok {
        return p, true
    }
    foundMAC := s.dhcp.MACByIP(addr) // 第 2 步：DHCP 服务器反查 MAC
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC) // 用 MAC 再查一次
    }
    return nil, false
}
```

**歧义场景**：
- PersistentClient-A 配置了 IP `192.168.1.50`
- PersistentClient-B 配置了 MAC `aa:bb:cc:dd:ee:ff`
- DHCP 租约恰好在运行时将 `192.168.1.50` 分配给了 `aa:bb:cc:dd:ee:ff`

**解决策略：先匹配到的优先，不会继续回退**
- 因为 `findByIP` 第 1 步 `index.findByIP(addr)` 命中 Client-A 即返回，**不会再执行 DHCP MAC 反查**
- 因此 IP 匹配的优先级 > DHCP 动态 MAC 反查匹配
- 只有当 IP 未在任何 PersistentClient 中出现时，才会走 DHCP→MAC 路径

### 13.4 RuntimeClient 侧的歧义：多来源 Name 覆盖

RuntimeClient 从多个来源获取 Name 信息，按 `Source` 优先级由高到低覆盖：

```
SourceHostsFile(5) > SourceDHCP(4) > SourceRDNS(3) > SourceARP(2) > SourceWHOIS(1)
```

`Runtime.Info()` 按优先级返回第一个非空的 Name：
```go
// [internal/client/client.go]
func (r *Runtime) Info() (cs Source, host string) {
    switch {
    case r.hostsFile != nil:   // hosts 文件最高优先级
        cs, info = SourceHostsFile, r.hostsFile
    case r.dhcp != nil:        // 然后是 DHCP
        cs, info = SourceDHCP, r.dhcp
    case r.rdns != nil:        // 反向 DNS
        cs, info = SourceRDNS, r.rdns
    case r.arp != nil:         // ARP
        cs, info = SourceARP, r.arp
    case r.whois != nil:       // WHOIS（仅 ASN/组织，不含 hostname）
        cs = SourceWHOIS
    }
}
```

---

## 14. MergeTags 与 Tags 数量上限

### 14.1 allowedTags 白名单（25 个内置 Tag）

```go
// [internal/client/storage.go:25-50]
var allowedTags = []string{
    "device_audio", "device_camera", "device_gameconsole",
    "device_laptop", "device_nas", "device_other",
    "device_pc", "device_phone", "device_printer",
    "device_securityalarm", "device_tablet", "device_tv",
    "os_android", "os_ios", "os_linux",
    "os_macos", "os_other", "os_windows",
    "user_admin", "user_child", "user_regular",
}
```

校验发生在 `Persistent.validate()` 中：
```go
// [internal/client/persistent.go:158-166]
for _, t := range c.Tags {
    _, ok := slices.BinarySearch(allTags, t)  // 二分查找
    if !ok {
        return fmt.Errorf("invalid tag: %q", t)
    }
}
slices.Sort(c.Tags)  // 校验后排序存储
```

### 14.2 Tags 数量上限：无硬编码上限，但白名单长度 = 25

当前代码中**没有**类似 `maxTagsPerClient` 的常量限制单个 PersistentClient 的 Tags 数量。但由于 Tag 必须属于 `allowedTags`（长度 25），实际上限就是 25 个。

API 层面也通过 `AllowedTags()` 暴露白名单，前端在选择 Tag 时只会给出这 25 个选项：
```go
// [internal/client/storage.go:722-726]
func (s *Storage) AllowedTags() (tags []string) {
    return s.allowedTags
}
```

### 14.3 Tag 传递链中的切片克隆

每次请求会克隆 Tags 切片写入 `filtering.Settings`，避免并发读写：
```go
// [internal/client/storage.go:795-796]
setts.ClientTags = slices.Clone(c.Tags)
```

---

## 15. atomicConfig 事务边界

### 15.1 `*homeconfig` 内嵌 `sync.RWMutex`

```go
// [internal/home/config.go:167]
type config struct {
    // ... 所有 YAML 字段 ...
    sync.RWMutex `yaml:"-"`  // 读写锁，不序列化
    SchemaVersion uint
}
```

全局 `config` 变量本身带有 `sync.RWMutex`，作为"原子配置"的事务边界。

### 15.2 写事务：`config.Lock()/Unlock()`

写配置到磁盘（`writeConfig()`）或通过 API 修改配置时，持有写锁：
```go
// 典型写事务：
config.Lock()
defer config.Unlock()
// 读取 + 修改 config 字段
// 写 YAML 到磁盘
```

### 15.3 读事务：`config.RLock()/RUnlock()`

所有需要一致视图的读取路径使用读锁：
```go
config.RLock()
defer config.RUnlock()
// 读取多个字段，保证原子一致视图
```

### 15.4 读写锁的分层：`config` 锁 vs `clients.lock` vs `dnsforward.serverLock`

AdGuardHome 使用**多层锁**保护不同粒度的配置，事务边界嵌套时要注意顺序：

| 锁 | 保护对象 | 粒度 |
|---|---------|------|
| `config.RWMutex` | 全局 `AdGuardHome.yaml` 配置对象 | 最粗粒度 |
| `clientsContainer.lock (sync.Mutex)` | `clients` HTTP API、客户端增删改 | 中粒度 |
| `client.Storage.mu (sync.Mutex)` | PersistentClient index、RuntimeClient index | 中粒度（客户端存储内部） |
| `dnsforward.Server.serverLock (sync.RWMutex)` | dnsProxy 指针、配置热加载 | 最细粒度（DNS 请求路径） |

**加锁顺序（避免死锁）**：
```
config.RWMutex → clients.lock → Storage.mu → dnsforward.serverLock
```
外层锁在持有期间可以获取内层锁，反之不可。

### 15.5 `handleSetProtection` 的事务边界示例

```go
// [internal/dnsforward/http.go:810-818]
func() {
    s.serverLock.Lock()         // 先拿 DNS 层写锁
    defer s.serverLock.Unlock()
    s.dnsFilter.SetProtectionStatus(...)  // 修改过滤引擎状态
}()
s.conf.ConfModifier.Apply(ctx)   // 再触发全局配置写盘（会拿 config.Lock）
```

注意：这里先拿 `serverLock` 再调用 `Apply` 拿 `config.Lock`，是与上面相反的方向。但 `ConfModifier.Apply` 是独立路径，不会反向持有 `serverLock`，因此不会死锁。

---

## 16. dnscache 级联失效路径

### 16.1 三层缓存及各自的触发点

| 缓存层 | 内容 | 失效方式 | 触发 API |
|-------|------|---------|---------|
| **全局 dnsProxy.Cache** | 所有 DNS 响应 | 全量清空（无局部失效） | `POST /control/cache_clear`、`Reconfigure()` |
| **客户端自定义 upstream 缓存** | 特定 PersistentClient 的自定义 upstream 响应 | 全量清空或按客户端清空 | `POST /control/cache_clear`、`Storage.Add/Update()` |
| **SafeSearch LRU** | 搜索引擎域名→安全域名映射 | 全量清空 | `SafeSearch.Update()` |
| **SafeBrowsing/Parental HashPrefix** | URL hash prefix 查毒结果 | TTL 过期（无主动清除 API） | 仅被动过期 |

### 16.2 手动级联失效：`handleCacheClear`

```go
// [internal/dnsforward/http.go:764-770]
func (s *Server) handleCacheClear(w http.ResponseWriter, _ *http.Request) {
    s.dnsProxy.ClearCache()                           // 第 1 层：全局 DNS 缓存
    s.conf.ClientsContainer.ClearUpstreamCache()       // 第 2 层：所有客户端 upstream 缓存
    _, _ = io.WriteString(w, "OK")
}
```

`ClearUpstreamCache` 内部遍历所有 PersistentClient 逐个清理：
```go
// [internal/client/upstreammanager.go]
func (m *upstreamManager) clearUpstreamCache() {
    for _, conf := range m.uidToCustomConf {
        conf.proxyConf.ClearCache()
    }
}
```

### 16.3 SafeSearch 配置变更的级联失效

```go
// [internal/filtering/safesearch/safesearch.go:349-361]
func (ss *Default) Update(ctx context.Context, conf filtering.SafeSearchConfig) (err error) {
    ss.mu.Lock()
    defer ss.mu.Unlock()
    err = ss.resetEngine(ctx, rulelist.IDSafeSearch, conf)
    if err != nil {
        return err
    }
    ss.cache.Clear()   // 引擎重建后，缓存无条件全量失效
    return nil
}
```

### 16.4 配置变更时的缓存失效粒度矩阵

| 配置变更类型 | dnsProxy.Cache | 客户端 upstream cache | SafeSearch | SafeBrowsing/Parental |
|------------|----------------|----------------------|-----------|----------------------|
| 全局 upstream 变更（`Reconfigure`） | ✅ 重建清空 | ❌ 不变 | ❌ 不变 | ❌ 不变 |
| 某 PersistentClient upstream 变更 | ❌ 不变 | ✅ 仅该客户端 `isChanged=true` 下次请求重建 | ❌ 不变 | ❌ 不变 |
| 过滤规则列表增删 | ❌ **不主动失效**（依赖 TTL） | ❌ 不变 | ❌ 不变 | ❌ 不变 |
| 手动 `POST /control/cache_clear` | ✅ 全清空 | ✅ 所有客户端清空 | ❌ 不变 | ❌ 不变 |
| SafeSearch 配置变更 | ❌ 不变 | ❌ 不变 | ✅ 全清空 | ❌ 不变 |
| SafeBrowsing 开关切换 | ❌ 不变 | ❌ 不变 | ❌ 不变 | ✅ 引擎替换（缓存 TTL 保留） |

### 16.5 客户端 upstream 缓存的"懒重建"机制

```go
// [internal/client/upstreammanager.go:100-119]
func (m *upstreamManager) updateCustomUpstreamConfig(c *Persistent) {
    cliConf, ok := m.uidToCustomConf[c.UID]
    if !ok {
        cliConf = &customUpstreamConfig{...}
        m.uidToCustomConf[c.UID] = cliConf
    }
    cliConf.upstreams = slices.Clone(c.Upstreams)
    cliConf.upstreamsCacheSize = c.UpstreamsCacheSize
    cliConf.isChanged = true   // 打脏标记，不立即重建
}

// 下一次请求 customUpstreamConfig() 时才真正重建并清空旧缓存：
// upstreamManager.customUpstreamConfig():
//   if cliConf.isChanged || cliConf.commonConfUpdate.Before(m.confUpdate) {
//       old := cliConf.proxyConf
//       cliConf.proxyConf = ... 重新解析 upstream ...
//       old.Close()              // 关闭旧对象，缓存随之消失
//       cliConf.isChanged = false
//   }
```

---

## 17. services.json 热更新 reload

### 17.1 代码生成：`servicelist.go` 是构建产物，非运行时下载

```
// 生成命令：
go run ./scripts/blocked-services/main.go
// 输入：  https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/blocked-services.json
// 输出：  internal/filtering/servicelist.go
```

`servicelist.go` 文件头：
```go
// Code generated by go run ./scripts/blocked-services/main.go; DO NOT EDIT.
var blockedServices = []blockedService{{
    ID:      "4chan",
    Rules:   []string{"||4cdn.org^", "||4chan.org^", ...},
    ...
}, ...}
```

→ **运行时没有从网络动态加载 services.json 的逻辑**，规则列表随二进制发布。

### 17.2 包级初始化：`blockedServices` → `serviceRules`

```go
// [internal/filtering/blocked.go:27-60]
var serviceRules map[string][]*rules.NetworkRule

func initBlockedServices() {
    serviceRules = make(map[string][]*rules.NetworkRule, len(blockedServices))
    for _, s := range blockedServices {
        for _, ruleText := range s.Rules {
            nr, err := rulelist.NewRuleBuilder().
                Text(ruleText).
                Result()
            serviceRules[s.ID] = append(serviceRules[s.ID], nr.(*rules.NetworkRule))
        }
    }
}
```

`initBlockedServices()` 在 `InitModule()` 中被调用，**进程生命周期内只执行一次**。

### 17.3 运行时"热更新"的实际含义：reload 的不是 services.json，是用户选中的 ID 列表

用户通过以下 API 变更"要阻塞哪些服务"：
```
GET  /control/blocked_services/all           // 列出所有可用服务（从 blockedServices 读）
GET  /control/blocked_services/get           // 获取当前全局/客户端的阻塞配置
PUT  /control/blocked_services/update        // 更新阻塞配置（调度 + 服务 ID 列表）
```

`handleBlockedServicesUpdate` 内部调用：
```
filter.SetBlockedServices(schedule, ids)
  └─ 重建全局 BlockedServices 对象
  └─ 内部不会重新编译 serviceRules（因为 serviceRules 不变）
```

→ 所谓"热更新"只更新用户的**选择**（ID 列表 + Schedule），底层规则库 `serviceRules` 是只读的。

### 17.4 重新编译 serviceRules 的唯一方式：重启进程

由于 `initBlockedServices()` 只在启动时执行一次，要加载新版 `services.json` 的规则必须：
1. 重新构建二进制（执行 `go generate` 或脚本）
2. 重启 AdGuardHome

没有运行时 API 可以触发 serviceRules 重建。

---

## 18. SNI 加密（ECH）启用后的客户端识别退路

### 18.1 ECH（Encrypted Client Hello）对 ClientID 提取的影响

传统 TLS 的 SNI 扩展是明文的，AdGuardHome 从 SNI 的子域名解析 ClientID：
```
myphone.dns.example.com  →  ClientID = "myphone"
```

但启用 ECH（Encrypted Client Hello，即 TLS 1.3 ESNI/ECH 扩展）后：
- **Outer SNI**（明文）：仅包含公共域名（如 `dns.example.com`），不带 ClientID
- **Inner SNI**（加密，在 EncryptedExtensions 中）：包含真实 SNI，但服务器需要持有 ECH 私钥才能解密

### 18.2 AdGuardHome 对 ECH 的当前支持情况

在 SVCB/HTTPS 记录生成时支持透传 `ech` 参数：
```go
// [internal/dnsforward/svcbmsg.go + svcbmsg_internal_test.go:97-107]
// 测试用例：svcb: ech, "AAAA" → SVCBECHConfig{ECH: []byte{0,0,0}}
// 表示 DNS Filter 规则中的 $dnssvcb 参数能识别 ech= 值并写入 HTTPS/SVCB 响应
```

但**TLS listener 层不支持 ECH 解密**（`crypto/tls` 标准库目前也不支持 ECH），因此：

| 协议 | 启用 ECH 后 ClientID 能否提取 | 说明 |
|-----|----------------------------|------|
| **DoH (HTTPS)** | ✅ 可提取（优先用 URL Path） | DoH 的 ClientID 主要从 `/myphone/dns-query` 的 URL Path 提取，不依赖 SNI |
| **DoT (TLS over TCP/853)** | ❌ 无法提取 | Outer SNI 只有公共域名，Inner SNI 无法解密，ClientID 子域名丢失 |
| **DoQ (QUIC/853)** | ❌ 无法提取 | 同上，QUIC 的 Initial 包中的 SNI 也被 ECH 加密 |

### 18.3 DoH Path 提取：ECH 场景下的退路

```go
// [internal/dnsforward/clientid.go]
func clientIDFromDNSContextHTTPS(pctx *proxy.DNSContext) (clientID string, err error) {
    r := pctx.HTTPRequest
    clientID = clientIDFromPath(r.URL.Path, s.conf.TLSConf.ForceHTTPSSvcDomain)
    if clientID != "" {
        return clientID, nil
    }
    // 退回到 SNI 提取（如果没有 ECH 还能成功）
    return "", nil
}
```

**退路策略**：
1. **DoH 用户**：使用 URL Path 前缀/后缀承载 ClientID，完全避开 SNI，ECH 不影响
2. **DoT/DoQ 用户**：
   - ECH 未启用：SNI 正常提取
   - ECH 已启用：Outer SNI 仅含公共域名，`clientIDFromClientServerName` 返回空串，客户端回退到 **按 IP/MAC 识别**（走 `ApplyClientFiltering` 的 IP → DHCP MAC 路径）

### 18.4 ECH 启用后的完整识别链路

```
DoT/DoQ 请求到达
  ├─ clientServerName() 获取 SNI
  │   ├─ 无 ECH → 真实 SNI（含 ClientID 子域名）→ 提取成功
  │   └─ 有 ECH → Outer SNI（仅 dns.example.com）→ 提取失败，clientID = ""
  └─ ApplyClientFiltering("", remoteIP, setts)
      ├─ findByClientID("") → 失败
      ├─ findByIP(remoteIP) → 若该 IP 被 PersistentClient 配置则命中
      └─ DHCP MACByIP(remoteIP) → 若 DHCP 查到 MAC 且 MAC 被 PersistentClient 配置则命中
```

**结论**：ECH 只影响 DoT/DoQ 的 SNI 子域名识别，对 DoH（URL Path）和 IP/MAC 匹配无影响。启用 ECH 后 DoT/DoQ 用户应确保 PersistentClient 配置了 IP 或 MAC 而不是只靠 ClientID。

---

## 19. CleanupClients TTL 配置项

### 19.1 不存在 "CleanupClients TTL" 这一显式配置项

AdGuardHome 对 RuntimeClient **没有 TTL 过期机制**，不因为"超过 N 秒未活跃"自动删除。清理完全由**来源数据的变化事件**驱动。

### 19.2 唯一的时间相关配置：`ARPClientsUpdatePeriod`

```go
// [internal/client/storage.go:117-119]
type StorageConfig struct {
    // ARPClientsUpdatePeriod defines how often [SourceARP] runtime client
    // information is updated.
    ARPClientsUpdatePeriod time.Duration
}

// [internal/home/clients.go]
const arpClientsUpdatePeriod = 10 * time.Minute  // 硬编码默认值
```

这个参数仅控制 ARP 表的刷新频率，不直接控制 TTL。ARP 刷新流程中隐含了清理：
```go
// [internal/client/storage.go:periodicARPUpdate → ReloadARP]
func (s *Storage) ReloadARP(ctx context.Context) {
    s.runtimeIndex.clearSource(SourceARP)   // 清除所有 IP 的 ARP 来源字段
    // ... 填充当前 ARP 表中存在的设备 ...
    removed := s.runtimeIndex.removeEmpty() // 仅剩下空壳的 RuntimeClient 被删除
}
```

→ 一个仅靠 ARP 被识别到的设备，在离线后最长 **10 分钟** 才会被清理（下一次 ARP 刷新周期）。

### 19.3 各来源的隐式"TTL"

| 来源 | 触发清理的事件 | 等效 TTL | 代码位置 |
|-----|-------------|---------|---------|
| **SourceHostsFile** | `/etc/hosts` 文件被修改（通过 fsnotify watcher） | 文件系统事件驱动，无时间上限 | `storage.handleHostsUpdates()` |
| **SourceDHCP** | DHCP 租约刷新（调用 `UpdateDHCP()`） | DHCP 租约更新周期，通常 12h~24h | `storage.UpdateDHCP()` |
| **SourceARP** | ARP 表定时刷新 | 默认 10 分钟（`arpClientsUpdatePeriod`） | `storage.periodicARPUpdate()` |
| **SourceRDNS** | rDNS 异步请求返回 | 无周期性刷新，仅在请求时首次填充 | `storage.UpdateAddress()` |
| **SourceWHOIS** | WHOIS 异步请求返回 | 无周期性刷新，仅在请求时首次填充 | `storage.setWHOISInfo()` |
| **PersistentClient** | 永不自动清理，仅 API 显式删除 | 永久 | `Storage.Add/Update/RemoveByName()` |

### 19.4 为什么没有 RuntimeClient TTL

AdGuardHome 的设计哲学：
1. **RuntimeClient 是来源数据的投影**，不是独立对象；来源存在则客户端存在，来源消失则客户端消失
2. 避免引入「活跃检测」带来的额外开销（需要维护最后访问时间 + 定时扫描）
3. `removeEmpty()` 提供了惰性清理的锚点——只要至少一个来源仍能提供该 IP 的信息，就保留

如需主动清理，唯一方式是重启进程（PersistentClient 从配置恢复，RuntimeClient 从零开始重新填充）。

---

## 20. LastSeen 时间戳精度与漂移

### 20.1 时间戳精度：`time.RFC3339Nano`

Query Log 中的每条日志使用 `time.Time` 类型存储，JSON 序列化格式为 **纳秒精度**：

```go
// [internal/querylog/entry.go:16-20]
type logEntry struct {
    Time time.Time `json:"T"`
    // ...
}
```

序列化到磁盘时使用 `time.RFC3339Nano`：
```go
// [internal/querylog/querylogfile.go:139-140]
val := readJSONValue(string(buf[:r]), `"T":"`)
t, err := time.Parse(time.RFC3339Nano, val)
```

典型输出：
```json
{"T":"2025-07-01T12:34:56.123456789+08:00","QH":"example.com",...}
```

### 20.2 时间戳生成点：`queryLog.Add()` 入口

```go
// [internal/querylog/querylog.go:xxx]
func (l *queryLog) Add(p *AddParams) {
    // ...
    entry := &logEntry{
        Time: time.Now(),  // ← 时间戳生成点
        // ...
    }
    // ...
}
```

`processInitial()` 在请求处理开始时调用 `queryLog.Add()`：
```
DNS 请求到达
  ├─ processInitial()
  │   ├─ queryLog.Add(&AddParams{...})  // ← 时间戳 = 收到请求时间
  │   └─ ... 后续过滤处理
  └─ filterDNSResponse()
      └─ queryLog.Update()  // 更新同一日志条目（不改时间戳）
```

### 20.3 漂移来源与量级

| 漂移来源 | 量级 | 说明 |
|---------|------|------|
| **Go runtime 调度延迟** | 1-10 µs | `time.Now()` 系统调用后 goroutine 可能被抢占 |
| **多 goroutine 执行顺序** | 1-100 µs | 并发请求的 `time.Now()` 与实际处理顺序可能不一致 |
| **CPU 时钟漂移** | 1-100 ns | 跨 CPU 核调度时 TSC 时钟不一致 |
| **日志缓冲 flush 延迟** | 1-100 ms | `bufferLock` 保护的 ring buffer，先入内存再批量写盘 |
| **NTP 校时跳变** | 可变 | 系统时间被 NTP 调整可能导致时间戳回拨 |

### 20.4 测试代码中的精度保护

在搜索测试中特意增加了 10 秒缓冲，应对 Windows 低精度计时器：
```go
// [internal/querylog/search_internal_test.go:82-87]
// Add some time to the "current" one to protect against
// low-resolution timers on some Windows machines.
olderThan: time.Now().Add(10 * time.Second),
```

### 20.5 不存在 "LastSeen" 字段

注意：AdGuardHome 的 RuntimeClient/PersistentClient 结构体中 **没有名为 `LastSeen` 的字段**。客户端"上次在线"时间仅隐含在 Query Log 的时间戳中，需要通过查询日志聚合得到，不是独立维护的元数据。

---

## 21. MergeTags 超阈值的运维告警

### 21.1 结论：代码中不存在此机制

经过全代码库搜索，**AdGuardHome 没有实现 Tags 超阈值的运维告警功能**。具体情况：

| 需求 | 代码现状 |
|-----|---------|
| `maxTags` 硬编码常量 | ❌ 不存在 |
| Tags 数量超限检查 | ❌ 不存在（仅校验 Tag 是否在白名单内） |
| 超限告警（日志/metrics/webhook） | ❌ 不存在 |

### 21.2 实际的 Tags 校验逻辑

`Persistent.validate()` 中只做白名单校验，**不检查数量**：
```go
// [internal/client/persistent.go:158-166]
for _, t := range c.Tags {
    _, ok := slices.BinarySearch(allTags, t)  // 二分查找白名单
    if !ok {
        return fmt.Errorf("invalid tag: %q", t)
    }
}
```

**实际上限 = `allowedTags` 长度 = 25 个**，但这是白名单机制的副产品，不是显式的数量限制。

### 21.3 为什么没有实现

1. **白名单即上限**：25 个内置 Tag 已经覆盖全部可能，数量本身不会超过
2. **API 层面限制**：前端 UI 从 `GET /control/clients/allowed_tags` 获取白名单，多选框最多选 25 个
3. **运维告警的设计取舍**：AdGuardHome 定位是家用/小型办公，没有 Prometheus metrics exporter（企业版 AdGuard DNS 才有）

### 21.4 替代方案：自行监控

如需告警，可通过外部脚本：
```bash
# 检查 YAML 中 tags 数量
yq eval '.clients[].tags | length' AdGuardHome.yaml | awk '$1 > 20 {print "WARNING: client has", $1, "tags"}'
```

---

## 22. atomicConfig 两阶段提交失败回滚路径

### 22.1 配置更新的实际流程：先改内存，后写盘

以 `POST /control/dns_config` 为例：

```go
// [internal/dnsforward/http.go:539-584]
func (s *Server) handleSetConfig(w http.ResponseWriter, r *http.Request) {
    // 阶段 1：解析并校验请求
    req := &jsonDNSConfig{}
    json.NewDecoder(r.Body).Decode(req)
    req.validate(...)  // ✅ 所有校验在这里，失败直接返回，无副作用

    // 阶段 2：修改内存状态（无事务保护）
    restart := s.setConfig(req)  // ❗ 直接修改 s.conf 和 s.dnsFilter

    // 阶段 3：持久化到磁盘
    s.conf.ConfModifier.Apply(ctx)  // ❗ 写 YAML 到磁盘

    // 阶段 4：如需重启服务
    if restart {
        s.Reconfigure(ctx, nil)  // ❗ 可能失败，此时内存和磁盘已不一致
    }
}
```

### 22.2 失败场景与回滚能力分析

| 失败点 | 内存状态 | 磁盘状态 | 一致性 | 是否自动回滚 |
|-------|---------|---------|--------|-------------|
| `req.validate()` 失败 | ❌ 未修改 | ❌ 未修改 | ✅ 一致 | ✅ 自然回滚 |
| `setConfig()` 内部失败 | ⚠️ 可能部分修改 | ❌ 未修改 | ❌ 不一致 | ❌ 不回滚 |
| `ConfModifier.Apply()` 写盘失败 | ✅ 已修改 | ❌ 未修改 | ❌ 不一致 | ❌ 不回滚 |
| `Reconfigure()` 重启失败 | ✅ 已修改 | ✅ 已修改 | ✅ 一致 | ❌ 不回滚（服务未重启但配置已变） |

### 22.3 关键：内存修改是"一锤子买卖"

`setConfig()` 内部逐个字段修改，没有原子性：
```go
// [internal/dnsforward/http.go:588-660]
func (s *Server) setConfig(dc *jsonDNSConfig) (shouldRestart bool) {
    s.serverLock.Lock()
    defer s.serverLock.Unlock()

    if dc.BlockingMode != nil {
        s.dnsFilter.SetBlockingMode(...)  // 修改 1
    }
    if dc.BlockedResponseTTL != nil {
        s.dnsFilter.SetBlockedResponseTTL(...)  // 修改 2
    }
    if dc.ProtectionEnabled != nil {
        s.dnsFilter.SetProtectionStatus(...)  // 修改 3
    }
    // ... 约 15 个独立的 if 分支，逐个修改
    // 任何一步 panic/error 都会导致部分修改、部分未修改
}
```

**没有事务边界**：没有 "begin transaction → 全部成功 commit / 失败 rollback" 的逻辑。

### 22.4 bbolt 数据库操作有回滚，YAML 写盘没有

唯一实现了两阶段提交的是 bbolt 数据库操作（如会话存储、统计数据）：
```go
// [internal/aghuser/sessionstorage.go:150-181]
tx, err := ds.db.Begin(true)  // 阶段 1：开启事务
needRollback := true
defer func() {
    if needRollback {
        tx.Rollback()  // 失败自动回滚
    }
}()

// ... 执行数据库操作 ...

needRollback = false
err = tx.Commit()  // 阶段 2：提交
```

但 `AdGuardHome.yaml` 的写盘是简单的 `os.WriteFile`，**没有事务**，失败就是失败，内存状态不会回退。

### 22.5 恢复手段：人工介入

配置更新失败后的恢复策略：
1. 重新发起相同请求（若问题是临时的）
2. 手动编辑 `AdGuardHome.yaml` 恢复
3. 从备份恢复
4. 重启进程（会重新从 YAML 加载，丢弃内存中不一致的状态）

---

## 23. InvalidateChildren 递归深度上限防栈溢出

### 23.1 结论：代码中完全不存在此概念

经过全代码库搜索 `InvalidateChildren`、`invalidate.*child`、`recursive.*invalidate`、`recursion.*depth` 等关键词，**AdGuardHome 中没有这个函数或概念**。

这个概念属于 **AdGuard DNS（云端 SaaS 服务）** 的缓存失效机制，不是 AdGuardHome（本地开源版本）的功能。

### 23.2 AdGuardHome 的缓存失效机制对比

| 特性 | AdGuardHome（本地） | AdGuard DNS（云端） |
|-----|-------------------|-------------------|
| InvalidateChildren | ❌ 不存在 | ✅ 存在，递归失效子域名缓存 |
| 递归深度上限 | ❌ 无此概念 | ✅ 有，防止栈溢出 |
| 缓存架构 | 本地内存 + LRU | 分布式多级缓存 |
| 失效粒度 | 全量清空 / TTL 被动失效 | 精确单条失效 + 递归子域名 |

### 23.3 AdGuardHome 中唯一的"递归"：域名匹配

AdGuardHome 中有递归域名匹配，但不存在"缓存失效递归"：
- `filtering.CheckHost()` 会对 `www.example.com` 依次尝试匹配 `www.example.com` → `example.com` → `com`（逐级去掉前缀）
- 这是匹配逻辑，不是缓存失效逻辑

### 23.4 为什么 AdGuardHome 不需要

AdGuardHome 作为本地递归解析器：
1. **缓存规模小**：单实例最多百万级条目，全量清空成本低（`/control/cache_clear` 是 O(1) map 重建）
2. **请求量低**：家用场景 QPS < 100，不需要精确失效
3. **TTL 驱动**：依赖上游 DNS 的 TTL，不需要主动递归失效

---

## 24. servicesMap.Reload 期间响应请求的过渡

### 24.1 结论：代码中不存在 `servicesMap.Reload`

搜索 `servicesMap`、`ServicesMap`、`services_map.Reload` 等关键词，**AdGuardHome 中没有这个结构体或方法**。

### 24.2 Blocked Services 的实际更新机制

Blocked Services 由两部分组成，各自的更新策略不同：

| 组件 | 更新方式 | 原子性 | 过渡期间行为 |
|-----|---------|-------|-------------|
| **`serviceRules` map**（底层规则库） | 启动时 `initBlockedServices()` 一次性编译，运行时只读 | ✅ 运行时不可变 | 无过渡问题，永远一致 |
| **`BlockedServices` 对象**（用户选中的 ID 列表 + Schedule） | `SetBlockedServices()` 运行时更新 | ✅ mutex 保护 | 更新期间阻塞读，无中间状态 |

### 24.3 `SetBlockedServices()` 的原子更新

```go
// [internal/filtering/filtering.go]
func (d *DNSFilter) SetBlockedServices(schedule *filtering.Schedule, ids []string) {
    d.confMu.Lock()  // ✅ 写锁
    defer d.confMu.Unlock()

    // 先销毁旧对象
    if d.BlockedServices != nil {
        d.BlockedServices.Close()
    }
    // 再创建新对象
    d.BlockedServices = blocked.New(schedule, ids, d.EngineVersion)
    d.Config.BlockedServicesSchedule = schedule
    d.Config.BlockedServicesIDs = ids
}
```

读取时也加锁：
```go
// [internal/filtering/filtering.go: matchBlockedServicesRules]
d.confMu.RLock()  // ✅ 读锁
bs := d.BlockedServices
d.confMu.RUnlock()
if bs != nil {
    // 使用 bs 检查
}
```

**过渡保证**：读写都加锁，不会出现"读到一半构造中的对象"的问题。如果更新过程中有请求到达，会阻塞在 `RLock()` 上，等待更新完成后继续。

### 24.4 为什么没有 `servicesMap.Reload`

1. **规则库不可变**：`serviceRules` 是构建时注入的，运行时不改变，不需要 Reload
2. **用户配置轻量**：用户选中的 ID 列表只是一串字符串，替换成本极低，不需要复杂的 reload 过渡
3. **锁粒度足够**：`confMu` 是细粒度锁，只保护 BlockedServices 等配置字段，不影响 DNS 请求处理主路径

---

## 25. ECH-aware fallback 真实部署占比监测

### 25.1 结论：代码中完全不存在此监测机制

搜索 `metrics`、`prometheus`、`counter`、`ech.*fallback`、`fallback.*ech` 等关键词，**AdGuardHome 没有实现任何 metrics 统计或 ECH fallback 占比监测**。

### 25.2 ECH 识别链路的"沉默失败"

```go
// [internal/dnsforward/middleware.go: clientIDFromDNSContext]
func (s *Server) clientIDFromDNSContext(
    ctx context.Context, l *slog.Logger, pctx *proxy.DNSContext,
) (clientID string, err error) {
    // ...
    clientID, err = clientIDFromClientServerName(
        hostSrvName,
        cliSrvName,      // ← ECH 启用后这里是 Outer SNI，不含 ClientID
        s.conf.TLSConf.StrictSNICheck,
    )
    if err != nil {
        return "", fmt.Errorf("clientid check: %w", err)
    }
    return clientID, nil  // ← ECH 场景下返回空串，不计数、不日志
}
```

**静默降级**：ECH 导致 SNI 提取失败时，`clientID` 为空，然后走 IP/MAC 识别链路。整个过程：
- ❌ 没有 Prometheus Counter 递增
- ❌ 没有 Debug 日志
- ❌ 没有区分"ECH 导致的失败"和"普通提取失败"

### 25.3 为什么没有监测

1. **产品定位**：AdGuardHome 是家用/小型办公场景，不需要精细化 metrics
2. **ECH 渗透率低**：截至 2025 年浏览器 ECH 启用率 < 5%，且仅在特定域名下触发
3. **Go 生态依赖**：Prometheus exporter 需要额外依赖，AdGuardHome 尽量减少第三方依赖

### 25.4 自行监测方案

如需监测 ECH fallback 占比，可通过日志侧分析：
```bash
# 统计 DoT/DoQ 请求中 ClientID 为空的比例
grep '"CP":"dot"\|"CP":"doq"' querylog.json | \
  jq -s '[.[] | select(.CID == "")] | length / length'
```

---

## 26. clients_persistent_ttl 默认值合理性论证

### 26.1 结论：代码中完全不存在此配置项

搜索 `clients_persistent_ttl`、`persistent.*ttl`、`client.*ttl.*config` 等关键词，**AdGuardHome 中没有这个配置项，也没有 PersistentClient TTL 机制**。

### 26.2 设计哲学：Persistent ≠ Runtime

AdGuardHome 对两种客户端的定位有本质区别：

| 维度 | PersistentClient | RuntimeClient |
|-----|-----------------|---------------|
| **定义** | 用户在 Web UI 中显式添加的客户端 | 从 ARP/DHCP/hosts 等来源自动发现的客户端 |
| **生命周期** | 永久，直到用户主动删除 | 临时，随来源数据消失而消失 |
| **配置存储** | 写入 `AdGuardHome.yaml` | 仅内存，重启丢失 |
| **TTL 机制** | ❌ 不需要，设计上就是永久 | ❌ 不需要，由来源事件驱动 |
| **清理方式** | API `DELETE /control/clients/delete` | `removeEmpty()` 来源驱动 |

### 26.3 为什么 PersistentClient 不需要 TTL

1. **语义冲突**："持久化"（Persistent）这个词本身就意味着"不自动消失"
2. **用户预期**：用户手动添加的客户端，期望它永久存在，而不是"7 天不活跃就被删了"
3. **数据量小**：家用场景 PersistentClient 数量 < 100，存储成本可忽略
4. **安全风险**：自动删除可能导致家长控制策略意外失效（例如孩子的设备假期不联网，回来后策略消失）

### 26.4 相关的 TTL 配置（但不是 PersistentClient TTL）

AdGuardHome 中有这些 TTL 配置，但都不是 `clients_persistent_ttl`：

| 配置项 | 作用 | 默认值 |
|-------|------|--------|
| `dns.cache_size` | DNS 响应缓存大小 | 4 MB |
| `dns.cache_ttl_min` / `cache_ttl_max` | DNS 响应 TTL 上下限 | 不设置 / 不设置 |
| `dns.blocked_response_ttl` | 被阻塞响应的 TTL | 10 秒 |
| `stats.interval` | 统计数据保留时长 | 24 小时 |
| `querylog.interval` | 查询日志保留时长 | 90 天 |
| `clients.arp_clients_update_period` | ARP 表刷新周期（控制 RuntimeClient 清理） | 10 分钟 |

### 26.5 需求替代方案

如果确实需要"PersistentClient 自动过期"（例如访客网络），可以：
1. 外部脚本定期检查 Query Log，删除 N 天不活跃的 PersistentClient
2. 使用 RuntimeClient 机制（不手动添加 PersistentClient，靠 ARP/DHCP 自动发现）
3. 给 PersistentClient 配置调度（Schedule），按时间段生效/失效

---

## 27. 关键配置参数

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
| `ARPClientsUpdatePeriod` | time.Duration | ARP 表刷新周期（控制 RuntimeClient 清理频率） | [storage.go:119](internal/client/storage.go#L119) |
| `SafeSearchCacheTTL` | time.Duration | 安全搜索缓存 TTL | [clientshttp.go:225](internal/home/clientshttp.go#L225) |
| `SafeSearchCacheSize` | int | 安全搜索缓存大小 | [clientshttp.go:224](internal/home/clientshttp.go#L224) |

## 28. 调试与排错要点

1. **客户端识别问题**：
   - 检查 `Source` 优先级，确认客户端信息来源是否正确
   - 查看 `FindParams` 的查找顺序，确认标识是否匹配
   - 注意 IP 地址的 zone 索引可能导致匹配失败
   - **DoH/DoT ClientID 不匹配**：检查 URL Path 格式或 SNI 子域名，是否符合提取规则
   - **Persistent vs Runtime 混淆**：过滤决策只看 PersistentClient，RuntimeClient 仅用于展示
   - **MAC 与 IP 匹配不同客户端歧义**：`clashes()` 方法会阻止标识符被多个客户端共享，若仍出现 IP 匹配 A 但 DHCP→MAC 匹配 B，则走 `findByIP` 先 IP 命中即返回，不会走 MAC 路径
   - **ECH 导致 DoT/DoQ ClientID 丢失**：启用 ECH 后 Outer SNI 不含 ClientID 子域名，需改用 DoH URL Path 或给 PersistentClient 配置 IP/MAC 作为退路
   - **LastSeen 时间戳精度**：Query Log 精度为 RFC3339Nano（纳秒），但客户端无独立 `LastSeen` 字段，需从日志聚合
   - **时间戳漂移**：goroutine 调度、CPU TSC 漂移、NTP 校时可能导致日志时间顺序与实际处理顺序不一致

2. **规则不生效问题**：
   - 检查 `ProtectionEnabled` 和 `FilteringEnabled` 开关
   - 确认 `hostCheckers` 执行顺序，前面的检查可能短路后续检查
   - 白名单规则优先级高于黑名单，检查是否被误放行
   - 客户端 `UseOwnSettings` 开关会覆盖全局设置
   - **Tag 不匹配**：确认 Tag 是否在 `allowedTags` 白名单内（共 25 个内置 Tag）
   - **多 Tag 语法**：`|` 是 OR 逻辑，`&` 是 AND 逻辑，注意不要搞混
   - **$important 修饰符**：会跳过白名单覆盖，检查是否误加
   - **Tag 数量上限**：实际上限 25 个（等于 allowedTags 长度），但代码无硬编码 `maxTags` 限制
   - **MergeTags 超阈值告警**：代码中不存在此机制，需通过外部脚本自行监控 YAML 中的 tags 数量

3. **缓存相关问题**：
   - 修改规则后注意缓存 TTL，可临时减小 `CacheTime` 测试
   - 异步更新规则时，需等待新引擎初始化完成
   - 安全浏览/家长控制缓存基于 hash prefix，清除需等待过期
   - **过滤规则变更不立即生效**：DNS proxy cache 不会主动失效，需手动调用 `/control/cache_clear`
   - **客户端 upstream 缓存懒重建**：`updateCustomUpstreamConfig` 只打 `isChanged=true` 脏标记，真正清空旧缓存在下一次请求 `customUpstreamConfig()` 时发生
   - **缓存级联失效**：`/control/cache_clear` 会清空 dnsProxy.Cache + 所有客户端 upstream cache，但 SafeSearch/SafeBrowsing 缓存不清
   - **SafeSearch 配置变更**：会自动 `ss.cache.Clear()`，无需手动
   - **InvalidateChildren**：AdGuardHome 中不存在此机制（仅 AdGuard DNS 云端有），本地只能全量清空或等待 TTL

4. **阻塞服务问题**：
   - 检查 `Schedule.Contains(time.Now())`，调度时间内不阻塞
   - 客户端 `UseOwnBlockedServices` 会替换全局阻塞服务列表
   - `ServicesRules` 字段是生效的规则列表
   - **services.json 构建时注入**：运行时不会动态下载，规则随二进制版本更新；"热更新"只指用户的 ID 选择列表变更，不是规则库本身
   - **ApplyBlockedServicesList 执行顺序**：先全局→再客户端覆盖→最后按 Schedule 决定是否加载
   - **serviceRules 重建方式**：`initBlockedServices()` 只在启动时执行一次，无运行时 API 可以重新编译，必须重启进程
   - **servicesMap.Reload**：代码中不存在此函数，`SetBlockedServices()` 用 `confMu` 读写锁保证原子更新

5. **ConfigReload 期间问题**：
   - **100ms 端口切换窗口**：新连接可能短暂失败，TCP/UDP 会自动重试
   - **Reconfigure 全局锁**：`serverLock.Lock()` 期间所有新请求排队等待
   - **TLS 证书热加载**：仅重启 HTTPS/TLS listener，不影响 DNS 明文请求
   - **多层锁事务边界**：`config.RWMutex → clients.lock → Storage.mu → dnsforward.serverLock`，注意加锁顺序避免死锁
   - **atomicConfig 事务**：配置读取需用 `config.RLock()` 保证多个字段的原子一致性视图
   - **配置更新失败回滚**：`setConfig()` 先改内存后写盘，失败时内存状态已变更，无自动回滚；`AdGuardHome.yaml` 写操作无事务，bbolt 数据操作有 Rollback
   - **部分修改风险**：`setConfig()` 有 15 个独立 if 分支，任一步失败导致配置不一致，需重新设置或重启进程

6. **CleanupClients 清理时机问题**：
   - RuntimeClient 不会因「不活跃」被清理，仅在来源数据消失时清理
   - ARP 更新周期默认 10 分钟，离线设备最长需 10 分钟才被清掉
   - 某 IP 仅出现在 ARP 中：下一次 `periodicARPUpdate` 时会被先 `clearSource(ARP)` 再 `removeEmpty()` 删除
   - **不存在 RuntimeClient TTL 配置项**：不要浪费时间找 `client_ttl` 之类的参数，设计上就没有活跃超时机制
   - **来源驱动的隐式 TTL**：hosts 文件（fsnotify 事件）、DHCP（租约刷新）、ARP（10 分钟定时）、rDNS/WHOIS（仅首次请求填充，不刷新）
   - **clients_persistent_ttl**：代码中完全不存在此配置项，PersistentClient 设计上就是永久有效，如需自动过期可通过外部脚本实现

7. **监测与告警问题**：
   - **ECH fallback 占比监测**：代码中无 metrics，需通过日志侧分析（grep '"CP":"dot"\|"CP":"doq"' + jq 统计 CID 为空的比例）
   - **配置更新失败告警**：监听 `/control/dns_config` API 返回 500 错误，或监控 `AdGuardHome.yaml` 的修改时间与内存状态一致性
   - **时间戳异常检测**：监控 Query Log 中时间戳回拨、超前等异常情况

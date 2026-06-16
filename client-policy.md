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

## 6. 关键配置参数

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

## 7. 调试与排错要点

1. **客户端识别问题**：
   - 检查 `Source` 优先级，确认客户端信息来源是否正确
   - 查看 `FindParams` 的查找顺序，确认标识是否匹配
   - 注意 IP 地址的 zone 索引可能导致匹配失败

2. **规则不生效问题**：
   - 检查 `ProtectionEnabled` 和 `FilteringEnabled` 开关
   - 确认 `hostCheckers` 执行顺序，前面的检查可能短路后续检查
   - 白名单规则优先级高于黑名单，检查是否被误放行
   - 客户端 `UseOwnSettings` 开关会覆盖全局设置

3. **缓存相关问题**：
   - 修改规则后注意缓存 TTL，可临时减小 `CacheTime` 测试
   - 异步更新规则时，需等待新引擎初始化完成
   - 安全浏览/家长控制缓存基于 hash prefix，清除需等待过期

4. **阻塞服务问题**：
   - 检查 `Schedule.Contains(time.Now())`，调度时间内不阻塞
   - 客户端 `UseOwnBlockedServices` 会替换全局阻塞服务列表
   - `ServicesRules` 字段是生效的规则列表

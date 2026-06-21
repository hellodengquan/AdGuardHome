# AdGuard Home DNS 过滤流水线分析

## 概述

AdGuard Home 的 DNS 过滤系统是一个三层流水线：**规则编译** → **客户端识别** → **策略叠加**。这三个阶段在每次 DNS 查询时按特定顺序串联起来，形成完整的过滤决策链。

```
DNS 查询请求
    ↓
[中间件层] 客户端ID提取 + 访问控制检查
    ↓
[客户端识别] 查找持久化客户端配置
    ↓
[策略叠加] 全局配置 → 客户端配置 → 生成 Settings 对象
    ↓
[规则匹配] 按优先级检查: Rewrites → Hosts → 过滤规则 → 封禁服务 → 安全浏览 → 家长控制 → 安全搜索
    ↓
过滤决策 (拦截/放行/重写)
    ↓
[上游转发] 未拦截请求转发至上游 DNS
    ↓
[响应过滤] 检查响应中的 CNAME/A/AAAA/HTTPS 记录
    ↓
最终响应
```

---

## 一、规则编译 (Rule Compilation)

### 1.1 规则源分类

AdGuard Home 从三类来源收集过滤规则：

| 类型 | 配置字段 | 存储位置 | 说明 |
|------|---------|---------|------|
| 订阅黑名单 | `conf.Filters` | `data/filters/{id}.txt` | 远程下载的广告/跟踪器黑名单 |
| 订阅白名单 | `conf.WhitelistFilters` | `data/filters/{id}.txt` | 远程下载的白名单 |
| 用户自定义规则 | `conf.UserRules` | 内存 + 配置文件 | 用户手动添加的规则 |

### 1.2 编译流程

**核心代码位置**：`internal/filtering/filter.go:662-708`

```go
func (d *DNSFilter) enableFiltersLocked(ctx context.Context, async bool) {
    // 1. 自定义规则始终放在第一位 (ID = rulelist.IDCustom)
    filters := make([]Filter, 1, len(d.conf.Filters)+len(d.conf.WhitelistFilters)+1)
    filters[0] = Filter{
        ID:   rulelist.IDCustom,
        Data: []byte(strings.Join(d.conf.UserRules, "\n")),
    }

    // 2. 添加所有启用的黑名单订阅
    for _, filter := range d.conf.Filters {
        if filter.Enabled {
            filters = append(filters, Filter{
                ID:       filter.ID,
                FilePath: filter.Path(d.conf.DataDir),
            })
        }
    }

    // 3. 单独收集白名单
    var allowFilters []Filter
    for _, filter := range d.conf.WhitelistFilters {
        if filter.Enabled {
            allowFilters = append(allowFilters, Filter{...})
        }
    }

    // 4. 编译为 DNSEngine
    d.setFilters(ctx, filters, allowFilters, async)
}
```

### 1.3 编译引擎初始化

**核心代码位置**：`internal/filtering/filtering.go:746-777`

```go
func (d *DNSFilter) initFiltering(ctx context.Context, allowFilters, blockFilters []Filter) error {
    // 黑名单引擎
    rulesStorage, _ := newRuleStorage(blockFilters)
    filteringEngine := urlfilter.NewDNSEngine(rulesStorage)

    // 白名单引擎 (独立)
    rulesStorageAllow, _ := newRuleStorage(allowFilters)
    filteringEngineAllow := urlfilter.NewDNSEngine(rulesStorageAllow)

    // 原子替换引擎 (无锁读取)
    d.engineLock.Lock()
    d.rulesStorage = rulesStorage
    d.filteringEngine = filteringEngine
    d.rulesStorageAllow = rulesStorageAllow
    d.filteringEngineAllow = filteringEngineAllow
    d.engineLock.Unlock()
}
```

**关键设计**：
- 使用 **双引擎架构**：黑名单和白名单分别编译到独立的 `DNSEngine`
- **原子替换**：编译完成后一次性替换指针，查询期间无锁
- **白名单优先**：查询时先检查白名单，命中直接放行

### 1.4 规则更新机制

`internal/filtering/rulelist/engine.go:102-154` 中 `Engine.Refresh()` 负责：
1. 下载最新规则文件
2. 校验 checksum，检测变化
3. 重新编译 `RuleStorage` 和 `DNSEngine`
4. 原子替换旧引擎

---

## 二、客户端识别 (Client Identification)

### 2.1 客户端类型

| 类型 | 存储位置 | 生命周期 | 识别方式 |
|------|---------|---------|---------|
| 持久化客户端 (Persistent) | `client/index.uidToClient` | 配置文件持久化 | IP/子网/MAC/ClientID |
| 运行时客户端 (Runtime) | `client/runtimeIndex` | 内存临时 | ARP/DHCP/hosts/rDNS/WHOIS |

### 2.2 客户端ID提取

**核心代码位置**：`internal/dnsforward/middleware.go:28-55`

```go
func (s *Server) Wrap(h proxy.Handler) proxy.Handler {
    return proxy.HandlerFunc(func(ctx context.Context, p *proxy.Proxy, pctx *proxy.DNSContext) error {
        // 1. 从 DoH/DoT/DoQ 提取 ClientID
        clientID, err := s.clientIDFromDNSContext(ctx, l, pctx)

        // 2. 检查客户端是否在访问黑名单
        blocked, _ := s.IsBlockedClient(pctx.Addr.Addr(), clientID)
        if blocked {
            return s.serveBlockedResponse(pctx)
        }

        // 3. ClientID 注入 context 供后续使用
        if clientID != "" {
            ctx = contextWithClientID(ctx, clientID)
        }

        return h.ServeDNS(ctx, p, pctx)
    })
}
```

### 2.3 客户端索引结构

**核心代码位置**：`internal/client/index.go:33-51`

```go
type index struct {
    subnetToUID   *aghalg.SortedMap[netip.Prefix, UID]  // 子网 → UID
    nameToUID     map[string]UID                       // 名称 → UID
    clientIDToUID map[ClientID]UID                     // ClientID → UID
    ipToUID       map[netip.Addr]UID                   // IP → UID
    macToUID      map[macKey]UID                       // MAC → UID
    uidToClient   map[UID]*Persistent                  // UID → 客户端对象
}
```

### 2.4 客户端查找优先级

**核心代码位置**：`internal/client/storage.go:529-560` + `770-781`

```go
func (s *Storage) Find(params *FindParams) (p *Persistent, ok bool) {
    // 查找顺序: ClientID → IP → 子网 → MAC
    for {
        switch {
        case isClientID:
            p, ok = s.index.findByClientID(params.ClientID)
        case isRemoteIP:
            // IP 查找失败时，尝试通过 DHCP 用 MAC 查找
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

// findByIP 的 fallback 逻辑
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    p, ok = s.index.findByIP(addr)
    if ok {
        return p, true
    }

    // 通过 DHCP 将 IP 映射为 MAC 再查找
    foundMAC := s.dhcp.MACByIP(addr)
    if foundMAC != nil {
        return s.index.findByMAC(foundMAC)
    }

    return nil, false
}
```

**查找优先级链**：
```
ClientID (DoH/DoT/DoQ)
    ↓ 未找到
IP 地址
    ↓ 未找到
DHCP MAC 地址映射
    ↓ 未找到
子网匹配 (CIDR)
    ↓ 未找到
MAC 地址
    ↓ 未找到
返回 nil (使用全局策略)
```

---

## 三、策略叠加 (Policy Overlay)

### 3.1 Settings 对象结构

**核心代码位置**：`internal/filtering/filtering.go:45-67`

```go
type Settings struct {
    ClientName string
    ClientIP   netip.Addr
    ClientTags []string

    ServicesRules []ServiceEntry      // 封禁服务规则
    BlockedServices *BlockedServices  // 客户端封禁服务配置

    ProtectionEnabled   bool
    FilteringEnabled    bool
    SafeSearchEnabled   bool
    SafeBrowsingEnabled bool
    ParentalEnabled     bool

    ClientSafeSearch SafeSearch
}
```

### 3.2 全局默认值生成

**核心代码位置**：`internal/filtering/filtering.go:324-334`

策略叠加的起点是从全局配置生成基础 Settings 对象：

```go
func (d *DNSFilter) Settings() (s *Settings) {
    d.confMu.RLock()
    defer d.confMu.RUnlock()

    return &Settings{
        FilteringEnabled:    atomic.LoadUint32(&d.conf.enabled) != 0,
        SafeSearchEnabled:   d.conf.SafeSearchConf.Enabled,
        SafeBrowsingEnabled: d.conf.SafeBrowsingEnabled,
        ParentalEnabled:     d.conf.ParentalEnabled,
    }
}
```

### 3.3 策略叠加流程

**核心代码位置**：`internal/dnsforward/filter.go:18-24` + `internal/filtering/filter.go:710-725`

```go
func (s *Server) clientRequestFilteringSettings(dctx *dnsContext) *filtering.Settings {
    // 1. 基础: 从全局配置复制
    setts := s.dnsFilter.Settings()
    setts.ProtectionEnabled = dctx.protectionEnabled

    // 2. 叠加: 应用客户端特定配置
    s.dnsFilter.ApplyAdditionalFiltering(dctx.proxyCtx.Addr.Addr(), dctx.clientID, setts)

    return setts
}

func (d *DNSFilter) ApplyAdditionalFiltering(cliAddr netip.Addr, clientID string, setts *Settings) {
    setts.ClientIP = cliAddr

    // 2.1 应用全局封禁服务
    d.ApplyBlockedServices(setts)

    // 2.2 查找并应用客户端策略
    d.applyClientFiltering(clientID, cliAddr, setts)

    // 2.3 若客户端有独立封禁服务配置，覆盖全局
    if setts.BlockedServices != nil {
        setts.ServicesRules = nil
        svcs := setts.BlockedServices.IDs
        if !setts.BlockedServices.Schedule.Contains(time.Now()) {
            d.ApplyBlockedServicesList(setts, svcs)
        }
    }
}
```

### 3.4 客户端策略覆盖

**核心代码位置**：`internal/client/storage.go:767-806`

```go
func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings) {
    // 1. 查找客户端 (ClientID → IP → DHCP MAC)
    c, ok := s.index.findByClientID(ClientID(id))
    if !ok {
        c, ok = s.index.findByIP(addr)
    }
    if !ok {
        foundMAC := s.dhcp.MACByIP(addr)
        if foundMAC != nil {
            c, ok = s.index.findByMAC(foundMAC)
        }
    }
    if !ok {
        return // 使用全局设置
    }

    // 2. 覆盖封禁服务配置
    if c.UseOwnBlockedServices {
        setts.BlockedServices = c.BlockedServices.Clone()
    }

    // 3. 客户端标识注入 (用于规则中的 $client 修饰符)
    setts.ClientName = c.Name
    setts.ClientTags = slices.Clone(c.Tags)

    // 4. 覆盖过滤开关 (如果客户端启用了独立配置)
    if !c.UseOwnSettings {
        return
    }

    setts.FilteringEnabled = c.FilteringEnabled
    setts.SafeSearchEnabled = c.SafeSearchConf.Enabled
    setts.ClientSafeSearch = c.SafeSearch
    setts.SafeBrowsingEnabled = c.SafeBrowsingEnabled
    setts.ParentalEnabled = c.ParentalEnabled
}
```

### 3.5 循环依赖解耦：函数注入设计

为了解决 `filtering` 包与 `client` 包之间的循环依赖问题，AdGuard Home 使用了**函数注入**的设计模式。

**核心代码位置**：
- `internal/filtering/filtering.go:94-97`（Config 中的函数字段）
- `internal/filtering/filtering.go:277-282`（DNSFilter 中的函数字段）
- `internal/home/clients.go:142`（注入点）

```go
// 1. 在 filtering.Config 中定义函数字段
type Config struct {
    // ApplyClientFiltering retrieves persistent client information using the
    // ClientID or client IP address, and applies it to the filtering settings.
    ApplyClientFiltering func(clientID string, cliAddr netip.Addr, setts *Settings) `yaml:"-"`
}

// 2. 在 DNSFilter 中保存该函数
type DNSFilter struct {
    applyClientFiltering func(clientID string, cliAddr netip.Addr, setts *Settings)
}

// 3. 在 New 时注入
func New(c *Config, blockFilters []Filter) (d *DNSFilter, err error) {
    d = &DNSFilter{
        applyClientFiltering:   c.ApplyClientFiltering,
        // ...
    }
}

// 4. 在 home 包初始化时注入具体实现
// internal/home/clients.go:142
filteringConf.ApplyClientFiltering = clients.storage.ApplyClientFiltering
```

**设计亮点**：
- `filtering` 包不直接依赖 `client` 包
- 通过抽象函数接口实现反向控制（IoC）
- 查询时通过函数指针调用，无性能损失

### 3.6 覆盖优先级

```
全局默认值
    ↓
全局封禁服务配置
    ↓
客户端独立封禁服务 (UseOwnBlockedServices=true)
    ↓
客户端独立过滤开关 (UseOwnSettings=true)
    ↓
最终 Settings 对象
```

---

## 四、查询时的完整串联

### 4.1 查询处理流水线

**核心代码位置**：`internal/dnsforward/requesthandler.go:18-61`

```go
func (s *Server) ServeDNS(ctx context.Context, _ *proxy.Proxy, pctx *proxy.DNSContext) error {
    dctx := &dnsContext{
        proxyCtx:  pctx,
        result:    &filtering.Result{},
        startTime: time.Now(),
    }

    // 处理模块按顺序执行
    mods := []modProcessFunc{
        s.processInitial,               // 阶段1: 客户端识别 + 策略叠加
        s.processDDRQuery,
        s.processDHCPHosts,
        s.processDHCPAddrs,
        s.processFilteringBeforeRequest, // 阶段2: 请求过滤
        s.processUpstream,              // 阶段3: 上游转发
        s.processFilteringAfterResponse,// 阶段4: 响应过滤
        s.ipset.process,
        s.processQueryLogsAndStats,
    }

    for _, process := range mods {
        r := process(ctx, l, dctx)
        switch r {
        case resultCodeSuccess: continue
        case resultCodeFinish:  return nil
        case resultCodeError:   return dctx.err
        }
    }
}
```

### 4.2 dnsContext：贯穿全流程的上下文

**核心代码位置**：`internal/dnsforward/process.go:21-60`

`dnsContext` 是整个 DNS 查询处理流程的核心数据载体，在各个处理模块间传递状态：

```go
type dnsContext struct {
    proxyCtx *proxy.DNSContext      // 来自 dnsproxy 的原始上下文

    setts *filtering.Settings       // 【关键】客户端过滤设置 (策略叠加结果)
    result *filtering.Result        // 过滤匹配结果

    origResp *dns.Msg               // 上游原始响应 (被修改时保存)
    err error                       // 处理错误

    clientID string                 // 从 DoH/DoT/DoQ 提取的 ClientID
    startTime time.Time             // 请求开始时间

    origQuestion dns.Question       // 原始问题 (被重写时保存)
    protectionEnabled bool          // 全局保护状态
    responseFromUpstream bool       // 响应是否来自上游
    responseAD bool                 // 响应是否有 AD 位
    isDHCPHost bool                 // 是否为 DHCP 本地域名
}
```

**关键作用**：
- `setts` 字段连接了「策略叠加」和「规则匹配」两个阶段
- `clientID` 字段连接了「中间件提取」和「客户端识别」两个阶段
- `result` 字段保存最终过滤决策，供后续模块使用

### 4.3 阶段1：客户端识别 + 策略叠加

**核心代码位置**：`internal/dnsforward/process.go:104-148`

```go
func (s *Server) processInitial(ctx context.Context, l *slog.Logger, dctx *dnsContext) resultCode {
    // ... 特殊域名处理 (Firefox canary, healthcheck 等)

    // 1. 从 context 获取 ClientID
    clientID, ok := clientIDFromContext(ctx)
    if ok {
        dctx.clientID = clientID
    }

    // 2. 获取全局保护状态
    dctx.protectionEnabled, _ = s.UpdatedProtectionStatus(ctx)

    // 3. 关键: 生成客户端特定的过滤设置
    dctx.setts = s.clientRequestFilteringSettings(dctx)

    return resultCodeSuccess
}
```

### 4.4 阶段2：请求过滤

**核心代码位置**：`internal/dnsforward/process.go:395-428` → `internal/dnsforward/filter.go:28-77`

```go
func (s *Server) processFilteringBeforeRequest(...) resultCode {
    // ...

    dctx.result, err = s.filterDNSRequest(ctx, l, dctx)

    return resultCodeSuccess
}

func (s *Server) filterDNSRequest(...) (*filtering.Result, error) {
    host := strings.TrimSuffix(q.Name, ".")

    // 核心: 调用 DNSFilter.CheckHost，传入客户端 Settings
    resVal, err := s.dnsFilter.CheckHost(host, q.Qtype, dctx.setts)

    // 根据匹配结果生成响应或重写请求
    if resVal.IsFiltered {
        pctx.Res = s.genDNSFilterMessage(ctx, l, pctx, &resVal)
    } else if isRewrittenCNAME(&resVal) {
        dctx.origQuestion = q
        req.Question[0].Name = dns.Fqdn(resVal.CanonName)
    }

    return &resVal, err
}
```

### 4.5 规则匹配顺序

**核心代码位置**：`internal/filtering/filtering.go:505-537`

```go
func (d *DNSFilter) CheckHost(host string, qtype uint16, setts *Settings) (Result, error) {
    host = strings.ToLower(host)

    // 0. DNS 重写规则 (优先级最高)
    if setts.FilteringEnabled {
        res = d.processRewrites(host, qtype)
        if res.Reason == Rewritten {
            return res, nil
        }
    }

    // 按顺序执行各个检查器
    for _, hc := range d.hostCheckers {
        res, err = hc.check(host, qtype, setts)
        if err != nil {
            return Result{}, err
        }
        if res.Reason.Matched() {
            return res, nil
        }
    }

    return Result{}, nil
}
```

**hostCheckers 顺序**（`filtering.go:994-1012`）：
```go
d.hostCheckers = []hostChecker{
    {check: d.matchSysHosts,           name: "hosts container"},    // 1. /etc/hosts
    {check: d.matchHost,               name: "filtering"},          // 2. 订阅 + 自定义规则
    {check: d.matchBlockedServicesRules, name: "blocked services"}, // 3. 封禁服务
    {check: d.checkSafeBrowsing,       name: "safe browsing"},      // 4. 安全浏览
    {check: d.checkParental,           name: "parental"},           // 5. 家长控制
    {check: d.checkSafeSearch,         name: "safe search"},        // 6. 安全搜索
}
```

### 4.6 核心规则匹配逻辑

**核心代码位置**：`internal/filtering/filtering.go:884-949`

```go
func (d *DNSFilter) matchHost(host string, rrtype uint16, setts *Settings) (Result, error) {
    if !setts.FilteringEnabled {
        return Result{}, nil
    }

    // 构造 DNS 请求，携带客户端信息
    // 【关键连接点】：客户端识别阶段获取的 ClientName 和 ClientTags
    // 通过 DNSRequest 传递给 urlfilter 引擎，用于支持 $client 修饰符的规则
    ufReq := &urlfilter.DNSRequest{
        Hostname:          host,
        ClientTags:        container.NewSortedSliceSet(setts.ClientTags...),
        ClientIP:          setts.ClientIP,
        ClientIdentifiers: container.NewSortedSliceSet(setts.ClientName),
        DNSType:           rrtype,
    }

    // $client 修饰符规则示例:
    // ||example.com^$client=192.168.1.100    → 仅对特定 IP 生效
    // ||example.com^$client=John              → 仅对名为 John 的客户端生效
    // ||example.com^$client=~John             → 对除 John 外的所有客户端生效
    // ||example.com^$client=kid               → 仅对带有 kid 标签的客户端生效

    d.engineLock.RLock()
    defer d.engineLock.RUnlock()

    // 1. 白名单优先检查
    if setts.ProtectionEnabled && d.filteringEngineAllow != nil {
        dnsres, ok := d.filteringEngineAllow.MatchRequest(ufReq)
        if ok {
            return d.matchHostProcessAllowList(ctx, host, dnsres)
        }
    }

    // 2. 黑名单检查
    dnsres, matchedEngine := d.filteringEngine.MatchRequest(ufReq)

    // 3. DNS 重写规则处理
    dnsRWRes := d.processDNSResultRewrites(dnsres, host)
    if dnsRWRes.Reason != NotFilteredNotFound {
        return dnsRWRes, nil
    }

    // 4. 处理匹配结果
    if !setts.ProtectionEnabled {
        return Result{}, nil
    }

    res = d.matchHostProcessDNSResult(rrtype, dnsres)
    return res, nil
}
```

### 4.7 封禁服务匹配

**核心代码位置**：`internal/filtering/filtering.go:623-667`

```go
func (d *DNSFilter) matchBlockedServicesRules(host string, _ uint16, setts *Settings) (Result, error) {
    if !setts.ProtectionEnabled {
        return Result{}, nil
    }

    svcs := setts.ServicesRules // 来自策略叠加阶段
    if len(svcs) == 0 {
        return Result{}, nil
    }

    req := rules.NewRequestForHostname(host)
    for _, s := range svcs {
        for _, rule := range s.Rules {
            if rule.Match(req) {
                return Result{
                    Reason:      FilteredBlockedService,
                    IsFiltered:  true,
                    ServiceName: s.Name,
                    Rules: []*ResultRule{{
                        FilterListID: rulelist.APIID(rule.GetFilterListID()),
                        Text:         rule.Text(),
                    }},
                }, nil
            }
        }
    }

    return Result{}, nil
}
```

### 4.8 阶段4：响应过滤

**核心代码位置**：`internal/dnsforward/process.go:542-575` → `internal/dnsforward/filter.go:116-169`

即使请求未被拦截，AdGuard Home 还会检查上游响应中的资源记录：

```go
func (s *Server) filterDNSResponse(ctx context.Context, l *slog.Logger, dctx *dnsContext) error {
    setts := dctx.setts
    if !setts.FilteringEnabled {
        return nil
    }

    // 遍历响应 Answer 中的每条记录
    for i, a := range pctx.Res.Answer {
        switch a := a.(type) {
        case *dns.CNAME:
            host = strings.TrimSuffix(a.Target, ".")
            res, err = s.checkHostRules(host, dns.TypeCNAME, setts)
        case *dns.A:
            host = a.A.String()
            res, err = s.checkHostRules(host, dns.TypeA, setts)
        case *dns.AAAA:
            host = a.AAAA.String()
            res, err = s.checkHostRules(host, dns.TypeAAAA, setts)
        case *dns.HTTPS:
            res, err = s.filterHTTPSRecords(a, setts)
        }

        if res != nil && res.IsFiltered {
            dctx.result = res
            dctx.origResp = pctx.Res
            pctx.Res = s.genDNSFilterMessage(ctx, l, pctx, res)
            break
        }
    }

    return nil
}
```

---

## 五、关键数据结构关系图

```
┌─────────────────────────────────────────────────────────────┐
│                     DNS 查询请求                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  Middleware (middleware.go)                                 │
│  ├─ 提取 ClientID (DoH/DoT/DoQ)                              │
│  ├─ 检查客户端访问黑名单                                    │
│  └─ ClientID 注入 Context                                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    dnsContext 结构体                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  proxyCtx: *proxy.DNSContext (原始请求上下文)           │  │
│  │  clientID: "" (来自 Context)                           │  │
│  │  setts: nil (待填充)                                   │  │
│  │  result: &Result{} (待填充)                            │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  processInitial (process.go:104-148)                        │
│  ├─ dnsFilter.Settings() → 获取全局默认值                    │
│  └─ clientRequestFilteringSettings(dctx)                    │
│     └─ dnsFilter.ApplyAdditionalFiltering(addr, id, setts)  │
│        ├─ ApplyBlockedServices(setts) → 全局封禁服务        │
│        └─ applyClientFiltering(id, addr, setts)             │
│           └─ Storage.Find() → index.findByClientID/IP/MAC   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    dnsContext (已填充)                      │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  setts: *Settings                                      │  │
│  │  ├─ ClientName/ClientIP/ClientTags                     │  │
│  │  ├─ ServicesRules (封禁服务规则)                       │  │
│  │  ├─ ProtectionEnabled/FilteringEnabled                 │  │
│  │  └─ SafeBrowsing/Parental/SafeSearch                  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  processFilteringBeforeRequest                              │
│  └─ filterDNSRequest(ctx, l, dctx)                          │
│     └─ dnsFilter.CheckHost(host, qtype, dctx.setts)         │
│        ├─ processRewrites() → DNS 重写                       │
│        ├─ matchSysHosts() → /etc/hosts                       │
│        ├─ matchHost() → 订阅规则 + 自定义规则                │
│        │  ├─ filteringEngineAllow.MatchRequest() → 白名单    │
│        │  └─ filteringEngine.MatchRequest() → 黑名单         │
│        ├─ matchBlockedServicesRules() → 封禁服务             │
│        ├─ checkSafeBrowsing() → 安全浏览                     │
│        ├─ checkParental() → 家长控制                         │
│        └─ checkSafeSearch() → 安全搜索                       │
└─────────────────────────────────────────────────────────────┘
                              ↓
                 ┌────────────┴────────────┐
                 ↓                         ↓
          拦截/重写                     放行
                 ↓                         ↓
    genDNSFilterMessage()        processUpstream()
                 ↓                         ↓
          直接响应               上游 DNS 服务器
                                           ↓
                              processFilteringAfterResponse
                                           ↓
                              filterDNSResponse(dctx) → 检查响应记录
                                           ↓
                                     最终响应
```

---

## 六、关键代码路径索引

| 功能 | 文件 | 行号 |
|------|------|------|
| 规则编译入口 | `internal/filtering/filter.go` | 662-708 |
| 引擎初始化 | `internal/filtering/filtering.go` | 746-777 |
| 客户端ID提取 | `internal/dnsforward/middleware.go` | 28-55 |
| 客户端索引 | `internal/client/index.go` | 33-51 |
| 客户端查找 | `internal/client/storage.go` | 529-576 |
| 策略叠加入口 | `internal/filtering/filter.go` | 710-725 |
| 客户端策略应用 | `internal/client/storage.go` | 767-806 |
| 全局 Settings 生成 | `internal/filtering/filtering.go` | 324-334 |
| 客户端 Settings 生成 | `internal/dnsforward/filter.go` | 18-24 |
| 函数注入解耦 | `internal/home/clients.go` | 142 |
| dnsContext 定义 | `internal/dnsforward/process.go` | 21-60 |
| 请求处理主流程 | `internal/dnsforward/requesthandler.go` | 18-61 |
| 初始处理阶段 | `internal/dnsforward/process.go` | 104-148 |
| 过滤执行 | `internal/dnsforward/filter.go` | 28-77 |
| CheckHost 主逻辑 | `internal/filtering/filtering.go` | 505-537 |
| 规则匹配核心 | `internal/filtering/filtering.go` | 884-949 |
| 封禁服务匹配 | `internal/filtering/filtering.go` | 623-667 |
| 响应过滤 | `internal/dnsforward/filter.go` | 116-169 |

---

## 七、设计亮点

1. **双引擎架构**：白名单和黑名单独立编译，查询时白名单优先，避免误拦截
2. **原子替换**：规则更新时编译新引擎后原子替换指针，查询期间无锁竞争
3. **灵活的策略叠加**：通过 `UseOwnSettings` 和 `UseOwnBlockedServices` 标志实现精细的配置继承
4. **多层次客户端识别**：ClientID → IP → DHCP MAC → 子网 → MAC 的 fallback 链
5. **完整的响应过滤**：不仅检查请求域名，还检查响应中的 CNAME、IP 和 HTTPS 记录
6. **检查器链模式**：`hostCheckers` 数组清晰定义了各过滤模块的优先级
7. **函数注入解耦**：通过 `ApplyClientFiltering` 函数字段解决 `filtering` 与 `client` 包的循环依赖
8. **上下文传递设计**：`dnsContext` 结构体在各处理模块间无缝传递状态，避免全局变量
9. **白名单优先原则**：在 `matchHost` 中先检查白名单引擎，命中直接放行，性能优化

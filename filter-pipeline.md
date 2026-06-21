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

### 3.5 循环依赖解耦：编译期函数注入设计

这是 AdGuard Home 架构中一个非常精妙的设计，通过**编译期抽象 + 运行期注入**，完美解决了包之间的循环依赖问题。

#### 3.5.1 为什么会产生循环依赖？

让我们先看三个包的 import 关系：

```
┌──────────────────────────────────────────────────────────┐
│  client 包 (internal/client/)                            │
│  ├─ storage.go:15  → import "filtering"                  │
│  │    (Storage.ApplyClientFiltering 需要接收              │
│  │     *filtering.Settings 参数)                          │
│  └─ persistent.go:14 → import "filtering"                │
│       (Persistent 客户端的 BlockedServices,               │
│        SafeSearch 等字段使用 filtering 包的类型)           │
└──────────────────────────────────────────────────────────┘
                          │
                          │ 依赖
                          ▼
┌──────────────────────────────────────────────────────────┐
│  filtering 包 (internal/filtering/)                       │
│  【问题】：在规则匹配时需要查找客户端配置！                 │
│  例如 ApplyAdditionalFiltering() 需要调用                 │
│  storage.ApplyClientFiltering() 来叠加客户端策略          │
│                                                          │
│  如果直接 import "client" → 形成循环依赖！                │
│  filtering → client → filtering → ...                    │
│  Go 编译器报错: import cycle not allowed                 │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  home 包 (internal/home/)                                │
│  同时 import "client" 和 "filtering"                     │
│  → 这个包是顶层协调者，可以看到两边的具体类型              │
└──────────────────────────────────────────────────────────┘
```

**循环依赖触发场景**：
- `client` 包依赖 `filtering` 包：使用 `filtering.Settings`、`filtering.BlockedServices`、`filtering.SafeSearch` 等类型
- 如果 `filtering` 包反过来依赖 `client` 包：调用 `client.Storage.ApplyClientFiltering()` 方法
- 结果：`filtering → client → filtering`，编译失败

#### 3.5.2 解耦方案：函数签名抽象 + 依赖反转

解决思路来自 **DIP（依赖倒置原则）**：高层模块不应依赖低层模块，两者都应依赖抽象。

**第一步：在 filtering 包中定义抽象（函数签名）**

```go
// internal/filtering/filtering.go:94-97
type Config struct {
    // 【关键】只定义函数签名，不依赖 client 包！
    // 参数和返回值都使用 filtering 包自身或标准库类型
    ApplyClientFiltering func(clientID string, cliAddr netip.Addr, setts *Settings) `yaml:"-"`
}

// internal/filtering/filtering.go:277-282
type DNSFilter struct {
    // 保存注入的函数指针
    applyClientFiltering func(clientID string, cliAddr netip.Addr, setts *Settings)
}
```

**设计要点**：
- 函数参数 `*Settings` 是 filtering 包自己定义的类型，没问题
- 函数参数 `netip.Addr` 是标准库类型，没问题
- 整个函数签名中**没有出现任何 `client` 包的类型**
- 因此 `filtering` 包编译时**完全不需要 import `client` 包**

**第二步：在 DNSFilter 中通过字段保存函数**

```go
// internal/filtering/filtering.go:972-986
func New(c *Config, blockFilters []Filter) (d *DNSFilter, err error) {
    d = &DNSFilter{
        // 【依赖注入】从 Config 中接收函数实现
        applyClientFiltering:   c.ApplyClientFiltering,
        // ... 其他字段
    }
}
```

**第三步：在 ApplyAdditionalFiltering 中调用注入的函数**

```go
// internal/filtering/filter.go:710-725
func (d *DNSFilter) ApplyAdditionalFiltering(cliAddr netip.Addr, clientID string, setts *Settings) {
    setts.ClientIP = cliAddr
    d.ApplyBlockedServices(setts)

    // 【通过函数指针间接调用】
    // 此时 d.applyClientFiltering 可能是 nil（测试场景）或具体实现
    if d.applyClientFiltering != nil {
        d.applyClientFiltering(clientID, cliAddr, setts)
    }

    // ... 后续处理
}
```

**第四步：在 home 包（顶层）注入具体实现**

```go
// internal/home/clients.go:1-25 (imports)
// home 包可以同时看到 client 和 filtering 两个包
import (
    "github.com/AdguardTeam/AdGuardHome/internal/client"     // ✅
    "github.com/AdguardTeam/AdGuardHome/internal/filtering"  // ✅
)

// internal/home/clients.go:142
// 在初始化流程中完成注入
// clients.storage.ApplyClientFiltering 的签名恰好匹配
// filtering.Config.ApplyClientFiltering 函数类型
filteringConf.ApplyClientFiltering = clients.storage.ApplyClientFiltering
```

**类型匹配检查**：
```go
// 函数签名完全匹配，可以直接赋值
//
// filtering.Config.ApplyClientFiltering 类型:
//   func(clientID string, cliAddr netip.Addr, setts *filtering.Settings)
//
// client.Storage.ApplyClientFiltering 方法签名:
//   func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings)
//
// 方法值 (method value) clients.storage.ApplyClientFiltering 
// 自动转换为同签名的函数值（receiver 被绑定）
```

#### 3.5.3 编译期 vs 运行期视角

| 阶段 | filtering 包可见性 | client 包可见性 |
|------|-------------------|----------------|
| **编译期** | 只知道函数签名，不知道具体实现 | 正常 import filtering 使用类型 |
| **运行期** | 函数指针已被 home 包注入，可正常调用 | 方法被调用，执行客户端策略叠加 |
| **依赖关系** | filtering → (无循环) → client | client → filtering |

#### 3.5.4 与接口实现的对比

为什么不用接口？

| 方案 | 优点 | 缺点 |
|------|------|------|
| **函数注入（当前方案）** | 仅需一个函数字段，零成本抽象 | 仅适合单一职责 |
| 接口（`type ClientLookup interface`） | 可扩展多个方法 | 需要定义接口 + 结构体实现，多一层间接 |

由于 filtering 包只需要「客户端策略叠加」这一个能力，用**单个函数字段**是最简洁的选择。

#### 3.5.5 类似模式在代码中的其他应用

```go
// filtering.Config 中还有类似的函数字段：
type Config struct {
    SafeBrowsingChecker    Checker  // 安全浏览检查器
    ParentalControlChecker Checker  // 家长控制检查器
    ApplyClientFiltering   func(...) // 客户端策略应用
}
```

这些都是**面向能力编程**而非**面向实现编程**的典型例子。

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

---

## 八、$client 修饰符匹配机制深度分析

`$client` 修饰符允许规则仅对特定客户端（按 IP、名称、标签）生效，是连接「客户端识别阶段」与「规则匹配阶段」的核心桥梁。分析基于 `github.com/AdguardTeam/urlfilter@v0.23.2`。

### 8.1 修饰符语法与内部表示

**语法规则**：

```
||example.com^$client=VALUE                // 白名单（允许模式）
||example.com^$client=~VALUE               // 黑名单（排除模式，~ 表示否定）
||example.com^$client=VAL1|VAL2|VAL3       // 多个值，任一匹配
```

VALUE 可以是：
- **IP 地址**：`192.168.1.100`
- **CIDR 子网**：`192.168.0.0/16`
- **客户端名**：`John`、`Family-PC`
- **客户端标签**：通过 `$ctag` 修饰符单独处理

**内部数据结构**（`urlfilter/rules/clients.go:12-19`）：

```go
type clients struct {
    // 非 IP/子网的字符串标识（客户端名）
    identifiers *container.SortedSliceSet[string]

    // IP/子网表示（用 SliceSubnetSet 实现二分查找）
    nets netutil.SliceSubnetSet
}

// NetworkRule 中保存两组客户端
type NetworkRule struct {
    permittedClients  *clients  // $client=VALUE  → 仅对这些客户端生效
    restrictedClients *clients  // $client=~VALUE → 对这些客户端不生效

    permittedClientTags  *container.SortedSliceSet[string] // $ctag=VALUE
    restrictedClientTags *container.SortedSliceSet[string] // $ctag=~VALUE
}
```

**解析过程**（`urlfilter/rules/network.go:959` 附近）：
```go
// 伪代码：解析 $client 修饰符时
for _, clientStr := range clientStrings {
    if strings.HasPrefix(clientStr, "~") {
        restricted.add(clientStr[1:])   // ~ 开头 → 加入排除集合
    } else {
        permitted.add(clientStr)        // 否则 → 加入允许集合
    }
}
```

### 8.2 NetworkRule.Match 中的检查顺序

`NetworkRule.Match` 方法使用一个**短路与**的 switch case 链，按固定顺序执行所有检查：

**核心代码**（`urlfilter/rules/network.go:322-341`）：

```go
func (r *NetworkRule) Match(req *Request) (ok bool) {
    switch {
    case
        // 1. 快捷匹配失败 → 快速排除（基于规则的最长无特殊字符子串）
        !r.matchShortcut(req),

        // 2. $third-party 修饰符检查
        r.IsOptionEnabled(OptionThirdParty) && !req.ThirdParty,
        r.IsOptionDisabled(OptionThirdParty) && req.ThirdParty,

        // 3. 请求类型检查（$script, $image 等，DNS 中一般为 TypeDocument）
        !r.matchRequestType(req.RequestType),

        // 4. 目标域名限制（$domain）
        !r.matchRequestDomain(req.Hostname, req.IsHostnameRequest),

        // 5. 来源域名限制（$domain，DNS 过滤中一般不使用）
        !r.matchSourceDomain(req.SourceHostname),

        // 6. DNS 记录类型检查（$dnstype=A|AAAA|CNAME 等）
        !r.matchDNSType(req.DNSType),

        // 7. 【关键】客户端标签检查（$ctag 修饰符）
        !r.matchClientTags(req.ClientTags),

        // 8. 【关键】客户端标识检查（$client 修饰符）
        !r.matchClient(req.ClientIdentifiers, req.ClientIP),

        // 9. 最后：正则/模式匹配（最耗时）
        !r.matchPattern(req):

        return false  // 任一检查失败 → 整体不匹配
    }

    return true  // 全部通过 → 匹配
}
```

**设计解读**：
- 检查顺序按**计算成本从低到高**排列：
  - `matchShortcut`：O(1) 字符串子串检查 → 最先执行，快速过滤 90%+ 的不匹配规则
  - `matchClientTags` / `matchClient`：O(log n) 集合运算 → 在模式匹配前
  - `matchPattern`：正则匹配，最耗时 → 最后执行
- **Go 的短路求值**：逗号分隔的 case 条件中，只要有一个为 true（即「不匹配」），立即 return false

### 8.3 matchClient 匹配算法详解

**核心代码**（`urlfilter/rules/network.go:696-721`）：

```go
func (r *NetworkRule) matchClient(
    ids *container.SortedSliceSet[string], // 来自 Settings.ClientName 等
    ip netip.Addr,                          // 来自 Settings.ClientIP
) (ok bool) {
    restLen := r.restrictedClients.len()
    permLen := r.permittedClients.len()

    // 情况 1：规则没有 $client 修饰符 → 所有客户端都匹配
    if restLen == 0 && permLen == 0 {
        return true
    }

    // 情况 2：先检查「排除集合」（黑名单）
    // 只要客户端在 restricted 中 → 规则绝对不生效
    if r.restrictedClients.match(ids, ip) {
        return false
    }

    // 情况 3：再检查「允许集合」（白名单）
    if permLen != 0 {
        // permitted 非空 → 仅当客户端在 permitted 中才生效
        return r.permittedClients.match(ids, ip)
    }

    // 情况 4：permitted 为空，restricted 也不命中
    // （即规则只有 restricted，且客户端不在里面）
    return true
}
```

**clients.match 方法**（`urlfilter/rules/clients.go:77-85`）：
```go
func (c *clients) match(
    ids *container.SortedSliceSet[string], // 客户端标识集合
    ip netip.Addr,                          // 客户端 IP
) (ok bool) {
    if c == nil {
        return false
    }

    // 两个条件任一满足即可：
    // 1. 客户端标识符（名称）交集不为空
    // 2. IP 不为零值且在子网集合中
    return c.identifiers.Intersects(ids) ||
           ip != (netip.Addr{}) && c.nets.Contains(ip)
}
```

**优先级总结**（在单个规则内）：

| 条件组合 | 结果 | 说明 |
|---------|------|------|
| `restricted` 命中 | ❌ 不匹配 | 排除优先级最高，即使在 permitted 中也不行 |
| `permitted` 非空 + 未命中 | ❌ 不匹配 | 允许模式下必须明确包含 |
| `permitted` 非空 + 命中 | ✅ 匹配 | |
| `permitted` 空 + restricted 未命中 | ✅ 匹配 | 排除模式下默认通过 |

### 8.4 多条规则冲突时的优先级

当多个 `NetworkRule` 都匹配同一个请求时，由 `IsHigherPriority` 方法决出最终生效的规则。

**优先级算法**（`urlfilter/rules/network.go:399-433`）：

```go
func (r *NetworkRule) IsHigherPriority(other *NetworkRule) (ok bool) {
    // 第一梯队：$important 修饰符
    // 1. whitelist + $important  → 最高优先级
    // 2. $important (blocklist)   → 第二高
    if hasPriority, done := r.isHigherPriorityImportant(other); done {
        return hasPriority
    }

    // 第二梯队：白名单 vs 黑名单
    // 3. whitelist (@@) → 第三高
    if r.Whitelist && !other.Whitelist {
        return true
    }
    if other.Whitelist && !r.Whitelist {
        return false
    }

    // 第三梯队：规则特异性
    if r.IsOptionEnabled(OptionRedirect) && !other.IsOptionEnabled(OptionRedirect) {
        // $redirect 修饰符略高于普通规则
        return true
    }
    // 4. 非 generic 规则（有 $domain/$client 等限制） > generic 规则
    if !r.IsGeneric() && other.IsGeneric() {
        return true
    }

    // 其余：按规则文本特征比较（重要修饰符数量等）
    return r.isHigherPrioritySpec(other)
}
```

**完整优先级链**（高 → 低）：

```
 1. @@||...^$important,$client=X   // 白名单 + $important（最高）
 2. ||...^$important,$client=X     // 黑名单 + $important
 3. @@||...^$client=X              // 白名单规则
 4. ||...^$redirect,$client=X      // $redirect 特殊修饰符
 5. ||...^$client=X                // 非 generic（有明确 $client 限制）
 6. ||...^$domain=example.com      // 非 generic（有明确 $domain 限制）
 7. ||...^                         // generic 规则（最低）
```

**关键：`$client` 修饰符让规则成为「非 generic」**

```go
// urlfilter/rules/network.go:394-397
func (r *NetworkRule) IsGeneric() (ok bool) {
    // 只要 permittedDomains 为空就是 generic
    // 注意：$client 修饰符不直接影响 IsGeneric() 判断！
    return len(r.permittedDomains) == 0
}

// 但在 isTooWide 检查中会考虑 client 限制：
func (r *NetworkRule) isTooWide(pattern string) (ok bool) {
    // 即使 pattern 太宽（如 /*），只要有 client 限制就允许
    return isPatternTooWide(pattern) && r.hasNoRestrictions()
}

func (r *NetworkRule) hasNoRestrictions() (ok bool) {
    return len(r.permittedDomains) == 0 &&
        r.permittedClients.len() == 0 &&    // ← $client 修饰符算一种限制
        r.restrictedClients.len() == 0 &&
        r.permittedClientTags.Len() == 0 && // ← $ctag 也算
        // ... 其他限制
}
```

### 8.5 AdGuard Home 侧的数据传递链路

客户端信息从 AdGuard Home 的 `filtering.Settings` 传递到 urlfilter 的 `rules.Request`，全程经过 3 层转换：

```
第 1 层：AdGuard Home filtering.Settings
    setts.ClientName = "John"               // 客户端名
    setts.ClientIP   = 192.168.1.100        // 客户端 IP
    setts.ClientTags = ["kid", "family"]    // 客户端标签
         │
         ▼  matchHost() 中构造
第 2 层：urlfilter.DNSRequest
    ufReq := &urlfilter.DNSRequest{
        ClientIdentifiers: SortedSliceSet{"John"},
        ClientIP:          192.168.1.100,
        ClientTags:        SortedSliceSet{"kid", "family"},
        Hostname:          "example.com",
        DNSType:           dns.TypeA,
    }
         │
         ▼  DNSEngine.getRequestFromPool() 中转换
第 3 层：urlfilter.rules.Request
    req := &rules.Request{
        ClientIdentifiers: SortedSliceSet{"John"},  // → $client 匹配
        ClientIP:          192.168.1.100,            // → $client 匹配
        ClientTags:        SortedSliceSet{"kid","family"}, // → $ctag 匹配
        Hostname:          "example.com",            // → 域名模式匹配
        DNSType:           dns.TypeA,                // → $dnstype 匹配
    }
         │
         ▼  NetworkEngine.AppendAllMatching()
         遍历所有候选规则，调用 rule.Match(req)
         → 内部执行 matchClientTags() + matchClient()
         → 最终匹配结果通过 IsHigherPriority() 决出
```

### 8.6 $client 修饰符的实际匹配示例

**场景**：
- 客户端 John（IP: 192.168.1.100，标签: `kid`）访问 `badsite.com`
- 规则列表：
  ```
  R1: ||badsite.com^$client=John
  R2: ||badsite.com^$client=~192.168.1.0/24
  R3: @@||badsite.com^$ctag=parent
  R4: ||badsite.com^$important
  ```

**匹配过程**：
1. R1 检查：
   - `permittedClients={"John"}`, `restrictedClients={}`
   - `matchClient({"John"}, 192.168.1.100)` → permitted 命中 → ✅ 匹配
2. R2 检查：
   - `permittedClients={}`, `restrictedClients={192.168.0.0/24}`
   - `restrictedClients.match(...)` → IP 在子网内 → ❌ 不匹配
3. R3 检查：
   - `permittedClientTags={"parent"}`
   - 实际标签 `{"kid"}` 不交集 → ❌ 不匹配
4. R4 检查：
   - 无 `$client` / `$ctag` 限制 → ✅ 匹配

**优先级裁决**（R1 vs R4）：
- R1 是 `blocklist (非 generic)`，R4 是 `blocklist + $important`
- R4 有 `$important` → R4 优先级更高 → **最终被 R4 拦截**

### 8.7 关键代码路径索引（urlfilter 库）

| 功能 | 文件（GOPATH mod 缓存） | 行号 |
|------|------------------------|------|
| `clients` 结构体定义 | `urlfilter/rules/clients.go` | 12-19 |
| `clients.match()` 方法 | `urlfilter/rules/clients.go` | 77-85 |
| `NetworkRule.Match()` 检查链 | `urlfilter/rules/network.go` | 322-341 |
| `matchClient()` 算法 | `urlfilter/rules/network.go` | 696-721 |
| `matchClientTags()` 算法 | `urlfilter/rules/network.go` | 674-694 |
| `IsHigherPriority()` 优先级 | `urlfilter/rules/network.go` | 399-433 |
| `IsGeneric()` 判断 | `urlfilter/rules/network.go` | 394-397 |
| 规则过宽检查 `hasNoRestrictions` | `urlfilter/rules/network.go` | 292-302 |
| `DNSEngine.MatchRequestInto()` 收集 | `urlfilter/dnsengine.go` | 154-187 |
| `GetDNSBasicRule()` 选最终规则 | `urlfilter/rules/match.go` | 173-196 |

---

## 九、urlfilter 第三方库版本依赖与升级影响分析

### 9.1 版本依赖现状

**go.mod 中的声明**（`go.mod:8`）：

```
require github.com/AdguardTeam/urlfilter v0.23.2
```

AdGuard Home 与 urlfilter 是**同一组织（AdguardTeam）**下的两个项目，urlfilter 是核心过滤引擎库，AdGuard Home 是上层应用。这是一个「内部库 + 应用」的分层架构。

### 9.2 urlfilter 在 AdGuard Home 中的使用面

整理所有直接使用 `urlfilter.` 的代码位置：

| 使用位置 | 用途 | 关键类型/函数 |
|---------|------|--------------|
| `internal/filtering/filtering.go` | 主过滤引擎 | `DNSEngine`, `DNSRequest`, `DNSResult` |
| `internal/filtering/rulelist/engine.go` | 规则列表引擎 | `DNSEngine` |
| `internal/filtering/rulelist/textengine.go` | 文本规则引擎 | `DNSEngine`, `DNSRequest`, `DNSResult` |
| `internal/filtering/safesearch/safesearch.go` | 安全搜索引擎 | `DNSEngine`, `DNSRequest` |
| `internal/filtering/rewrite/storage.go` | 重写规则存储 | `DNSEngine`, `DNSRequest` |
| `internal/dnsforward/access.go` | 访问控制（黑名单主机） | `DNSEngine` |
| `internal/aghnet/ignore.go` | 忽略域名 | `DNSEngine` |

**共 7 个模块**直接依赖 urlfilter，形成了广泛的使用面。

### 9.3 ApplyClientFiltering 与 urlfilter 的关系澄清

注意：`ApplyClientFiltering` **不是** urlfilter 的接口，而是 AdGuard Home 内部 `filtering` 包的一个**注入函数字段**。

但它与 urlfilter 有深刻的关联——这个函数的存在，本质上是为了把**客户端信息**传递到**过滤规则匹配**流程中，而过滤规则匹配是由 urlfilter 执行的。

**完整的传递链路**：

```
client.Storage.ApplyClientFiltering()
    ↓ 注入为
DNSFilter.applyClientFiltering (函数字段)
    ↓ 设置到
filtering.Settings.ClientName / ClientIP / ClientTags
    ↓ 构造
urlfilter.DNSRequest { ClientIdentifiers, ClientIP, ClientTags }
    ↓ 传入
urlfilter.DNSEngine.MatchRequest()
    ↓ 调用
urlfilter.rules.NetworkRule.Match()
    ↓ 调用
urlfilter.rules.NetworkRule.matchClient() / matchClientTags()
```

### 9.4 urlfilter 升级可能带来的接口变更风险

如果 urlfilter 升级，以下接口变更会直接影响 ApplyClientFiltering 相关流程：

#### 风险 1：`DNSRequest` 结构变更

```go
// 当前版本（v0.23.2）
type DNSRequest struct {
    ClientTags        *container.SortedSliceSet[string]
    ClientIdentifiers *container.SortedSliceSet[string]
    ClientIP          netip.Addr
    // ...
}
```

**如果 urlfilter 改了字段名或类型**：
- `filtering.go` 的 `matchHost()` 方法会编译失败（构造 `urlfilter.DNSRequest` 的地方）
- `filtering/rewrite/storage.go` 等 7 个模块都要跟着改
- 但 `ApplyClientFiltering` 函数本身**签名不变**，因为它只操作 `filtering.Settings`

#### 风险 2：匹配逻辑变更

**例如**：urlfilter 调整了 `matchClient` 中的优先级（permitted 先于 restricted 检查）
- 会影响所有带 `$client` 修饰符的规则的行为
- AdGuard Home 侧代码不需要改，但业务行为变了
- 这种「静默变更」风险更高

#### 风险 3：新增修饰符支持

**例如**：urlfilter 新增了 `$clienttag` 的新语法（如 `$ctag=tag1,tag2` 的与逻辑）
- 需要 AdGuard Home 侧的 UI 和配置层适配
- `ApplyClientFiltering` 中可能需要新增对更多标签来源的支持

### 9.5 函数注入设计对升级的缓冲作用

有趣的是，`ApplyClientFiltering` 的**函数注入设计**本身就提供了一层升级缓冲：

```
┌─────────────────────────────────────────────────────────────┐
│  urlfilter 库（第三方，可能升级）                            │
│    DNSRequest, DNSEngine, NetworkRule                       │
└─────────────┬───────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│  filtering 包（AdGuard Home 内部）                           │
│    Settings 结构体（AdGuard Home 自己的类型）                 │
│    ApplyClientFiltering 函数字段（抽象接口）                  │
│    matchHost() → 构造 DNSRequest → 调用 urlfilter           │
└─────────────┬───────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│  client 包（AdGuard Home 内部）                              │
│    Storage.ApplyClientFiltering() （具体实现）               │
└─────────────────────────────────────────────────────────────┘
```

**缓冲作用**：
- 如果 urlfilter 接口变了，只需要在 `filtering.matchHost()` 这一层做适配
- `ApplyClientFiltering` 函数签名（`func(clientID string, cliAddr netip.Addr, setts *Settings)`）不变
- `client` 包完全感知不到 urlfilter 的变化 → 影响面被限制在 `filtering` 包内

### 9.6 升级时的验证要点

升级 urlfilter 版本时，关于客户端相关功能需要验证：

1. **编译检查**：所有构造 `urlfilter.DNSRequest` 的地方是否编译通过
2. **单元测试**：`filtering/` 下与 `$client` 修饰符相关的测试
3. **集成测试**：客户端策略叠加 + 规则匹配的端到端测试
4. **优先级验证**：多规则混合时（`$client` + `$important` + 白名单），优先级是否符合预期
5. **边界场景**：IPv6、子网匹配、空 ClientID 等

---

## 十、特殊网络场景下的客户端识别边界分析

### 10.1 IPv6 场景的边界

#### 10.1.1 IPv6 Zone Index（链路本地地址的作用域）

**问题**：IPv6 链路本地地址（`fe80::/10`）带有 zone index（如 `fe80::1%eth0`），同一个 IP 在不同网络接口上可能对应不同的设备。

**代码中的处理**（`internal/client/index.go:252-276`）：

```go
func (ci *index) findByIP(ip netip.Addr) (c *Persistent, found bool) {
    // 1. 先按完整 IP（含 zone）精确匹配
    uid, found := ci.ipToUID[ip]
    if found {
        return ci.uidToClient[uid], true
    }

    // 2. 去掉 zone 后，再在子网中查找
    ipWithoutZone := ip.WithZone("")
    ci.subnetToUID.Range(func(pref netip.Prefix, id UID) (cont bool) {
        // Remove zone before checking because prefixes strip zones.
        if pref.Contains(ipWithoutZone) {
            uid, found = id, true
            return false
        }
        return true
    })
    // ...
}
```

**两个关键点**：
- **精确匹配保留 zone**：`ipToUID` map 的 key 是完整的 `netip.Addr`（含 zone），不同接口上的相同 IP 会被区分
- **子网匹配去掉 zone**：子网（Prefix）不包含 zone，所以查找前先剥离

#### 10.1.2 `findByIPWithoutZone` 的不确定性

**场景**：查询日志（querylog）中不保存 IPv6 zone（见注释 TODO），需要根据 IP 反查客户端。

**代码**（`internal/client/index.go:309-327`）：

```go
// Note that multiple clients can have the same IP address with different zones.
// Therefore, the result of this method is indeterminate.
func (ci *index) findByIPWithoutZone(ip netip.Addr) (c *Persistent) {
    // ...
    for addr, uid := range ci.ipToUID {
        if addr.WithZone("") == ip {
            return ci.uidToClient[uid]  // 返回第一个匹配的，结果不确定！
        }
    }
    return nil
}
```

**风险**：当多个客户端配置了相同 IP 但不同 zone 时，查询日志反查可能得到错误的客户端。

#### 10.1.3 IPv6 隐私扩展地址（Privacy Extensions）

**问题**：IPv6 主机通常会定期生成随机的临时地址用于出站连接，导致同一个设备有多个 IPv6 地址。

**客户端识别的应对**：
- **IP 精确匹配**：失效（临时地址一直在变）
- **子网匹配**：可能生效（如果配置了整个 /64 子网对应一个客户端）
- **DHCPv6 MAC 映射**：可能失效（隐私扩展地址不通过 DHCP 分配）
- **ClientID（DoH/DoT/DoQ）**：最可靠（与 IP 无关）

**代码证据**：`findByIP()` 中 DHCP MAC 映射只检查 `dhcp.MACByIP(addr)`，对于 IPv6 隐私地址不会命中。

### 10.2 NAT 后多主机场景的边界

#### 10.2.1 经典 NAT 场景

**场景描述**：多个内网设备通过 NAT 共享一个公网 IP 访问 AdGuard Home（例如 AdGuard Home 部署在公网 VPS 上）。

```
客户端 A (192.168.1.10) ──┐
客户端 B (192.168.1.20) ──┼── NAT 路由器 (公网 IP: 203.0.113.1) ──→ AdGuard Home
客户端 C (192.168.1.30) ──┘
```

**客户端识别效果**：

| 识别方式 | 效果 | 原因 |
|---------|------|------|
| **IP 精确匹配** | ❌ 全部相同 | 三个客户端的源 IP 都是 203.0.113.1 |
| **子网匹配** | ❌ 全部相同 | 都在同一个 /32 或更大子网内 |
| **DHCP MAC 映射** | ❌ 无效 | AdGuard Home 看不到内网 MAC |
| **ClientID** | ✅ 可区分 | 需要客户端配置 DoH/DoT/DoQ 时加上 ClientID |
| **$client 修饰符规则** | ⚠️ 取决于配置方式 | 用 IP 会全部命中，用 ClientID 可区分 |

#### 10.2.2 应对方案：EDNS Client Subnet (ECS)

AdGuard Home 支持从 EDNS Client Subnet 选项中读取客户端子网信息。

**相关代码位置**：
- `internal/dnsforward/process.go` 中的处理流程
- `internal/querylog/query.go:88-90`：`ReqECS` 字段

**但 ECS 主要用于**：
- 向上游 DNS 传递客户端子网（实现 CDN 就近接入）
- 记录查询日志

**ECS 不用于**：
- 客户端识别（`Find()` 方法不检查 ECS）
- 客户端策略叠加

验证：在 `storage.go` 的 `Find()` 方法中，`FindParams` 结构体没有 ECS 相关字段，查找逻辑也不使用 ECS。

#### 10.2.3 NAT 场景下的策略叠加行为

当多个客户端共享一个 IP（NAT 场景）时，如果配置了该 IP 对应的客户端策略，会发生什么？

```go
// internal/client/storage.go:564-576
func (s *Storage) findByIP(addr netip.Addr) (p *Persistent, ok bool) {
    // 1. IP 精确匹配 → 所有 NAT 后的客户端都命中同一个 Persistent
    p, ok = s.index.findByIP(addr)
    if ok {
        return p, true
    }
    // 2. DHCP MAC 映射 → 公网场景不命中
    foundMAC := s.dhcp.MACByIP(addr)
    // ...
}
```

**结果**：NAT 后的所有设备会**共享同一个客户端配置**。
- 如果这个 IP 对应的客户端配置了「禁止访问社交网站」，所有 NAT 后的设备都不能访问
- 无法单独对 NAT 后的某台设备设策略，除非使用 ClientID

### 10.3 多个重叠子网的优先级

当一个 IP 同时属于多个配置了客户端的子网时，哪一个会被选中？

**排序规则**（`internal/client/persistent.go:196-212`）：

```go
func subnetCompare(x, y netip.Prefix) (cmp int) {
    if x == y {
        return 0
    }
    xAddr, xBits := x.Addr(), x.Bits()
    yAddr, yBits := y.Addr(), y.Bits()

    if xBits == yBits {
        return xAddr.Compare(yAddr)
    }

    // 【关键】位数多（更精确）的子网排在前面
    if xBits > yBits {
        return -1  // x 在前
    } else {
        return 1
    }
}
```

**遍历顺序**：`SortedMap.Range()` 按 `subnetCompare` 排序后的顺序遍历 → **更精确的子网先被检查**。

**匹配逻辑**（`index.go:259-269`）：

```go
ci.subnetToUID.Range(func(pref netip.Prefix, id UID) (cont bool) {
    if pref.Contains(ipWithoutZone) {
        uid, found = id, true
        return false  // 找到第一个就停止遍历！
    }
    return true
})
```

**结论**：当 IP 同时属于多个子网时，**前缀长度最长（最精确）的子网优先**。

**示例**：
- 子网 A：`10.0.0.0/8` → 客户端「访客网络」
- 子网 B：`10.0.1.0/24` → 客户端「办公网络」
- IP `10.0.1.100` 同时属于两个子网
- 结果：命中「办公网络」（因为 /24 比 /8 更精确）

### 10.4 多 IP 客户端的识别边界

一个 Persistent 客户端可以配置多个 IP 地址：

```go
type Persistent struct {
    IPs     []netip.Addr    // 多个 IP
    Subnets []netip.Prefix  // 多个子网
    MACs    []net.HardwareAddr
    ClientIDs []ClientID
    // ...
}
```

**查找时的行为**：
- 任一 IP 命中 → 整个客户端配置生效
- 没有「根据命中的 IP 不同应用不同策略」的机制
- 一个客户端只有一套策略配置

### 10.5 边界场景总结表

| 场景 | IP 精确匹配 | 子网匹配 | DHCP MAC | ClientID | 可靠度 |
|------|------------|---------|----------|----------|--------|
| 普通 IPv4 局域网 | ✅ | ✅ | ✅ | ✅ | 高 |
| 普通 IPv6 局域网 | ✅ | ✅ | 部分 | ✅ | 中 |
| IPv6 隐私扩展地址 | ❌ | 部分 | ❌ | ✅ | 低 → 中（用 ClientID） |
| IPv6 链路本地（多 zone） | ⚠️ 取决于 zone | ✅ | ❌ | ✅ | 中 |
| NAT 后多主机共享 IP | ❌（都一样） | ❌（都一样） | ❌ | ✅ | 低 → 高（用 ClientID） |
| 客户端配置了多个 IP | ✅（任一命中即可） | ✅ | ✅ | ✅ | 高 |
| 多个重叠子网 | — | ✅（最长前缀优先） | — | — | 高 |

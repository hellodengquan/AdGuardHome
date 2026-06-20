# AdGuard Home Hosts 文件加载与系统 Hosts 联动机制分析

## 一、整体架构概览

AdGuard Home 的 hosts 解析体系涉及**两个独立的来源**和**两条解析路径**，它们在 DNS 请求处理流程中不同阶段被触发：

### 1.1 两个来源

| 来源类型 | 说明 | 存储位置 |
|---------|------|---------|
| 系统 Hosts | 操作系统自带的 hosts 文件（如 `/etc/hosts`、`C:\Windows\System32\drivers\etc\hosts`） | `globalContext.etcHosts` (`*aghnet.HostsContainer`) |
| 自定义 Hosts/DNS Rewrites | 用户在 AdGuard Home 管理界面配置的 DNS 重写规则 | 配置文件 `config.Rewrites` + 过滤规则引擎中的 `$dnsrewrite` 规则 |

### 1.2 两条解析路径

1. **过滤层路径**：在 `DNSFilter.CheckHost()` 中按优先级顺序匹配各 hosts 来源，直接返回解析结果，无需访问上游 DNS
2. **Bootstrap Resolver 路径**：系统 hosts 还被包装为 `upstream.Resolver`，参与上游 DNS 服务器域名的 bootstrap 解析

---

## 二、系统 Hosts 文件加载流程

### 2.1 初始化入口

系统 hosts 的初始化发生在 `setupContext()` 函数中（`internal/home/home.go:182`）：

```go
func setupContext(...) (err error) {
    if !opts.noEtcHosts {
        err = setupHostsContainer(ctx, baseLogger)
        // ...
    }
    // ...
}
```

可以通过命令行参数 `--no-etc-hosts` 禁用系统 hosts 加载。

### 2.2 HostsContainer 创建流程

`setupHostsContainer()` 函数（`internal/home/home.go:278`）执行以下步骤：

1. **创建文件系统监视器**：`aghos.NewOSWatcher()` 用于监听 hosts 文件变化
2. **获取系统 hosts 文件路径**：调用 `hostsfile.DefaultHostsPaths()` 返回操作系统默认的 hosts 文件路径列表
3. **创建 HostsContainer**：`aghnet.NewHostsContainer()`
4. **启动文件监视器**：`hostsWatcher.Start(ctx)`

```go
func setupHostsContainer(ctx context.Context, baseLogger *slog.Logger) (err error) {
    // 1. 创建 FS watcher
    hostsWatcher, err = aghos.NewOSWatcher(...)
    
    // 2. 获取系统 hosts 路径
    paths, err := hostsfile.DefaultHostsPaths()
    
    // 3. 创建 HostsContainer
    globalContext.etcHosts, err = aghnet.NewHostsContainer(
        ctx, l, osutil.RootDirFS(), hostsWatcher, paths...,
    )
    
    // 4. 启动监视器
    return hostsWatcher.Start(ctx)
}
```

### 2.3 HostsContainer 内部结构

定义在 `internal/aghnet/hostscontainer.go:26`：

```go
type HostsContainer struct {
    logger   *slog.Logger
    done     chan struct{}
    updates  chan *hostsfile.DefaultStorage
    current  atomic.Pointer[hostsfile.DefaultStorage]  // 当前生效的 hosts 数据
    fsys     fs.FS
    watcher  aghos.FSWatcher
    patterns []string  // 文件匹配模式（支持目录）
}
```

关键特性：
- `current` 使用 `atomic.Pointer` 保证并发读写安全
- `updates` channel 用于将更新通知给订阅者
- 通过 `hostChecker` 接口被调用：`ByName(name)` 和 `ByAddr(addr)`

### 2.4 加载与刷新机制

#### 初始加载
`NewHostsContainer()` 在创建时立即调用 `hc.refresh()` 完成首次加载。

#### 文件变化监听
独立 goroutine `handleEvents()` 监听文件系统事件：
- 接收到文件变化事件时调用 `refresh()` 重新解析
- 对比新旧数据：只有当 `!hc.current.Load().Equal(strg)` 时才更新并推送通知

#### refresh 流程 (`internal/aghnet/hostscontainer.go:234`)

```go
func (hc *HostsContainer) refresh(ctx context.Context) (err error) {
    // 1. 创建新的 Storage
    strg, _ := hostsfile.NewDefaultStorage(ctx, ...)
    
    // 2. 遍历所有匹配的文件，解析内容
    _, err = aghos.FileWalker(func(r io.Reader) (...) {
        return nil, true, hostsfile.Parse(ctx, strg, r, nil)
    }).Walk(hc.fsys, hc.patterns...)
    
    // 3. 对比并更新
    if !hc.current.Load().Equal(strg) {
        hc.current.Store(strg)
        hc.sendUpd(ctx, strg)
    }
    return nil
}
```

---

## 三、自定义 Hosts（DNS Rewrites）加载流程

AdGuard Home 支持两种形式的自定义 hosts 规则，底层机制完全不同：

### 3.1 形式一：Legacy Rewrites（旧版配置格式）

存储在 `filtering.Config.Rewrites []*LegacyRewrite`，通过 YAML 配置文件持久化。

#### 处理入口
`DNSFilter.processRewrites()` 函数（`internal/filtering/filtering.go:548`）：

```go
func (d *DNSFilter) CheckHost(host string, qtype uint16, setts *Settings) (...) {
    host = strings.ToLower(host)
    if setts.FilteringEnabled {
        res = d.processRewrites(host, qtype)
        if res.Reason == Rewritten {
            return res, nil  // 匹配成功立即返回
        }
    }
    // ...继续后续检查
}
```

#### Legacy Rewrites 特性
- **最高优先级**：在所有其他检查之前执行
- 支持 CNAME 链式解析，带循环检测（`handleRewriteLoop`）
- 支持通配符模式
- 通过 `findRewrites()` 进行模式匹配

### 3.2 形式二：$dnsrewrite 过滤规则

存储在过滤规则引擎中，与其他广告过滤规则统一管理。

#### 处理流程
在 `DNSFilter.matchHost()` 中（`internal/filtering/filtering.go:922`）：

```go
dnsres, matchedEngine := d.filteringEngine.MatchRequest(ufReq)

// DNS rewrites 优先于普通过滤规则检查
dnsRWRes := d.processDNSResultRewrites(dnsres, host)
if dnsRWRes.Reason != NotFilteredNotFound {
    return dnsRWRes, nil
}
```

#### DNS Rewrite Storage

专门的存储实现位于 `internal/filtering/rewrite/storage.go`：
- `DefaultStorage` 将 rewrite 条目转换为 urlfilter 规则格式
- 支持 CNAME 链解析和循环检测（`resolveCNAMEChain`）
- 按查询类型（A/AAAA/CNAME）过滤匹配结果（`collectDNSRewrites`）

#### DNS Rewrite 规则优先级（`processDNSRewrites`）

1. **CNAME 重写规则优先级最高**：遇到 `NewCNAME` 立即返回
2. **非成功 RCODE（如 REFUSED）**：立即返回
3. **成功 RCODE（NOERROR）**：累积多个 RR 值后返回

---

## 四、DNS 解析路径上的合并顺序

### 4.1 DNS 请求处理完整 Pipeline

每个 DNS 请求经过以下处理模块（`internal/dnsforward/requesthandler.go:33`），按顺序执行：

| 阶段 | 处理函数 | 说明 | 与 hosts 相关 |
|-----|---------|------|-------------|
| 1 | `processInitial` | 初始化上下文、客户端设置 | 否 |
| 2 | `processDDRQuery` | DDR（Discovery of Designated Resolvers） | 否 |
| 3 | `processDHCPHosts` | DHCP 分配的主机名解析 | DHCP hosts |
| 4 | `processDHCPAddrs` | DHCP 分配的 IP 反向解析（PTR） | DHCP hosts |
| 5 | **`processFilteringBeforeRequest`** | **核心过滤阶段** | **所有 hosts 检查** |
| 6 | `processUpstream` | 转发到上游 DNS | etcHosts 参与 bootstrap |
| 7 | `processFilteringAfterResponse` | 响应后过滤 | 否 |
| 8 | `ipset.process` | ipset 处理 | 否 |
| 9 | `processQueryLogsAndStats` | 日志与统计 | 否 |

### 4.2 核心过滤阶段（CheckHost）详解

`processFilteringBeforeRequest` → `filterDNSRequest` → `DNSFilter.CheckHost`

`CheckHost` 中的匹配顺序（`internal/filtering/filtering.go:505`）：

```
CheckHost(host, qtype, setts)
│
├─ [1] processRewrites()
│   └─ Legacy DNS Rewrites (config.Rewrites)
│      → Reason: Rewritten
│
└─ [2] hostCheckers 顺序遍历 (filtering.go:994)
    │
    ├─ [2.1] matchSysHosts()
    │   └─ 系统 /etc/hosts (d.conf.EtcHosts)
    │      → Reason: RewrittenAutoHosts
    │
    ├─ [2.2] matchHost()
    │   ├─ Allowlist 检查 (白名单优先)
    │   ├─ $dnsrewrite 规则匹配
    │   │   → Reason: RewrittenRule
    │   ├─ HostRulesV4/V6 匹配
    │   └─ NetworkRule 匹配
    │      → Reason: FilteredBlockList / NotFilteredAllowList
    │
    ├─ [2.3] matchBlockedServicesRules()
    │   └─ 阻止服务规则
    │      → Reason: FilteredBlockedService
    │
    ├─ [2.4] checkSafeBrowsing()
    │   └─ 安全浏览（恶意域名）
    │      → Reason: FilteredSafeBrowsing
    │
    ├─ [2.5] checkParental()
    │   └─ 家长控制
    │      → Reason: FilteredParental
    │
    └─ [2.6] checkSafeSearch()
        └─ 安全搜索重写
           → Reason: FilteredSafeSearch
```

**关键原则**：**先匹配先返回**。一旦某个检查器返回 `Reason.Matched()` 为 true，后续检查器不再执行。

### 4.3 各 Reason 的 Matched 判断

```go
// NotFilteredNotFound:   false (默认值，未匹配)
// NotFilteredAllowList:  true  (显式放行)
// NotFilteredError:      false
// FilteredBlockList:     true
// FilteredSafeBrowsing:  true
// FilteredParental:      true
// FilteredInvalid:       true
// FilteredSafeSearch:    true
// FilteredBlockedService:true
// Rewritten:             true  (Legacy Rewrites)
// RewrittenAutoHosts:    true  (系统 hosts)
// RewrittenRule:         true  ($dnsrewrite 规则)
```

### 4.4 Bootstrap Resolver 路径中的 etcHosts

系统 hosts 在另一个层面也参与解析：**上游 DNS 服务器域名的 bootstrap 解析**。

在 `newBootstrap()` 中（`internal/dnsforward/upstreams.go:27`）：

```go
func newBootstrap(addrs []string, etcHosts upstream.Resolver, opts *upstream.Options) (...) {
    // ...解析 bootstrap DNS 服务器地址...
    
    var parallel upstream.ParallelResolver
    for _, b := range boots {
        parallel = append(parallel, upstream.NewCachingResolver(b))
    }
    
    // etcHosts 作为 ConsequentResolver 的第一个解析器
    if etcHosts != nil {
        r = upstream.ConsequentResolver{etcHosts, parallel}
    } else {
        r = parallel
    }
    return r, boots, nil
}
```

`upstream.ConsequentResolver` 的语义是**顺序尝试**：
1. 先调用 `etcHosts` 解析
2. 如果 `etcHosts` 返回结果，则直接使用
3. 否则回退到 `parallel`（并行查询所有 bootstrap DNS）

---

## 五、结果类型与处理分支

### 5.1 filterDNSRequest 中的结果分发

在 `internal/dnsforward/filter.go:63`：

```go
switch res.Reason {
case FilteredSafeSearch, Rewritten:
    // SafeSearch 和 Legacy Rewrites: 生成 CNAME + IP 响应
    pctx.Res = s.getCNAMEWithIPs(ctx, req, res.IPList, res.CanonName)

case RewrittenAutoHosts, RewrittenRule:
    // 系统 hosts 和 $dnsrewrite 规则: 构造完整 DNS 响应
    // 包含 A/AAAA/PTR 等多类型记录
    if err = s.filterDNSRewrite(ctx, req, res, pctx); err != nil {
        return nil, err
    }
}
```

### 5.2 系统 hosts 支持的查询类型

`matchSysHosts` → `hostsRewrites`（`internal/filtering/hosts.go:46`）支持：

| 查询类型 | 处理方式 |
|---------|---------|
| `dns.TypeA` | 返回匹配的 IPv4 地址 |
| `dns.TypeAAAA` | 返回匹配的 IPv6 地址 |
| `dns.TypePTR` | 通过 IP 反查主机名 |
| 其他类型 | 不匹配 |

### 5.3 hostsRewrites 返回的规则标识

系统 hosts 匹配到的规则带有特殊的 FilterListID：

```go
rls = append(rls, &ResultRule{
    Text:         fmt.Sprintf("%s %s", addr, host),
    FilterListID: rulelist.APIIDEtcHosts,  // 标识为系统 hosts
})
```

---

## 六、关键数据流图示

### 6.1 系统 hosts 数据流

```
/etc/hosts 文件
    │
    ▼
aghos.FileWalker + hostsfile.Parse
    │
    ▼
hostsfile.DefaultStorage (name→addrs, addr→names 双向索引)
    │
    ├─► atomic.Pointer 存储 (HostsContainer.current)
    │      │
    │      ├─► matchSysHosts() 路径 (DNS 过滤阶段)
    │      │
    │      └─► upstream.NewHostsResolver() 路径
    │             │
    │             └─► ConsequentResolver (bootstrap 阶段)
    │
    └─► aghos.FSWatcher 事件
           │
           ▼
        refresh() 重新加载
```

### 6.2 DNS 请求中 hosts 匹配决策树

```
DNS 请求到达
    │
    ▼
processFilteringBeforeRequest
    │
    ▼
filterDNSRequest → DNSFilter.CheckHost()
    │
    ├─ [1] Legacy Rewrites? ──是──► 返回 Rewritten
    │        │
    │        否
    │        ▼
    ├─ [2.1] 系统 /etc/hosts? ──是──► 返回 RewrittenAutoHosts
    │        │
    │        否
    │        ▼
    ├─ [2.2] $dnsrewrite 规则? ──是──► 返回 RewrittenRule
    │        │
    │        否
    │        ▼
    ├─ [2.2] 过滤规则匹配? ──是──► 返回 FilteredBlockList / NotFilteredAllowList
    │        │
    │        否
    │        ▼
    ├─ [后续检查...]
    │
    ▼
都未匹配 ──► processUpstream (etcHosts 参与 bootstrap 解析)
```

---

## 七、核心文件索引

| 文件路径 | 核心职责 |
|---------|---------|
| `internal/home/home.go:278` | `setupHostsContainer()` - 系统 hosts 初始化 |
| `internal/aghnet/hostscontainer.go` | `HostsContainer` - 系统 hosts 存储与监视 |
| `internal/filtering/hosts.go` | `matchSysHosts()` - 系统 hosts 匹配逻辑 |
| `internal/filtering/filtering.go:505` | `CheckHost()` - 总匹配入口与优先级控制 |
| `internal/filtering/filtering.go:994` | `hostCheckers` 初始化顺序定义 |
| `internal/filtering/filtering.go:548` | `processRewrites()` - Legacy Rewrites 处理 |
| `internal/filtering/dnsrewrite.go` | `processDNSRewrites()` - $dnsrewrite 规则处理 |
| `internal/filtering/rewrite/storage.go` | DNS Rewrite 规则存储与匹配引擎 |
| `internal/filtering/reason.go` | 匹配原因枚举与优先级语义 |
| `internal/dnsforward/requesthandler.go` | DNS 请求处理 Pipeline 定义 |
| `internal/dnsforward/filter.go` | `filterDNSRequest()` - 过滤结果分发 |
| `internal/dnsforward/upstreams.go:27` | `newBootstrap()` - etcHosts 参与 bootstrap |
| `internal/dnsforward/dnsforward.go:238` | etcHosts 包装为 `upstream.Resolver` |

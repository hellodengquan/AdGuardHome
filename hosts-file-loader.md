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

---

## 八、域名冲突时的优先级日志行为

### 8.1 冲突处理机制：先匹配先返回，静默覆盖

当自定义 hosts（Legacy Rewrites / $dnsrewrite 规则）与系统 `/etc/hosts` 中同一域名出现冲突时，**代码层面没有任何显式的冲突检测或告警日志**。

其核心原因是 `DNSFilter.CheckHost()` 的设计：**短路求值 + 顺序优先**（`internal/filtering/filtering.go:505`）：

```go
// [1] Legacy Rewrites —— 最先检查，匹配即返回
if setts.FilteringEnabled {
    res = d.processRewrites(host, qtype)
    if res.Reason == Rewritten {
        return res, nil  // 命中后，系统 hosts 和 $dnsrewrite 根本不会执行
    }
}

// [2] hostCheckers 顺序遍历
for _, hc := range d.hostCheckers {
    res, err = hc.check(host, qtype, setts)
    // ...
    if res.Reason.Matched() {
        return res, nil  // 命中即返回，后续检查器不再执行
    }
}
```

这种模式下：
- 如果 Legacy Rewrites 命中 → 系统 hosts 匹配逻辑 **不会被调用**
- 如果系统 hosts 命中 → `$dnsrewrite` 规则匹配逻辑 **不会被调用**
- 不存在"两条来源都匹配然后比较优先级"的分支，因此**没有冲突检测点**

### 8.2 现有日志记录情况

全代码库搜索 `conflict`、`duplicate`、`overwrite`、`warn.*host` 等关键字，仅发现以下与 hosts 无关的结果：

| 位置 | 内容 | 与 hosts 冲突的关系 |
|-----|------|-------------------|
| `internal/filtering/rewrite/storage.go:203` | `// TODO(d.kolyshev): Handle duplicate items.` | **唯一相关 TODO**：表示 $dnsrewrite 规则重复项处理是未实现的功能 |
| `internal/filtering/idgenerator.go:69` | `"filter has duplicate id; reassigning"` | 过滤列表 ID 去重，与 hosts 无关 |
| `internal/filtering/filtering.go:1051` | `deduplicateFilters()` | 过滤列表去重，与 hosts 规则无关 |

### 8.3 Query Log 中的 Reason 标识

虽然没有冲突告警，但**每次匹配都会在 Query Log 中记录 `Reason` 字段**，可以间接推断命中了哪一条来源（`internal/querylog/entry.go` 通过 `dctx.result.Reason` 写入）：

| Reason 枚举值 | Query Log 字符串 | 对应来源 |
|--------------|-----------------|---------|
| `Rewritten` | `"Rewrite"` | Legacy DNS Rewrites |
| `RewrittenAutoHosts` | `"RewriteEtcHosts"` | 系统 `/etc/hosts` |
| `RewrittenRule` | `"RewriteRule"` | `$dnsrewrite` 过滤规则 |

在 `internal/filtering/reason.go:75`：
```go
Reason.String() map:
    Rewritten:          "Rewrite"
    RewrittenAutoHosts: "RewriteEtcHosts"
    RewrittenRule:      "RewriteRule"
```

**结论**：
- ✅ 没有优先级冲突的 warning/error 日志
- ✅ 冲突解决完全依赖匹配顺序（先匹配先返回）
- ✅ 通过 Query Log 中的 `Rewrite` / `RewriteEtcHosts` / `RewriteRule` 标识可事后追溯命中来源
- ✅ $dnsrewrite 存储层有 TODO 注释标注 duplicate 处理未实现

---

## 九、Hosts 文件热更新（fsnotify）解析失败的回滚行为

### 9.1 refresh() 的错误处理分析

`HostsContainer.refresh()` 函数（`internal/aghnet/hostscontainer.go:234`）是热更新的核心实现：

```go
func (hc *HostsContainer) refresh(ctx context.Context) (err error) {
    hc.logger.DebugContext(ctx, "refreshing")

    // 1. 创建全新的空 Storage（与旧版本完全独立）
    strg, _ := hostsfile.NewDefaultStorage(ctx, &hostsfile.DefaultStorageConfig{
        Logger: hc.logger,
    })

    // 2. 遍历所有匹配文件并解析，错误直接向上返回
    _, err = aghos.FileWalker(func(r io.Reader) (patterns []string, cont bool, err error) {
        return nil, true, hostsfile.Parse(ctx, strg, r, nil)
    }).Walk(hc.fsys, hc.patterns...)
    if err != nil {
        // Don't wrap the error since it's informative enough as is.
        return err  // ← 关键点：直接 return，不执行 Store
    }

    // 3. 对比新旧数据——只有解析成功才会走到这里
    if !hc.current.Load().Equal(strg) {
        hc.current.Store(strg)         // 原子替换
        hc.sendUpd(ctx, strg)
    }

    return nil
}
```

### 9.2 aghos.FileWalker.Walk 的错误传播路径

`internal/aghos/filewalker.go:87`：

```go
func (fw FileWalker) Walk(fsys fs.FS, initial ...string) (ok bool, err error) {
    // ...
    for i := 0; i < len(src); i++ {
        patterns, cont, err = checkFile(fsys, fw, src[i])
        if err != nil {
            return false, err  // ← 任何一个文件解析失败即终止整个 Walk 并返回 error
        }
        // ...
    }
    return false, nil
}
```

### 9.3 handleEvents() 中的错误日志记录

`internal/aghnet/hostscontainer.go:183`：

```go
func (hc *HostsContainer) handleEvents(ctx context.Context) {
    for {
        select {
        case _, ok := <-hc.watcher.Events():
            if !ok {
                hc.logger.DebugContext(ctx, "watcher events channel closed")
                return
            }
            if err := hc.refresh(ctx); err != nil {
                // ← 关键点：只记录 ERROR 日志，不做额外处理
                hc.logger.ErrorContext(ctx, "refreshing", slogutil.KeyError, err)
            }
        case <-ctx.Done():
            return
        }
    }
}
```

### 9.4 回滚结论

**新版 hosts 文件解析失败时，自动保留旧版本生效。** 这是由以下代码特性共同保证的：

1. **新版本存储对象完全独立构建**：`hostsfile.NewDefaultStorage()` 创建全新 `strg`，与 `hc.current.Load()` 指向的旧对象互不干扰
2. **错误提前返回**：`FileWalker.Walk()` 返回 error → `refresh()` 提前 `return err` → **不会执行** `hc.current.Store(strg)`
3. **原子指针替换**：即使走到 Store，`atomic.Pointer.Store()` 也是原子操作，不存在"半更新"状态
4. **调用方只记日志不干预**：`handleEvents()` 捕获 error 后只写 `ErrorContext` 日志，不尝试恢复或清除

**行为总结表**：

| 场景 | `hc.current` 状态 | 日志 |
|-----|-------------------|------|
| 文件正常且内容有变化 | 原子替换为新版本 | Debug "refreshing" |
| 文件正常但内容无变化 | 保持旧版本（Equal 跳过） | Debug "refreshing" |
| 第 N 个文件解析失败 | **保持旧版本完全不变** | Error "refreshing" + 具体 err |
| 文件被删除（fs.ErrNotExist） | 保持旧版本（checkFile 中特殊处理为 nil, true, nil） | 无错误日志 |

注意：**部分成功不存在**——FileWalker 遇到任何一个文件的任何一行解析错误就整体终止，已解析入 `strg` 的部分条目会被直接丢弃。

---

## 十、Hosts 文件超大规模（1M 条目以上）的内存占用与查询性能

### 10.1 数据结构：双向 Map 索引

系统 hosts 的底层存储是 `hostsfile.DefaultStorage`（来自 `github.com/AdguardTeam/golibs/hostsfile`），从 AdGuard Home 调用方式可以反推其内部结构：

```go
// ByAddr 通过 IP 反查主机名
func (hc *HostsContainer) ByAddr(addr netip.Addr) (names []string) {
    return hc.current.Load().ByAddr(addr)
}

// ByName 通过主机名查 IP
func (hc *HostsContainer) ByName(name string) (addrs []netip.Addr) {
    return hc.current.Load().ByName(name)
}

// Equal 比较两个 Storage 是否内容相同
hc.current.Load().Equal(strg)

// Parse 流式解析并写入 Storage
hostsfile.Parse(ctx, strg, r, nil)
```

因此内部至少维护了两张哈希表：
- `map[string][]netip.Addr` —— 主机名 → IP 列表（正向索引）
- `map[netip.Addr][]string` —— IP → 主机名列表（反向索引，用于 PTR 查询）

### 10.2 单条记录的内存开销估算

以标准 hosts 行 `127.0.0.1 localhost` 为例：

| 数据成员 | 类型 | 估算大小 |
|---------|------|---------|
| 主机名 `localhost` | Go `string` (16 字节 header + 实际字符) | ~16 + 9 = 25 B |
| IPv4 地址 | `netip.Addr` (24 字节结构体) | 24 B |
| map bucket 开销 | Go `map` 每个 entry 约 48 B overhead | ~48 B |
| slice header（多值时）| `[]netip.Addr` / `[]string` (24 B) | 24 B |
| Record 结构体（Source 等元数据） | hostsfile.Record 中额外存储 Source 文件名等 | ~32 B |

**每一条 hosts 记录双向索引的综合内存开销：约 150–250 字节。**

### 10.3 1M 条目的内存估算

```
1,000,000 条目 × 200 B/条目 ≈ 200 MB 原始数据
+ Go map 扩容预留空间（通常装载因子 65%）→ ~300 MB
+ hostsfile.Record 对象本身 → 额外 +100~200 MB
总计：约 400–600 MB 内存占用
```

### 10.4 查询性能特征

#### 10.4.1 系统 hosts 查询路径（`matchSysHosts`）

`internal/filtering/hosts.go:93`：
```go
addrs := hs.ByName(host)  // map[string][]netip.Addr 哈希查找
```

- **算法复杂度**：O(1) 平均哈希表查找
- **典型耗时**：< 1µs（纯内存哈希查找，无 IO）
- **并发安全**：`atomic.Pointer` 读无锁，仅替换时有一次原子写
- **无缓存层**：每次查询直接走 map，依赖 CPU L1/L2 Cache 命中

#### 10.4.2 Legacy Rewrites 查询路径（`processRewrites`）

`internal/filtering/filtering.go:558`：
```go
rewrites, matched := findRewrites(d.conf.Rewrites, host, qtype)
```

`findRewrites` 内部是**线性扫描** `[]*LegacyRewrite`（支持通配符展开）：
- **算法复杂度**：O(N)，N 为 Legacy Rewrites 数量
- **典型场景**：用户自定义 Rewrites 数量通常 < 1000，因此 < 100µs
- **1M 条目的问题**：如果把 1M 条塞进 Legacy Rewrites，**每次查询都是 O(1M) 的线性扫描，会导致严重的性能退化**——这也是 Legacy Rewrites 仅用于小规模用户配置、不适合大规模 hosts 列表的根本原因

#### 10.4.3 $dnsrewrite 规则查询路径（`matchHost` → `filteringEngine.MatchRequest`）

使用 `github.com/AdguardTeam/urlfilter` 引擎，内部是优化过的规则索引结构：
- 支持 `$dnsrewrite` 修饰符的规则被单独归类到 DNS 重写规则集
- 典型查询性能参考 Benchmark（同项目 `safesearch` 基准为 **~1.6µs**，`rulelist.Parser.Parse` 为 **~54ns/条**）
- 1M 条 $dnsrewrite 规则的内存开销比 hostsfile.DefaultStorage **更高**，因为 urlfilter 的 NetworkRule 结构包含大量修饰符字段

### 10.5 热更新期间的性能表现

`refresh()` 执行时：

```go
// 全量重新解析所有文件
_, err = aghos.FileWalker(func(r io.Reader) (patterns []string, cont bool, err error) {
    return nil, true, hostsfile.Parse(ctx, strg, r, nil)
}).Walk(hc.fsys, hc.patterns...)
```

- **解析方式**：流式 `io.Reader` + `bufio.Scanner` 逐行解析（注释中提到"Prefer using bufio.Scanner to read the r since the input is not limited"）
- **1M 行解析耗时**：预估 100–500ms（取决于 CPU，纯字符串处理无 IO 阻塞）
- **对查询的影响**：解析期间 `hc.current` 仍指向旧 Storage，**查询完全不受影响**；只有最后一步 `atomic.Pointer.Store()` 是一次原子写，暂停时间 < 100ns
- **GC 压力**：旧 Storage 被替换后成为垃圾，1M 条目约 500MB 对象触发一次较大的 GC 周期

### 10.6 性能对比总结表

| 维度 | 系统 hosts (DefaultStorage) | Legacy Rewrites | $dnsrewrite 规则 |
|-----|---------------------------|----------------|-----------------|
| 索引结构 | `map[string][]netip.Addr` + `map[netip.Addr][]string` | `[]*LegacyRewrite` 切片线性扫描 | urlfilter 规则引擎（多索引） |
| 查询复杂度 | O(1) 平均 | O(N) | O(1)~O(log N) 取决于规则类型 |
| 1M 条内存 | ~400–600 MB | 极高（且查询不可用） | ~600–1000 MB |
| 单次查询 | < 1µs | N=1M 时秒级不可用 | ~2–10 µs |
| 并发读写 | `atomic.Pointer` 无锁读 | `confMu.RLock()` 读写锁 | `confMu.RLock()` 读写锁 |
| 适用场景 | 操作系统级 hosts（通常 < 100 条） | 用户小规模重写（< 1000 条） | 订阅过滤列表（百万级规则） |
| 热更新方式 | 全量重新解析 + 原子指针替换 | 全量重新加载配置 | 过滤列表刷新 |

### 10.7 代码中的相关 TODO 与已知限制

| 位置 | 内容 | 含义 |
|-----|------|------|
| `internal/aghnet/hostscontainer.go:233` | `TODO(e.burkov): Accept a parameter to specify the files to refresh.` | 目前刷新是全量所有文件，不支持单文件增量刷新，1M 条时每次都要全部重新解析 |
| `internal/aghnet/hostscontainer.go:250` | `TODO(e.burkov): Serialize updates using [time.Time].` | 更新通知没有时间戳，无法判断新旧顺序 |
| `internal/filtering/rewrite/storage.go:203` | `TODO(d.kolyshev): Handle duplicate items.` | $dnsrewrite 重复项未处理 |

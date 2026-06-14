# AdGuardHome 过滤规则：从订阅文本到实时匹配的完整处理流程

## 0. 整体架构概览

AdGuardHome 的过滤规则系统采用"文本加载 → 解析清洗 → 编译索引 → 实时匹配"的四阶段流水线。系统内部存在两套并行的引擎实现：

| 组件 | 老系统（DNSFilter） | 新系统（rulelist.Storage） |
|---|---|---|
| 入口 | `filtering.DNSFilter` | `rulelist.Storage` |
| 核心引擎 | `urlfilter.DNSEngine` × 2（block/allow） | `rulelist.Engine` × 2 + `rulelist.TextEngine` |
| 使用场景 | DNS 主过滤流程 | 正在逐步迁移中 |

本文档以**老系统（DNSFilter）**为主线进行梳理，因为它是当前 DNS 请求实际流经的路径。

---

## 1. 第一阶段：规则订阅与加载（文本输入）

### 1.1 规则来源分类

规则文本从 6 种不同来源进入系统：

| 来源类型 | 数据结构 | 配置位置 |
|---|---|---|
| 远程 URL 订阅（黑名单） | `[]FilterYAML` → `Config.Filters` | `AdGuardHome.yaml` / HTTP API |
| 远程 URL 订阅（白名单） | `[]FilterYAML` → `Config.WhitelistFilters` | `AdGuardHome.yaml` / HTTP API |
| 用户自定义规则 | `[]string` → `Config.UserRules` | Web 界面「自定义过滤规则」 |
| 阻止服务规则 | `map[string][]*rules.NetworkRule` | 硬编码于 `servicelist.go` |
| 系统 hosts 文件 | `hostsfile.Storage` → `Config.EtcHosts` | 操作系统 `/etc/hosts` |
| 传统 DNS Rewrite | `[]*LegacyRewrite` → `Config.Rewrites` | `AdGuardHome.yaml` |

### 1.2 启动时加载流程

**入口函数**：`filtering.New()` (`filtering.go:972`)

```
New(c *Config, blockFilters []Filter)
  │
  ├─ loadFilters(ctx, d.conf.Filters)          // 加载黑名单文件元数据
  │   └─ 对每个启用的 FilterYAML: load(ctx, flt)
  │       ├─ os.Open(fileName)                 // 打开 data/filters/{id}.txt
  │       ├─ rulelist.NewParser().Parse()      // 解析并统计规则数、校验和
  │       └─ 设置 RulesCount, checksum, LastUpdated
  │
  ├─ loadFilters(ctx, d.conf.WhitelistFilters) // 加载白名单（同上）
  │
  ├─ deduplicateFilters()                      // 按 URL 去重
  │
  └─ initFiltering(ctx, nil, blockFilters)     // 初始化匹配引擎（见第2阶段）
```

**关键代码**：`filter.go:223` - `loadFilters()` 遍历配置中的过滤器列表，对启用的过滤器调用 `load()` 从磁盘读取并解析文件元信息（规则数量、校验和、标题、修改时间），但此阶段**尚未**将规则内容编译进匹配引擎。

### 1.3 运行时添加过滤器（HTTP API）

**入口**：`handleFilteringAddURL()` (`http.go:65`)

```
POST /control/filtering/add_url
  │
  ├─ validateFilterURL(fj.URL)                 // 校验 URL 或本地路径（含安全模式匹配）
  ├─ filterExists(fj.URL)                      // 检查重复
  ├─ filt := FilterYAML{Enabled:true, ID:idGen.next()}
  └─ d.update(&filt)                           // 下载+解析（见 2.1）
```

### 1.4 定期自动刷新

**入口**：`updatesLoop()` (`filtering.go:1087`)

启动时在独立 goroutine 中运行，使用 `time.Timer` 驱动：

```
updatesLoop()
  ├─ 每 5s 检查一次（逐步退避至最长 1h）
  ├─ 收到 filtersInitializerChan 信号 → initFiltering()
  └─ 定时器触发 → periodicallyRefreshFilters()
       └─ tryRefreshFilters(block, allow, force)
            └─ refreshFiltersIntl()
                 ├─ refreshFiltersArray()  // 列出需要更新的过滤器
                 │    ├─ listsToUpdate()   // 按 FiltersUpdateIntervalHours 判断到期
                 │    ├─ updateFilterList() // 逐个执行 d.update()
                 │    └─ syncUpdatedFilters() // 同步更新时间/规则数
                 ├─ EnableFilters(false)   // 同步重建引擎
                 └─ removeOldFilterFile()  // 清理 .old 临时文件
```

---

## 2. 第二阶段：解析与编译（文本 → 可匹配结构）

### 2.1 文本清洗与预处理：`rulelist.Parser`

**位置**：`rulelist/parser.go`

无论是从 HTTP 下载还是从本地文件读取，原始文本首先经过 `Parser` 的清洗。

**核心方法**：`Parse(dst io.Writer, src io.Reader, buf []byte)` (`parser.go:49`)

```
输入流 (src)
  │
  ▼
bufio.Scanner（逐行扫描，缓冲可扩大到 bufio.MaxScanTokenSize）
  │
  ├─ 第1行检测：isHTMLLine() → 若是 <html> 或 <!doctype 开头，返回 ErrHTML
  │
  └─ 逐行 processLine(line, lineNum):
       │
       ├─ bytes.TrimSpace(line) → trimmed
       │
       ├─ titleFound=false 时：parseLineTitle(trimmed)
       │    ├─ 空行或以 # 开头 → 跳过（注释）
       │    ├─ 以 ! 开头：
       │    │    ├─ 匹配 "! Title: " → 提取标题，设置 p.titleFound=true
       │    │    └─ 其他 ! 开头注释 → 跳过
       │    └─ 普通内容行 → 进入规则判定
       │
       ├─ titleFound=true 时：parseLine(trimmed)
       │    ├─ 空行 / # 开头 / ! 开头 → 跳过（注释）
       │    └─ 扫描每个字节：likelyBinary() 检测非打印字符 → 发现则报错
       │
       ├─ 通过判定后：
       │    ├─ p.rulesCount++
       │    ├─ p.checksum = CRC32-IEEE(trimmed)   // 增量计算
       │    └─ dst.Write(trimmed + '\n')          // 写入清理后的内容
       │
       └─ 异常：发现 HTML / 二进制字符 → 立即终止并返回错误
```

**输出**：`*ParseResult`
- `Title`：从 `! Title: xxx` 提取的列表名称
- `RulesCount`：有效规则行数（排除注释、空行）
- `BytesWritten`：写入 dst 的字节数
- `Checksum`：有效规则行的 CRC-32（IEEE 表）校验和

### 2.2 远程订阅（HTTP）更新流程

**入口**：`updateIntl()` (`filter.go:501`)

```
updateIntl(ctx, flt)
  │
  ├─ tmpFile := NewPendingFile(flt.Path(DataDir))
  │    // 临时文件路径：data/filters/{id}.txt.tmp（原子替换）
  │
  ├─ URL 是本地绝对路径？
  │    ├─ 是 → readFromFile(tmpFile, path)
  │    │         ├─ 安全校验：pathMatchesAny(safeFSPatterns, path)
  │    │         └─ Parser.Parse(tmpFile, file, buf)
  │    └─ 否 → readFromHTTP(tmpFile, urlStr)
  │              ├─ HTTPClient.Get(urlStr)
  │              ├─ 校验 resp.StatusCode == 200
  │              ├─ LimitReader(resp.Body, MaxHTTPSize)
  │              └─ Parser.Parse(tmpFile, body, buf)
  │
  ├─ 比较新旧 Checksum → 决定是否真正更新
  │
  └─ finalizeUpdate():
       ├─ 无变化 → tmpFile.Cleanup()（删除临时文件），仅 Chtimes 更新 mtime
       └─ 有变化 → tmpFile.CloseReplace()（原子重命名 .tmp → .txt）
                       更新 flt.Name/RulesCount/Checksum
```

### 2.3 从 Filter 到 `filterlist.Interface`

**函数**：`newRuleStorage(filters []Filter)` (`filtering.go:673`)

这是从"已下载的规则文件"到"urlfilter 可识别的规则列表"的转换层。

```
newRuleStorage(filters)
  │
  └─ 对每个 Filter: ruleListFromFilter(f)
       │
       ├─ f.Data 非空 → 内存字节模式
       │    └─ filterlist.NewBytes(&BytesConfig{
       │           ID:             f.ID,
       │           RulesText:      f.Data,
       │           IgnoreCosmetic: true,   // DNS 场景忽略 cosmetic 规则
       │         })
       │
       ├─ f.FilePath 为空 → skip=true（忽略）
       │
       ├─ Windows 平台 → 总是读入内存
       │    └─ os.ReadFile(FilePath) → NewBytes(...)
       │         // 原因：Windows 下文件被锁定时难以覆盖更新
       │
       └─ Unix/Linux/macOS → 文件映射模式
            └─ filterlist.NewFile(&FileConfig{
                   ID:             f.ID,
                   Path:           f.FilePath,
                   IgnoreCosmetic: true,
               })
                 // mmap 方式，节省内存，适合大规则集
```

### 2.4 核心编译：`initFiltering()`

**位置**：`filtering.go:746` —— 这是整个规则系统最关键的"激活"函数。

```
initFiltering(ctx, allowFilters, blockFilters)
  │
  ├─ 第1步：构建 block 侧 RuleStorage
  │    rulesStorage, _ := newRuleStorage(blockFilters)
  │    // filterlist.RuleStorage 内部会：
  │    //   a. 遍历所有 filterlist.Interface
  │    //   b. 逐行读取并调用 urlfilter 的规则解析器
  │    //   c. 将规则分类：
  │    //      - NetworkRule（Adblock 语法）→ 编译为 NFA/DFA 或哈希索引
  │    //      - HostRule（/etc/hosts 语法）→ 存入域名→IP 的映射
  │    //      - CosmeticRule → 被 IgnoreCosmetic 丢弃
  │
  ├─ 第2步：构建 allow 侧 RuleStorage（同上）
  │    rulesStorageAllow, _ := newRuleStorage(allowFilters)
  │
  ├─ 第3步：实例化 DNS 匹配引擎
  │    filteringEngine      = urlfilter.NewDNSEngine(rulesStorage)
  │    filteringEngineAllow = urlfilter.NewDNSEngine(rulesStorageAllow)
  │    // DNSEngine 内部完成：
  │    //   - 构建短路查找表（如精确域名 → 规则切片的 map）
  │    //   - 构建后缀树 / 正则表达式编译
  │    //   - 预计算所有 $client、$denyallow 等修饰符的索引
  │
  └─ 第4步：原子替换（engineLock 写锁保护）
       engineLock.Lock()
       ├─ d.reset(ctx)         // 关闭旧的 storage，释放资源
       ├─ d.rulesStorage = rulesStorage
       ├─ d.filteringEngine = filteringEngine
       ├─ d.rulesStorageAllow = rulesStorageAllow
       └─ d.filteringEngineAllow = filteringEngineAllow
       engineLock.Unlock()

       debug.FreeOSMemory()    // 立即归还内存给 OS
```

**并发模型**：`setFilters()` (`filtering.go:359`) 支持 `async=true` 模式——通过 `filtersInitializerChan` 将编译任务投递到后台 goroutine，编译期间旧引擎继续服务请求，完成后原子切换，实现**零停机更新**。

### 2.5 用户自定义规则的特殊处理

**位置**：`enableFiltersLocked()` (`filter.go:672`)

用户自定义规则（`Config.UserRules`）不经过文件系统，而是直接拼接为内存字节：

```go
filters := make([]Filter, 1, ...)
filters[0] = Filter{
    ID:   rulelist.IDCustom,   // = 0
    Data: []byte(strings.Join(d.conf.UserRules, "\n")),
}
```

然后 `IDCustom`（值为 0）这个 Filter 被追加到 `blockFilters` 列表最前面，参与 `newRuleStorage()` 的统一编译，因此**自定义规则优先级最高**（在同一引擎中，先加入的规则先匹配）。

---

## 3. 第三阶段：实时匹配（DNS 请求 → 匹配结果）

### 3.1 请求进入过滤系统的路径

**起点**：`dnsforward.Server.filterDNSRequest()` (`dnsforward/filter.go:28`)

每个 DNS 查询经过 `dnsforward` 代理层时，会执行以下调用链：

```
filterDNSRequest(ctx, l, dctx)
  │
  ├─ 从 dnsContext 提取：
  │    host  = strings.TrimSuffix(q.Name, ".")    // 去掉末尾的点
  │    qtype = q.Qtype                            // A / AAAA / CNAME / ...
  │    setts = clientRequestFilteringSettings(dctx)
  │
  └─ s.dnsFilter.CheckHost(host, qtype, setts)   // 进入 DNSFilter
```

### 3.2 主匹配入口：`CheckHost()`

**位置**：`filtering.go:505`

```
CheckHost(host, qtype, setts)
  │
  ├─ 前置：空 host 直接返回（如根域名 "." 查询）
  ├─ host = strings.ToLower(host)
  │
  ├─ 第0层：传统 Rewrite（若 FilteringEnabled）
  │    res := processRewrites(host, qtype)
  │    └─ 遍历 d.conf.Rewrites，支持 CNAME 链式重写，循环检测
  │    若 res.Reason == Rewritten → 立即返回（短路）
  │
  └─ 第1~N层：hostCheckers 流水线
       // 初始化于 filtering.go:994，按如下顺序排列：
       // [0] matchSysHosts            ← /etc/hosts
       // [1] matchHost                ← 核心规则引擎（block/allow）
       // [2] matchBlockedServicesRules← 阻止服务
       // [3] checkSafeBrowsing        ← 安全浏览（hash-prefix）
       // [4] checkParental            ← 家长控制（hash-prefix）
       // [5] checkSafeSearch          ← 安全搜索
       │
       └─ 按顺序遍历 hostCheckers:
            res, err := hc.check(host, qtype, setts)
            if res.Reason.Matched() {  // 非 NotFilteredNotFound 即视为命中
                return res, nil         // 命中则短路，不再走后续检查器
            }
       // 全部未命中 → 返回 Result{}
```

### 3.3 各 checker 的具体实现

#### 3.3.1 `[0] matchSysHosts` —— 系统 hosts 文件

**位置**：`hosts.go:18`

```
hostsRewrites(qtype, host, hs)
  │
  ├─ qtype == PTR:
  │    ├─ netutil.IPFromReversedAddr(host) → addr
  │    └─ hs.ByAddr(addr) → 所有反向解析的域名
  │
  └─ qtype == A or AAAA:
       ├─ hs.ByName(host) → []netip.Addr
       └─ 过滤出协议匹配的 IP（Is4 / Is6）
```

命中结果：`Reason = RewrittenAutoHosts`，`Rules[].FilterListID = APIIDEtcHosts (-1)`。

#### 3.3.2 `[1] matchHost` —— **核心规则引擎匹配**

**位置**：`filtering.go:884`

这是 Adblock 风格规则和 hosts 格式规则的实际匹配入口。

```
matchHost(host, rrtype, setts)
  │
  ├─ setts.FilteringEnabled == false → 跳过
  │
  ├─ 构造 urlfilter.DNSRequest:
  │    ufReq := &urlfilter.DNSRequest{
  │        Hostname:          host,
  │        ClientTags:        SortedSet(setts.ClientTags),    // $tag 修饰符
  │        ClientIP:          setts.ClientIP,                 // $client 修饰符
  │        ClientIdentifiers: SortedSet(setts.ClientName),    // $client 修饰符
  │        DNSType:           rrtype,                         // 规则中 $dnstype
  │    }
  │
  ├─ engineLock.RLock()   // 读锁，保证并发安全
  │   defer RUnlock()
  │
  ├─ 【Allowlist 优先匹配】
  │    if ProtectionEnabled && filteringEngineAllow != nil:
  │        dnsres, ok := filteringEngineAllow.MatchRequest(ufReq)
  │        if ok:
  │            // 白名单命中 → 放行，返回 NotFilteredAllowList
  │            return matchHostProcessAllowList(ctx, host, dnsres)
  │            // 注意：白名单匹配成功会短路整个 matchHost，
  │            //       不会再检查 blocklist
  │
  ├─ 【Blocklist 匹配】
  │    dnsres, matchedEngine := filteringEngine.MatchRequest(ufReq)
  │    // matchedEngine=true 表示至少一条规则命中
  │
  ├─ 先处理 DNS Rewrite（$dnsrewrite 修饰符）
  │    dnsRWRes := processDNSResultRewrites(dnsres, host)
  │    if dnsRWRes.Reason != NotFilteredNotFound:
  │        return dnsRWRes    // RewrittenRule，短路
  │    else if !matchedEngine:
  │        return Result{}     // 完全未命中
  │
  ├─ ProtectionEnabled == false → 不返回过滤结果，只处理 rewrite
  │
  └─ 【普通 Block / Host 规则命中处理】
       res = matchHostProcessDNSResult(rrtype, dnsres)
       │
       ├─ dnsres.NetworkRule != nil:    // Adblock 语法
       │    └─ Whitelist=true  → NotFilteredAllowList
       │       Whitelist=false → FilteredBlockList
       │
       ├─ qtype == A && dnsres.HostRulesV4 != nil:
       │    └─ FilteredBlockList，填充 res.Rules[i].IP
       │
       ├─ qtype == AAAA && dnsres.HostRulesV6 != nil:
       │    └─ FilteredBlockList，填充 res.Rules[i].IP
       │
       └─ 其他 qtype 但有 HostRules:
            └─ 取 HostRulesV4[0] 或 V6[0]，返回 FilteredBlockList
```

#### 3.3.3 `[2] matchBlockedServicesRules` —— 阻止服务

**位置**：`filtering.go:623`

匹配预编译的 `[]*rules.NetworkRule`（来源于 `servicelist.go` 中的服务定义）：

```
req := rules.NewRequestForHostname(host)
for _, s := range setts.ServicesRules:
    for _, rule := range s.Rules:
        if rule.Match(req):
            // 命中 → FilteredBlockedService，填充 ServiceName
```

注意：阻止服务规则不在主 `DNSEngine` 中，而是**独立匹配**，因此不受 allowlist 影响。

#### 3.3.4 `[3] checkSafeBrowsing` / `[4] checkParental` —— Hash Prefix

**位置**：`filtering.go:1138` / `1174`

不基于 urlfilter，而是调用 `hashprefix.Checker`（Mozilla Safe Browsing v4 协议风格的 SHA256 哈希前缀匹配）：

```go
block, err := d.safeBrowsingChecker.Check(host)
```

独立于规则列表，通过 HTTP API 实时查询或本地缓存比对。

#### 3.3.5 `[5] checkSafeSearch` —— 安全搜索

通过预定义的域名映射表，将搜索引擎域名重写为其安全搜索 CNAME。

### 3.4 DNS 响应的二次过滤

**位置**：`dnsforward.filterDNSResponse()` (`dnsforward/filter.go:116`)

即使请求本身未被过滤，**响应中的 Answer 部分**也会被逐一检查，防止 CNAME 链绕过过滤：

```
filterDNSResponse(ctx, l, dctx)
  │
  └─ 遍历 pctx.Res.Answer[i]:
       ├─ CNAME → a.Target 作为 host 检查
       ├─ A     → a.A.String() 作为 host 检查
       ├─ AAAA  → a.AAAA.String() 作为 host 检查
       └─ HTTPS → 遍历 SVCB IPv4/IPv6 Hint 逐一检查

       任一 RR 命中 IsFiltered → 替换整个响应为拦截响应
```

**典型场景**：`evil.com → CNAME → cdn.com`，若只过滤了 `evil.com`，用户直接请求 `cdn.com` 也能访问到恶意内容。响应二次过滤确保 `cdn.com` 若在黑名单中也被拦截。

### 3.5 匹配结果：`Result` 结构

**位置**：`result.go`

```go
type Result struct {
    DNSRewriteResult *DNSRewriteResult   // $dnsrewrite 规则的详细响应
    CanonName        string              // CNAME 重写目标
    ServiceName      string              // 阻止服务名
    IPList           []netip.Addr        // Rewrite 返回的 IP 列表
    Rules            []*ResultRule       // 命中的规则详情
    Reason           Reason              // 命中原因枚举
    IsFiltered       bool                // 是否拦截
}
```

`Reason` 枚举（`reason.go`）：

| 值 | 含义 |
|---|---|
| `NotFilteredNotFound` (0) | 未命中任何规则 |
| `NotFilteredAllowList` (1) | 被白名单放行 |
| `FilteredBlockList` (3) | 被黑名单规则拦截 |
| `FilteredSafeBrowsing` (4) | 安全浏览拦截 |
| `FilteredParental` (5) | 家长控制拦截 |
| `FilteredSafeSearch` (7) | 安全搜索重写 |
| `FilteredBlockedService` (8) | 阻止服务拦截 |
| `Rewritten` (9) | 传统 Rewrite 规则 |
| `RewrittenAutoHosts` (10) | /etc/hosts 重写 |
| `RewrittenRule` (11) | `$dnsrewrite` 规则重写 |

---

## 4. 关键数据结构关系图

```
用户配置 (YAML / HTTP API)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Config                                              │
│  ├─ Filters: []FilterYAML        (黑名单订阅列表)    │
│  ├─ WhitelistFilters: []FilterYAML (白名单订阅)      │
│  ├─ UserRules: []string          (自定义规则)        │
│  ├─ Rewrites: []*LegacyRewrite   (传统 Rewrite)      │
│  ├─ BlockedServices: *BlockedServices                │
│  └─ EtcHosts: hostsfile.Storage   (/etc/hosts)       │
└───────────┬─────────────────────────────────────────┘
            │  New() / EnableFilters()
            ▼
┌─────────────────────────────────────────────────────┐
│  DNSFilter                                           │
│                                                      │
│  hostCheckers pipeline:                              │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐  │
│  │matchSysHosts│ │ matchHost   │ │BlockedServices│  │
│  └─────────────┘ └──────┬──────┘ └──────────────┘  │
│                         │                            │
│          ┌──────────────┴──────────────┐            │
│          ▼                             ▼            │
│  filteringEngineAllow          filteringEngine       │
│  (urlfilter.DNSEngine)          (urlfilter.DNSEngine)│
│          │                             │            │
│          └──────────────┬──────────────┘            │
│                         │                            │
│                         ▼                            │
│              rulesStorageAllow + rulesStorage        │
│              (filterlist.RuleStorage)                │
│                         │                            │
│                         ▼                            │
│          ┌─────────────────────────────┐            │
│          │ filterlist.Interface × N    │            │
│          │  ├─ NewBytes (内存)          │            │
│          │  └─ NewFile  (mmap)          │            │
│          └─────────────────────────────┘            │
└───────────┬─────────────────────────────────────────┘
            │ CheckHost(host, qtype, setts)
            ▼
┌─────────────────────────────────────────────────────┐
│  dnsforward.Server                                   │
│  ├─ filterDNSRequest()   ← 请求进入时                │
│  └─ filterDNSResponse()  ← 响应返回前（二次检查）    │
└─────────────────────────────────────────────────────┘
```

---

## 5. 设计亮点与关键机制

### 5.1 零停机更新
- `async=true` 模式下，`initFiltering()` 在后台 goroutine 执行
- 新引擎构建完毕后通过 `engineLock.Lock()` 一次性原子替换
- 期间旧引擎持续服务，读取方无感知

### 5.2 内存优化
- **Unix 平台**：`filterlist.NewFile()` 使用 mmap，大规则集（几十万条）不占 RSS
- **Windows 平台**：退化为内存加载（避免文件锁问题）
- 更新后显式调用 `debug.FreeOSMemory()` 归还内存

### 5.3 完整性校验
- 每条规则行参与 CRC-32 增量计算
- 更新时比较新旧 checksum，无变化则跳过重新编译，仅更新 mtime

### 5.4 分层短路
匹配路径严格按"最便宜优先"排列：
1. 本地 hosts / Rewrite（O(1) 或 O(n) 小 n）
2. allowlist 引擎（命中即放行，跳过所有后续检查）
3. blocklist 引擎（核心匹配）
4. 阻止服务（网络规则预编译）
5. Safe Browsing / Parental（可能触发 HTTP 请求，放最后）

### 5.5 双向过滤
不仅过滤**请求域名**，还过滤**响应中所有 RR**（CNAME、A、AAAA、HTTPS hints），形成完整的闭环防护。

---

## 6. 关键文件索引

| 文件路径 | 职责 |
|---|---|
| `internal/filtering/filtering.go` | DNSFilter 核心结构体、CheckHost/matchHost、initFiltering |
| `internal/filtering/filter.go` | FilterYAML 加载/下载/更新/启用逻辑 |
| `internal/filtering/rulelist/parser.go` | 规则文本清洗（去注释、校验、CRC32） |
| `internal/filtering/rulelist/engine.go` | 新一代 Engine（尚未完全接入 DNS 主路径） |
| `internal/filtering/rulelist/storage.go` | 新一代 Storage（allow/block/custom 三合一） |
| `internal/filtering/rulelist/textengine.go` | 文本规则 → DNSEngine 的快捷封装 |
| `internal/filtering/rulelist/filter.go` | 新一代 Filter（URL/file 源、Refresh 方法） |
| `internal/filtering/hosts.go` | /etc/hosts 匹配实现 |
| `internal/filtering/blocked.go` | 阻止服务初始化与匹配 |
| `internal/filtering/result.go` | Result / ResultRule 数据结构 |
| `internal/filtering/reason.go` | Reason 枚举定义 |
| `internal/filtering/http.go` | HTTP API handlers（添加/更新/删除过滤器） |
| `internal/dnsforward/filter.go` | dnsforward 层的 filterDNSRequest / filterDNSResponse |

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

### 2.5 热加载机制与新旧产物切换的事务边界

#### 2.5.1 异步热加载的完整生命周期

热加载由 **生产者-消费者** 模式驱动，核心通道是 `filtersInitializerChan`（容量为 1 的缓冲 channel）：

```
[触发方]                           [消费方：updatesLoop goroutine]
     │                                     │
     ├─ setFilters(async=true)             ├─ 阻塞 select 等待
     │    ├─ filtersInitializerLock.Lock()  │
     │    ├─ 清空 channel 中未处理任务       │
     │    ├─ 投递 params 到 channel ────────▶ 收到 params
     │    └─ filtersInitializerLock.Unlock() │
     │                                     ├─ 调用 initFiltering()
     │                                     │    ├─ 构建新 RuleStorage + DNSEngine（耗时操作）
     │                                     │    └─ 原子替换（engineLock 写锁）
     │                                     └─ 继续 select 循环
```

**关键细节**：
- **去抖机制**：每次投递前清空 channel，确保多次快速触发只执行最后一次（避免频繁编译）
- **串行保证**：`filtersInitializerLock` 互斥锁 + channel 容量 1，确保同一时刻只有一个编译任务在途
- **失败容忍**：`initFiltering` 失败仅打错误日志，不影响正在运行的旧引擎

#### 2.5.2 事务边界：原子替换的临界点

`initFiltering()` 中的**第 4 步原子替换**是整个热加载唯一的事务边界：

```go
// 临界区开始（engineLock 写锁）
func() {
    d.engineLock.Lock()
    defer d.engineLock.Unlock()

    d.reset(ctx)              // ① 关闭旧 storage（释放资源）
    d.rulesStorage = rulesStorage          // ② 替换 block 侧 storage
    d.filteringEngine = filteringEngine    // ③ 替换 block 侧 engine
    d.rulesStorageAllow = rulesStorageAllow // ④ 替换 allow 侧 storage
    d.filteringEngineAllow = filteringEngineAllow // ⑤ 替换 allow 侧 engine
}()
// 临界区结束
```

**事务属性分析**：

| 特性 | 状态 | 说明 |
|---|---|---|
| **原子性** | ✅ 近似原子 | 5 个指针赋值在同一写锁内完成，外部读操作要么看到全部旧值，要么看到全部新值 |
| **一致性** | ⚠️ 最终一致 | `reset()` 关闭旧 storage 在前，若关闭过程中发生 panic，新值已写入但旧资源泄漏 |
| **隔离性** | ✅ 严格隔离 | 写锁持有期间，所有读操作（`engineLock.RLock()`）被阻塞 |
| **持久性** | ✅ 内存持久 | 替换完成后新引擎立即生效，配置变更通过 `ConfModifier` 持久化到磁盘 |

**读侧一致性保证**：`matchHost()` 中对 `engineLock.RLock()` 的持有覆盖了整个 `MatchRequest()` 调用过程，确保同一次查询使用的是同一版本的引擎实例，不会出现"半新半旧"的状态。

> **注意**：注释中提到 "Keep in mind that this lock must be held not just when calling Match() but also while using the rules returned by it"（`filtering.go:905`），意味着返回的 `*rules.Rule` 指针与 storage 生命周期绑定，引擎切换后若继续使用旧规则指针可能引发悬垂引用风险。

#### 2.5.3 同步 vs 异步模式对比

| 维度 | 同步模式 (`async=false`) | 异步模式 (`async=true`) |
|---|---|---|
| 调用方阻塞 | 是，等待编译完成 | 否，立即返回 |
| 调用线程 | 当前 goroutine | `updatesLoop` 后台 goroutine |
| 错误返回 | 直接返回 error | 仅日志记录，无返回值 |
| 适用场景 | 启动、单测 | 运行时刷新、HTTP API 触发 |
| 事务粒度 | 粗（整个编译过程阻塞调用方） | 细（仅指针替换时阻塞读方） |

### 2.6 用户自定义规则的特殊处理

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

#### 3.3.3 规则类型、优先级与冲突解决策略

`urlfilter.DNSEngine` 内部对规则进行了分类索引，不同类型的规则在匹配链上有严格的优先级顺序。当多条规则同时命中时，按以下优先级决出"最终生效规则"：

##### 第一级：规则大类优先级（引擎内部排序）

`MatchRequest()` 返回的 `*urlfilter.DNSResult` 中可能同时包含多种类型的命中结果，`matchHostProcessDNSResult()` 按如下顺序判定（先匹配到即返回）：

| 优先级 | 规则类型 | 对应字段 | 时间复杂度 | 说明 |
|---|---|---|---|---|
| 1 | NetworkRule（Adblock 通配/正则） | `dnsres.NetworkRule` | O(1) ~ O(n) | 仅返回 1 条"最高优先级"的网络规则 |
| 2 | HostRule V4（hosts 格式） | `dnsres.HostRulesV4` | O(1) 哈希查找 | 返回所有匹配 A 记录的 host 规则数组 |
| 3 | HostRule V6（hosts 格式） | `dnsres.HostRulesV6` | O(1) 哈希查找 | 返回所有匹配 AAAA 记录的 host 规则数组 |

> **核心逻辑**（`filtering.go:824`）：若 `NetworkRule != nil` 直接使用它；否则尝试 `HostRulesV4`；再否则尝试 `HostRulesV6`。即 **NetworkRule 优先级高于 HostRule**。

##### 第二级：NetworkRule 内部的优先级体系

在 Adblock 风格的 `NetworkRule` 中，当多条规则同时匹配同一域名时，urlfilter 内部按以下修饰符优先级决出"胜利者"（最终只有 1 条 NetworkRule 被返回）：

| 优先级 | 修饰符 / 特性 | 效果 | 代码证据 |
|---|---|---|---|
| 最高 | `$important` | 无视普通 allowlist，强制拦截（或强制放行） | `filtering_internal_test.go:264` 的测试用例 `importantRules` |
| 高 | `@@` 白名单（whitelist） | 同级别下白名单优先于黑名单 | `matchHostProcessAllowList` 独立引擎优先检查 |
| 中 | `$denyallow` | 对指定域名排除拦截（部分放行） | `servicelist.go:2456` 中 `$denyallow=wx.qq.com` |
| 中 | `$dnsrewrite` | DNS 重写规则 | `processDNSResultRewrites` 优先处理 |
| 低 | 普通拦截规则 | 默认优先级 | — |

**`$important` 的工作机制**：
- 普通白名单（`@@`）只能覆盖普通拦截规则
- 带 `$important` 的拦截规则可以"穿透"普通白名单
- 只有带 `$important` 的白名单才能覆盖带 `$important` 的拦截规则
- 测试验证（`filtering_internal_test.go:375-408`）：
  - 规则：`@@||example.org^` + `||test.example.org^$important`
  - 访问 `example.org` → 白名单生效（放行）
  - 访问 `test.example.org` → `$important` 拦截生效（阻断）

##### 第三级：DNS Rewrite 内部优先级

当多个 `$dnsrewrite` 规则同时命中时，`processDNSRewrites()`（`dnsrewrite.go:22`）按以下顺序短路返回：

| 优先级 | 重写类型 | 行为 |
|---|---|---|
| 1 | **错误码类**（NXDOMAIN / REFUSED 等 Rcode != Success） | 立即返回，最高优先级 |
| 2 | **CNAME 重写**（`NewCNAME`） | 立即返回，次高优先级 |
| 3 | **IP 重写**（A / AAAA 记录，Rcode = Success） | 累加所有匹配项，合并返回 |

代码证据：`dnsrewrite.go:30` 中 "NewCNAME rules have a higher priority than other rules"，以及 `dnsrewrite.go:49` 中 "RcodeRefused and other such codes have higher priority. Return immediately."

##### 第四级：跨引擎的优先级（allow vs block）

在 `matchHost()` 层面，两台独立引擎按如下顺序工作：

```
请求 → allowlist 引擎检查
        ├─ 命中 → 直接放行（短路），不查 blocklist
        └─ 未命中 → blocklist 引擎检查
                ├─ 命中 → 拦截
                └─ 未命中 → 放行
```

这意味着：**白名单引擎天然具有更高优先级**。一条 `@@` 规则只要命中，无论 blocklist 中有多少条拦截规则，都直接放行。

> 例外：`$important` 修饰符可以反转这一优先级（在 blocklist 侧的重要规则可以穿透 allowlist）。

##### 冲突解决的完整决策树

```
域名命中多条规则时：

① 先查 allowlist 引擎 → 命中 → 返回 NotFilteredAllowList（放行）
│                     ↘ 未命中
② 进入 blocklist 引擎
    ├─ 有 NetworkRule 命中？
    │    ├─ 是 → 检查是否 Whitelist + 是否 $important
    │    │      └─ 返回单条"最高优先级" NetworkRule
    │    └─ 否 → 检查 HostRules
    │           ├─ qtype=A 且有 HostRulesV4 → 返回数组
    │           └─ qtype=AAAA 且有 HostRulesV6 → 返回数组
    │
    └─ 在 processDNSRewrites 中进一步排序：
         ├─ 有 Rcode != Success → 立即返回（最高）
         ├─ 有 CNAME 重写 → 立即返回（次高）
         └─ 否则合并所有 IP 重写返回
```

#### 3.3.4 通配符规则与正则规则的性能差异

在 `DNSEngine` 内部，Adblock 风格规则根据模式复杂度被编译为不同的数据结构：

| 规则模式 | 示例 | 编译后结构 | 匹配复杂度 |
|---|---|---|---|
| **精确域名** | `||example.com^` | 哈希表（map[string][]Rule） | O(1) |
| **后缀通配** | `||*.example.com^` | 后缀 Trie（反向域名树） | O(k)，k = 域名段数 |
| **路径/参数通配** | `||example.com/ads*` | 前缀/子串自动机 | O(m)，m = 模式长度 |
| **正则表达式** | `/example\.com/\d+/` | 编译后的 NFA/DFA | O(n×m)，最坏情况 |

`*` 通配符规则在 urlfilter 中通常被**优化为子串匹配或前后缀匹配**，比完整正则快一个数量级。只有包含 `?`、`()`、`|` 等复杂语法的 `/regex/` 规则才会进入正则引擎。

#### 3.3.5 `[2] matchBlockedServicesRules` —— 阻止服务

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

#### 3.3.6 `[3] checkSafeBrowsing` / `[4] checkParental` —— Hash Prefix

**位置**：`filtering.go:1138` / `1174`

不基于 urlfilter，而是调用 `hashprefix.Checker`（Mozilla Safe Browsing v4 协议风格的 SHA256 哈希前缀匹配）：

```go
block, err := d.safeBrowsingChecker.Check(host)
```

独立于规则列表，通过 HTTP API 实时查询或本地缓存比对。

#### 3.3.7 `[5] checkSafeSearch` —— 安全搜索

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

## 6. 大规模规则下的性能与资源分析

### 6.1 千万级（10M）规则的内存占用估算

AdGuardHome 的规则系统在不同加载模式下内存表现差异巨大。以下基于主流规则集的统计特征（平均每条规则约 40~60 字节文本）进行估算。

#### 6.1.1 三种内存形态对比

| 内存形态 | 触发条件 | 10M 条规则估算占用 | 说明 |
|---|---|---|---|
| **磁盘文件（零内存）** | 仅 `loadFilters()` 阶段，尚未编译 | ~0 B | 只在内存中保留 Filter 元数据（ID、URL、RulesCount、checksum 等），每条 ~200 B，总计约 2 MB |
| **mmap 映射** | Unix 平台 `filterlist.NewFile()` 模式 | ~100 MB RSS + ~500 MB VSS | 规则文本由 OS 页缓存管理，应用层 RSS 很低；索引结构仍占堆内存 |
| **全内存加载** | Windows 平台 / `filterlist.NewBytes()` / 用户自定义规则 | ~600 MB ~ 1.2 GB | 规则文本 + 索引结构全部在堆上，GC 压力大 |

> **关键代码**：`filtering.go:704-720` —— `ruleListFromFilter()` 中根据平台和 Data 字段选择 mmap 或内存模式。

#### 6.1.2 内存构成拆解（以 10M 条 NetworkRule 为例）

```
总内存 ≈ 规则文本存储 + 索引结构 + 规则对象
        │
        ├─ 规则文本存储
        │    ├─ mmap 模式：≈ 500 MB（页缓存，不计入进程 RSS）
        │    └─ 内存模式：≈ 500 MB（[]byte，计入 RSS）
        │
        ├─ 索引结构（urlfilter 内部）
        │    ├─ 精确域名哈希表：约占 20%~30% 规则
        │    │    └─ map[string][]int → 每条键+值+切片开销 ≈ 150 B
        │    │    └─ 10M 中若 3M 是精确域名 → 约 450 MB（含扩容冗余）
        │    ├─ 后缀 Trie（域名树）：约占 40%~50% 规则
        │    │    └─ 每个 Trie 节点 ≈ 64 B（子节点 map + 规则切片指针）
        │    │    └─ 平均域名 3 段，节点数 ≈ 规则数 × 1.5
        │    │    └─ 5M 条后缀规则 → 约 7.5M 节点 → 约 480 MB
        │    ├─ 正则规则列表：约占 1%~5% 规则
        │    │    └─ 每条编译后正则 ≈ 1~5 KB（NFA 状态数）
        │    │    └─ 10 万条正则 → 约 100 ~ 500 MB
        │    └─ 修饰符索引（$client、$tag、$dnstype 等）
        │         └─ 约占总索引的 10% → 约 100 MB
        │
        └─ 规则对象（NetworkRule / HostRule）
             └─ 每条 NetworkRule ≈ 200 B（字符串切片 + 修饰符位域 + 指针）
             └─ 10M 条 → 约 2 GB

──────────────────────────────────────────────
保守估计：10M 条规则 ≈ 2.5 ~ 4 GB 堆内存（内存模式）
          加上 mmap 模式可以减少约 500 MB 文本存储开销
```

**实际生产数据参考**：
- EasyList + EasyPrivacy + 国内规则合计约 **20 万条** → 内存模式约 **100~200 MB**
- 按此比例线性外推，**10M 条约 5~10 GB**（因索引非线性增长，实际会更高）

#### 6.1.3 内存优化手段

| 优化手段 | 实现位置 | 效果 |
|---|---|---|
| **mmap 零拷贝** | `filterlist.NewFile()`（Unix） | 规则文本不计入 RSS，减少 ~40% 内存 |
| **IgnoreCosmetic** | 所有 RuleStorage 配置 | 丢弃 CSS/JS 注入规则，减少约 30%~50% 规则量（但 DNS 场景本来就忽略） |
| **按需编译** | `urlfilter.DNSEngine` 延迟构建 | 冷启动快，但首次查询慢 |
| **规则去重** | `deduplicateFilters()` | 按 URL 去重，避免同一规则集重复加载 |
| **FreeOSMemory** | `initFiltering()` 末尾 | 编译后强制归还内存给 OS，降低 RSS 峰值 |

> **注意**：`rulelist.DefaultMaxRuleListSize = 256 MB`（`parser.go:20`）是单文件大小限制，不是总规则数限制。但实际使用中建议单引擎规则量控制在 **100 万条以内**，否则编译和匹配延迟会显著上升。

### 6.2 Trie 深度对查询性能的影响

域名后缀匹配（如 `||example.com^` 匹配 `sub.example.com`）是通过**反向 Trie（后缀树）**实现的。Trie 的深度直接决定了单次匹配的时间复杂度。

#### 6.2.1 Trie 的构建方式

```
域名：www.example.com → 反向：moc.elpmaxe.www
                               
Trie 结构（根节点 = 空）：
  root
   └─ moc
       └─ elpmaxe
           ├─ www    ← 规则1: ||example.com^（命中 www.example.com）
           └─ *      ← 规则2: ||*.example.com^（通配子域名）
```

**匹配过程**：从 Trie 根节点出发，按域名的反向标签（从顶级域名开始）逐层下降，每下降一层对应一个域名段（label）。

#### 6.2.2 深度与性能的关系

| 指标 | 关系 | 说明 |
|---|---|---|
| **时间复杂度** | **O(k)**，k = 域名段数 | 例如 `a.b.c.example.com` 有 5 段，需遍历 5 层 Trie |
| **每层耗时** | ~10 ~ 50 ns | 主要是 `map[string]*node` 的哈希查找 |
| **典型深度** | 3 ~ 5 层 | 互联网域名平均 3~4 段（如 `www.example.com` = 3 段） |
| **最深实用场景** | 10 ~ 15 层 | 多级子域名 + 通配符叠加（如 `*.x.y.z.example.com`） |

**性能估算**（单线程）：
- 3 层域名（`www.example.com`）：~100 ns / 次查询
- 5 层域名（`sub.sub.example.co.uk`）：~200 ns / 次查询
- 10 层极端域名：~500 ns / 次查询

> 对比：精确域名哈希查找 O(1) 约 20~50 ns，正则匹配 O(n×m) 约 1~10 μs。Trie 性能介于两者之间。

#### 6.2.3 深度爆炸的风险与防护

**风险场景**：
1. **通配符规则嵌套**：`||*.*.*.example.com^` → Trie 中每层都有通配符节点，匹配时需回溯
2. **超深层级域名**：攻击者构造 100 层子域名的查询，可能触发 Trie 深度遍历
3. **正则规则回退**：当 Trie 和哈希都未命中时，可能需要遍历所有"泛模式"规则（如 `/ad.*/`），这是 O(n) 操作

**防护机制**：
- **最大域名长度限制**：DNS 协议限制域名总长 253 字节，每段 63 字节，天然限制深度 ≤ 127
- **通配符优化**：`*` 在 urlfilter 中通常被编译为"任意子节点"逻辑，而非真的生成无穷多节点
- **正则规则隔离**：正则规则单独存储，只有 Trie 和哈希都未命中时才尝试正则，且有数量限制
- **分层短路**：精确域名哈希 → 后缀 Trie → 子串匹配 → 正则，越往后的匹配路径越慢但越灵活

#### 6.2.4 10M 规则下的 Trie 特性

| 特性 | 小规模（10 万条） | 大规模（10M 条） |
|---|---|---|
| **Trie 节点数** | ~50 万 | ~5000 万（节点数 ≈ 规则数 × 0.5） |
| **每层平均分支数** | 5 ~ 20 | 几百 ~ 几千（根节点最宽） |
| **根节点哈希表大小** | 几百个顶级域名（.com, .net, ...） | 仍为几百个（顶级域名数量有限） |
| **内存占用** | ~30 MB | ~3 GB（节点数 × 64 B + 扩容冗余） |
| **单次查询耗时** | ~100 ns | ~200 ~ 500 ns（深层节点的 map 变大，哈希查找变慢） |

**关键洞察**：Trie 的**宽度**（根节点分支数）受限于顶级域名数量（~1500 个 gTLD + ccTLD），不会随规则数线性膨胀；但**深度**和**中下层节点数**会随规则数增长。对性能影响最大的是**域名段数（深度）**，而非总规则数。

---

## 7. 关键文件索引

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

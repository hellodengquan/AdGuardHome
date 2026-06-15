# AdGuardHome 黑白名单远端订阅、定时刷新及增量合并流程分析

## 1. 概述

AdGuardHome 的黑白名单过滤系统由三大部分组成：**远端订阅源管理**、**定时刷新调度**、**增量合并与去重**。三者协作完成了从订阅源获取、定时更新到最终合并应用的完整生命周期。

当前代码库中存在两套架构，但**实际运行的是旧架构**（`DNSFilter`），新架构（`rulelist.Storage/Engine`）处于迁移中未被主流程使用。详见第 6 章。

核心代码位于 `internal/filtering/` 目录下，涉及的关键文件：

| 文件 | 职责 |
|------|------|
| `filtering.go` | `DNSFilter` 核心结构、主刷新调度入口 `updatesLoop()` |
| `filter.go` | 订阅源定义 `FilterYAML`、刷新流程、增量合并、去重逻辑 |
| `http.go` | HTTP API 接口、手动刷新触发 |
| `rulelist/parser.go` | 规则解析、CRC-32 校验和计算 |
| `rulelist/filter.go` | 新架构下的 Filter 定义与单个订阅源刷新 |
| `rulelist/engine.go` | 新架构过滤引擎构建、批量刷新 |
| `rulelist/storage.go` | 新架构引擎存储管理 |
| `idgenerator.go` | 过滤列表 ID 生成与去重 |
| `home/dns.go` | 主程序启动入口：创建并启动 `DNSFilter` |

---

## 2. 远端订阅源管理

### 2.1 数据结构定义

订阅源由 `FilterYAML` 结构定义（`internal/filtering/filter.go:33`）：

```go
type FilterYAML struct {
    Enabled     bool
    URL         string    // URL 或本地文件绝对路径
    Name        string    `yaml:"name"`
    RulesCount  int       `yaml:"-"`
    LastUpdated time.Time `yaml:"-"`
    checksum    uint32    // CRC-32 校验和（有效规则内容的哈希）
    white       bool      // true = 白名单，false = 黑名单

    Filter `yaml:",inline"` // 内嵌：ID(rules.ListID)、FilePath、Data
}
```

内嵌的基础 `Filter` 结构（`internal/filtering/filtering.go:307`）：

```go
type Filter struct {
    FilePath string          // 本地缓存的过滤规则文件路径
    Data     []byte       // 内存中的规则内容（可选）
    ID       rules.ListID // 自动分配的唯一 ID（非 0）
}
```

### 2.2 订阅源分类与存储

黑白名单分别存储在两个独立的切片中（`internal/filtering/filtering.go:146-149`）：

- **黑名单（Blocklist）：`d.conf.Filters []FilterYAML`
- **白名单（Allowlist）：`d.conf.WhitelistFilters []FilterYAML`

二者数据结构完全相同，通过存储位置区分用途。匹配时先查白名单（命中直接放行），再查黑名单。

### 2.3 订阅源操作 API

HTTP API 入口在 `internal/filtering/http.go:720` `RegisterFilteringHandlers()` 中注册，主要接口：

| 方法 | 路径 | 功能 |
|------|------|------|
| POST | `/control/filtering/add_url` | 添加订阅源 |
| POST | `/control/filtering/remove_url` | 删除订阅源 |
| POST | `/control/filtering/set_url` | 更新订阅源属性（URL/名称/开关） |
| POST | `/control/filtering/refresh` | 手动强制刷新 |
| GET | `/control/filtering/status` | 获取当前过滤配置状态 |
| POST | `/control/filtering/config` | 设置刷新间隔/总开关等 |

### 2.4 添加订阅源完整流程

以 `POST /control/filtering/add_url` 为例，完整调用链（`internal/filtering/http.go:65`）：

```
handleFilteringAddURL()
  │
  ├── validateFilterURL()
  │     ├── 本地路径：校验路径匹配 SafeFSPatterns
  │     └── 远程 URL：校验 HTTP/HTTPS 协议合法性
  │
  ├── filterExists()        检查 URL 是否重复（黑名单+白名单全局唯一）
  │
  ├── idGen.next()          分配唯一 ListID
  │
  ├── d.update(&filt)       立即下载并解析订阅内容
  │     ├── updateIntl()    HTTP 下载 → Parser.Parse() → 校验和对比
  │     └── finalizeUpdate()  原子写入缓存文件、更新元数据
  │
  ├── filterAdd()           将 FilterYAML 追加到 d.conf.Filters 或 WhitelistFilters
  │
  ├── ConfModifier.Apply()  持久化配置到磁盘
  │
  └── EnableFilters(true)   异步重建过滤引擎（走初始化通道）
```

URL 重复检测逻辑：`filterExistsLocked()`（`internal/filtering/filter.go:182`）会同时遍历 `conf.Filters` 和 `conf.WhitelistFilters`，确保 URL 全局唯一。

---

## 3. 定时刷新调度

### 3.1 调度器启动流程

主程序在 `internal/home/dns.go:103` 创建 DNSFilter，在 `internal/home/dns.go:491` 调用 `.Start()` 启动调度：

```go
// internal/home/dns.go:103
globalContext.filters, err = filtering.New(config.Filtering, nil)

// internal/home/dns.go:491
globalContext.filters.Start()
```

`Start()` 内部实现（`internal/filtering/filtering.go:1077`）：

```go
func (d *DNSFilter) Start() {
    d.filtersInitializerChan = make(chan filtersInitializerParams, 1) // 容量=1
    d.done = make(chan struct{}, 1)
    d.RegisterFilteringHandlers()
    go d.updatesLoop(context.TODO())  // 启动独立 goroutine
}
```

### 3.2 核心结构：`updatesLoop` 的事件多路复用

`updatesLoop()`（`internal/filtering/filtering.go:1087`）是整个调度的核心，通过 `select` 同时处理**三类互斥事件**：

```
┌──────────────────────────────────────────────────────────────────┐
│                    updatesLoop()                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                │
│  ivl = 5秒, t = time.NewTimer(5s)                            │
│                                                                │
│  for {                                                        │
│    select {                                                   │
│                                                                │
│    ┌─ 分支1: filtersInitializerChan ──────────────────────┐   │
│    │  触发条件：有人调用 setFilters(async=true) 推入数据    │   │
│    │  动作：initFiltering() 同步重建过滤引擎               │   │
│    │  说明：用于"添加/删除/修改订阅源"后的引擎热重载         │   │
│    │  注意：消费后会重置定时器（不影响间隔，继续原节奏）    │   │
│    └───────────────────────────────────────────────────────┘   │
│                                                                │
│    ┌─ 分支2: t.C (定时器触发) ──────────────────────────────┐  │
│    │  触发条件：定时器到期（初始 5s，后续动态调整）          │  │
│    │  动作：periodicallyRefreshFilters()                    │  │
│    │         检查是否有过期订阅 → 执行刷新 → 返回新间隔     │  │
│    │         t.Reset(nextIvl)  重置下一次触发时间           │  │
│    │  说明：定时刷新的真正入口                               │  │
│    └───────────────────────────────────────────────────────┘   │
│                                                                │
│    ┌─ 分支3: done 信号 ────────────────────────────────────┐   │
│    │  触发条件：Close() 发送退出信号                        │   │
│    │  动作：Stop 定时器，return 退出 goroutine              │   │
│    └───────────────────────────────────────────────────────┘   │
│  }                                                            │
└──────────────────────────────────────────────────────────────────┘
```

**关键点**：三个分支互斥执行，同一时刻只会处理其中一个事件。初始化通道的消费与定时器触发互不干扰，但也不能同时进行。

### 3.3 "新增订阅源" 如何接入刷新循环

用户调用"添加订阅源"时，**订阅源本身不会被单独加入刷新循环**。实际机制如下：

1. **订阅源数据层面**：新的 `FilterYAML` 被追加到 `d.conf.Filters` / `d.conf.WhitelistFilters` 切片中（`filterAdd()`，`filter.go:200`）。刷新循环在每次执行 `listsToUpdate()` 时会**遍历整个切片**，新添加的订阅源自然会被扫描到。

2. **过滤引擎层面**：`EnableFilters(true)` → `setFilters(async=true)` 会把最新的引擎构建参数推入 `filtersInitializerChan`，由 `updatesLoop` 的分支 1 消费并执行 `initFiltering()`，完成热重载。

```
添加订阅源 → filterAdd() 追加到 conf.Filters
            → EnableFilters(true)
               → setFilters(async=true)
                  ├── filtersInitializerLock.Lock()
                  ├── 清空 filtersInitializerChan 中已挂起的旧任务
                  └── 将新的 {allowFilters, blockFilters} 推入通道
                        ↓
            updatesLoop() 分支1 收到数据
               → initFiltering() 重建引擎
               → 下一次定时器触发时，新订阅源已在 conf.Filters 中
```

### 3.4 刷新周期动态调整策略 `periodicallyRefreshFilters()`

核心逻辑（`internal/filtering/filtering.go:1115`）：

```go
func (d *DNSFilter) periodicallyRefreshFilters(ivl time.Duration) (nextIvl time.Duration) {
    const maxInterval = time.Hour

    if d.conf.FiltersUpdateIntervalHours == 0 {
        return ivl  // 配置禁用：保持当前间隔不变
    }

    // block=true, allow=true, force=false → 刷新黑白名单，不强制
    updated, isNetErr, ok := d.tryRefreshFilters(true, true, false)

    if ok && !isNetErr {
        ivl = maxInterval              // 成功（哪怕没实际内容变化）→ 1 小时
    } else if isNetErr {
        ivl *= 2                       // 网络全失败：指数退避翻倍
        ivl = max(ivl, maxInterval)    // ⚠️ 注意：是 max，不是 min！
    }
    // 其他情况（锁被占用 / 非网络错误）：保持原间隔不变

    return ivl
}
```

调度策略完整表格：

| 场景 | 初始 ivl | 计算过程 | 结果 nextIvl |
|------|----------|----------|-------------|
| 刷新完全成功（无网络错误） | 任意 | 设为 maxInterval | **1 小时** |
| 全部订阅源网络失败（isNetErr=true） | 5 秒 | `5*2=10秒` → `max(10秒, 1小时)` | **1 小时** |
| 全部订阅源网络失败（第二次） | 1 小时 | `1h*2=2h` → `max(2h, 1h)` | **2 小时** |
| 刷新锁被占用（ok=false） | 任意 | 保持原值 | 不变 |
| 部分失败但非全网络错误 | 任意 | 保持原值 | 不变 |
| FiltersUpdateIntervalHours=0 | 任意 | 直接返回 | 不变 |

### 3.5 网络错误退避的代码逻辑说明

**代码实际行为分析**：

- 代码为 `ivl = max(ivl, maxInterval)`（`filtering.go:1129`），使用 `max` 而非 `min`
- 第一次网络错误：5秒 → 10秒 → `max(10秒, 1小时)` = **直接跳到 1 小时**
- 注释期望是"指数退避"，但由于 `max` 的存在，**第一次网络错误后直接到顶**，真正的指数退避（5s→10s→20s→40s...）从未发生
- 只有当间隔本身已经 ≥1 小时（如连续多次网络错误后从 1h→2h→4h），翻倍才会生效

**设计考量推测**：
- 意图可能是"网络错误时不要过于频繁地重试"，避免对服务器造成压力
- 同时设置较长的最低间隔（1小时）确保网络恢复后不会等太久（但由于 max 导致实际就是1小时起步）
- 连续多次网络错误后间隔会继续增长（1h→2h→4h），上限由 Go Duration 类型决定（实际使用中不会到顶）

### 3.6 刷新锁机制：防止并发刷新

使用 `sync.Mutex.TryLock()` 实现**非阻塞锁**（`internal/filtering/filter.go:265`）：

```go
func (d *DNSFilter) tryRefreshFilters(block, allow, force bool) (updated int, isNetworkErr bool, ok bool) {
    if ok = d.refreshLock.TryLock(); !ok {
        return 0, false, false  // 锁被占用 → ok=false，立即返回，不阻塞
    }
    defer d.refreshLock.Unlock()

    updated, isNetworkErr = d.refreshFiltersIntl(block, allow, force)
    return updated, isNetworkErr, true
}
```

返回值含义（校准后）：

| 返回值 | 类型 | 含义 |
|--------|------|------|
| `updated` | `int` | 实际内容有变化（checksum 不同）的订阅源数量 |
| `isNetworkErr` | `bool` | `true` = 所有待更新订阅源全部失败，且都是网络错误 |
| `ok` | `bool` | `true` = 成功获取刷新锁并执行了刷新流程 |

该机制确保同一时刻只有一个刷新流程在执行。定时器触发时如果刷新还在进行，直接跳过本次，下一轮再试。

---

## 4. 强制刷新 vs 定时刷新

### 4.1 三条调用路径对比

| 维度 | 定时刷新 | 手动强制刷新（API） |
|------|----------|---------------------|
| 触发位置 | `filtering.go:1123` | `http.go:387` |
| 调用代码 | `tryRefreshFilters(true, true, false)` | `tryRefreshFilters(!req.White, req.White, true)` |
| `block` 参数 | `true`（刷新黑名单） | `!req.White`（根据请求决定） |
| `allow` 参数 | `true`（刷新白名单） | `req.White`（根据请求决定） |
| `force` 参数 | `false` | `true` |

### 4.2 `force` 参数的具体影响：`listsToUpdate()` 筛选逻辑

`listsToUpdate()`（`internal/filtering/filter.go:277`）：

```go
func (d *DNSFilter) listsToUpdate(filters *[]FilterYAML, force bool) (toUpd []FilterYAML) {
    now := time.Now()
    d.conf.filtersMu.RLock()
    defer d.conf.filtersMu.RUnlock()

    for i := range *filters {
        flt := &(*filters)[i]
        if !flt.Enabled {
            continue  // 条件1：必须启用（始终检查）
        }

        if !force {
            // 条件2：force=false 才检查是否过期
            exp := flt.LastUpdated.Add(time.Duration(d.conf.FiltersUpdateIntervalHours) * time.Hour)
            if now.Before(exp) {
                continue  // 未过期，跳过
            }
        }
        // force=true：所有 Enabled 的都会进入待更新列表
        toUpd = append(toUpd, ...)
    }
    return toUpd
}
```

**总结 `force` 的区别**：

- **force=false（定时）**：`Enabled=true` **且** `now >= LastUpdated + Interval` 才更新
- **force=true（手动）**：只要 `Enabled=true` 就更新，不管上次更新时间

---

## 5. 增量合并与去重

### 5.1 增量判断：CRC-32 校验和机制

**第一步：解析时计算校验和**（`internal/filtering/rulelist/parser.go:119`）

```go
// processLine() 中，每个有效规则行：
p.rulesCount++
p.checksum = crc32.Update(p.checksum, crc32.IEEETable, trimmed)  // 增量累加 CRC-32
```

**校验和计算对象**：仅针对 trim 后的有效规则行（非空、非注释、非标题行）。空行、注释、HTML 检测等不参与。

**第二步：对比校验和判断是否变化**（`internal/filtering/filter.go:527` `updateIntl()` 返回值）：

```go
// res.Checksum = 新下载内容的 CRC-32
// flt.checksum = 旧内容保存的 CRC-32
return res.Checksum != flt.checksum, nil
```

只有校验和不同时，才执行文件替换和后续的引擎重载。校验和相同则仅更新文件 mtime，不做其他操作。

### 5.2 规则解析与内容清理：`rulelist.Parser`

`Parser.Parse()`（`internal/filtering/rulelist/parser.go:49`）在下载/读取时**实时处理**每一行：

| 处理步骤 | 说明 |
|----------|------|
| 首尾空白 Trim | 统一格式，去除多余空格 |
| 空行跳过 | 不计入规则数，不参与校验和 |
| 注释行跳过 | `#` 开头或 `!` 开头（非标题）全部跳过 |
| 标题提取 | `! Title: xxx` 格式 → 存入 ParseResult.Title |
| HTML 内容检测 | 首行以 `<html` 或 `<!doctype` 开头 → 返回 `ErrHTML` |
| 二进制检测 | 含非打印字符（除 `\n\r\t`）→ 报错 |
| 最大行大小 | `bufio.MaxScanTokenSize`（64KB），防止超大行 OOM |

解析结果 `ParseResult`（`internal/filtering/rulelist/parser.go:31`）：

```go
type ParseResult struct {
    Title        string // ! Title: 提取的名称（空则用默认名）
    RulesCount   int    // 有效规则行数
    BytesWritten int    // 写入 dst 的字节数（含换行）
    Checksum     uint32 // CRC-32 校验和
}
```

### 5.3 URL 级别去重

**启动初始化时去重** `deduplicateFilters()`（`internal/filtering/filter.go:245`）：

```go
func deduplicateFilters(filters []FilterYAML) (deduplicated []FilterYAML) {
    urls := container.NewMapSet[string]()
    lastIdx := 0
    for _, filter := range filters {
        if !urls.Has(filter.URL) {
            urls.Add(filter.URL)
            filters[lastIdx] = filter  // 原地压缩，保留首次出现
            lastIdx++
        }
    }
    return filters[:lastIdx]
}
```

调用时机：`New()` 初始化时（`filtering.go:1051-1052`）分别对 `Filters` 和 `WhitelistFilters` 执行。基于 URL 去重，保留首次出现的订阅源。

**运行时 URL 防重**：`filterExistsLocked()`（`filter.go:182`）在 `filterAdd()` 和 `filterSetProperties()` 中实时检查。

### 5.4 ID 级别去重

`idGenerator.fix()`（`internal/filtering/idgenerator.go:47`）确保所有 ListID 唯一：

- ID 为 0 的过滤器分配新 ID
- 重复 ID 检测到后，循环生成新 ID 直到找到未占用的
- 使用 `MapSet` 保证 O(1) 查重

### 5.5 原子文件更新机制

使用 `aghrenameio.PendingFile` 实现**写时复制**的原子替换（`internal/filtering/filter.go:506`）：

```
┌─────────────────────────────────────────────┐
│  1. aghrenameio.NewPendingFile()            │
│     创建临时文件：<dataDir>/filters/<id>.txt.tmp │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  2. Parser.Parse(tmpFile, src, buf)          │
│     将解析后的规则（去除注释/空行）写入临时文件 │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  3. finalizeUpdate() 判断 updated 标志       │
│     ├── updated=false：file.Cleanup()        │
│     │             删除临时文件，保留旧文件     │
│     └── updated=true：file.CloseReplace()    │
│                   原子 rename 为 <id>.txt    │
│                   （原文件被覆盖，POSIX 原子）│
└─────────────────────────────────────────────┘
```

---

## 6. 实际运行架构说明（重要！）

### 6.1 两套架构并存状态

| 架构 | 核心类型 | 定义位置 | 实际使用状态 |
|------|----------|----------|--------------|
| **旧架构（当前运行）** | `DNSFilter` | `filtering.go:253` | ✅ **主流程在用**，由 `home/dns.go:103` 创建，`home/dns.go:491` 启动 |
| 新架构（迁移中） | `rulelist.Storage` | `rulelist/storage.go:16` | ❌ **未接入主流程**，仅被引用常量 `DefaultMaxRuleListSize`（`home/config.go:568`） |

代码证据：
```go
// internal/home/dns.go:103  →  明确使用 filtering.New() 即旧架构
globalContext.filters, err = filtering.New(config.Filtering, nil)

// 全局搜索 rulelist.NewStorage()：在 home/ 中没有调用
// 仅在 rulelist/*_test.go 测试代码中被使用
```

### 6.2 两套架构核心差异

| 维度 | 旧架构（DNSFilter） | 新架构（rulelist.Storage） |
|------|---------------------|---------------------------|
| 调度器 | `updatesLoop()` 内建 goroutine + timer | 无内建调度，外部调用 `Storage.Refresh()` |
| 锁 | `refreshLock` + `TryLock()` | `refreshMu` + 常规 `Lock()` |
| 增量判断 | CRC-32 + 同上 | CRC-32 + 同上 |
| 原子文件 | `aghrenameio.PendingFile` | `aghrenameio.PendingFile` |
| 底层引擎 | `urlfilter.DNSEngine` | `urlfilter.DNSEngine` |
| ID 管理 | `idGenerator` 自增 | 外部传入 `rules.ListID` |
| 黑白名单 | `conf.Filters` / `conf.WhitelistFilters` 两个切片 | `allow` / `block` 两个 `Engine` |
| 自定义规则 | 与订阅源一同组装为 Filter 列表 | 独立 `custom TextEngine` |

新架构的 `Engine.Refresh()` 已实现完整的刷新逻辑（`rulelist/engine.go:108`），包括 checksum 对比、原子文件、引擎热替换等，但尚未被主程序采纳。`TODO(a.garipov): Add a new update worker.`（`rulelist/rulelist.go:4`）注释说明迁移工作尚未完成。

---

## 7. 完整刷新流程（旧架构，实际运行）

### 7.1 调用链总览

```
Start()
  │
  ▼
updatesLoop() [goroutine]
  │
  ├── [定时器分支] t.C 触发
  │     │
  │     ▼
  │   periodicallyRefreshFilters(ivl)
  │     │
  │     ├── FiltersUpdateIntervalHours==0? → 直接返回
  │     │
  │     ▼
  │   tryRefreshFilters(block=true, allow=true, force=false)
  │     │
  │     ├── refreshLock.TryLock()  [失败直接返回]
  │     │
  │     ▼
  │   refreshFiltersIntl(block, allow, force)
  │     │
  │     ├── refreshFiltersArray(&conf.Filters, force) 处理黑名单
  │     │     │
  │     │     ├── listsToUpdate()  筛选过期订阅源
  │     │     │     │  Enabled==true 且 已过期
  │     │     │
  │     │     ├── updateFilterList()  逐个更新
  │     │     │     │
  │     │     │     └── for each: d.update(&uf)  ↓↓ 见 7.2
  │     │     │
  │     │     └── syncUpdatedFilters()  回写元数据到 conf.Filters
  │     │
  │     ├── refreshFiltersArray(&conf.WhitelistFilters, force) 处理白名单
  │     │     └── 同上
  │     │
  │     └── [updNum>0] EnableFilters(false) 同步重建引擎
  │           └── setFilters(async=false)
  │                 └── initFiltering() 重建 DNSEngine
  │
  ├── [初始化通道分支] filtersInitializerChan
  │     │
  │     └── initFiltering(allowFilters, blockFilters) 热重载引擎
  │
  └── [退出分支] done → Stop 定时器，return
```

### 7.2 单个订阅源更新详细步骤

`update()` → `updateIntl()` → `finalizeUpdate()`（`internal/filtering/filter.go:480`）：

```go
func (d *DNSFilter) update(filter *FilterYAML) (b bool, err error) {
    b, err = d.updateIntl(ctx, filter)        // 实际内容更新
    filter.LastUpdated = time.Now()           // ⚠️ 无论成功失败都更新时间戳！
    if !b {
        os.Chtimes(path, now, now)            // 无变化时 touch 文件 mtime
    }
    return b, err
}
```

**⚠️ 重要注意**：即使内容下载失败，`LastUpdated` 也会被设为 `Now()`。这意味着**下次定时刷新要等完整的 Interval 后**才会再次尝试该订阅源（除非 force=true）。

`updateIntl()` 内部根据 URL 类型分支：

```go
if filepath.IsAbs(flt.URL) {
    res, err = d.readFromFile(tmpFile, path)  // 本地文件：SafeFSPatterns 校验 + 打开 + 解析
} else {
    res, err = d.readFromHTTP(tmpFile, urlStr) // 远程 HTTP：GET + StatusCode==200 + LimitReader + 解析
}
// 返回 (res.Checksum != flt.checksum) 即是否有变化
```

---

## 8. 三者协作关系总结

```
            ┌──────────────────────────────┐
            │     远端订阅源 (FilterYAML) │
            │  存储在 conf.Filters /       │
            │  conf.WhitelistFilters      │
            │  字段: Enabled/URL/ID/       │
            │  LastUpdated/checksum        │
            └──────────┬───────────────────┘
                       │
          ┌────────────┤ 提供元数据给调度器
          │            │ listsToUpdate() 遍历扫描
          ▼            │
┌──────────────────────────────┐
│    定时刷新调度 (updatesLoop) │
│ 1. 定时器 → periodicallyRefreshFilters() │
│ 2. force=false 过期筛选                    │
│ 3. tryRefreshFilters() 获取刷新锁          │
│ 4. 逐个 update() 下载+Parser 解析           │
│ 5. checksum 对比 → 判断增量                 │
└──────────┬───────────────────┘
           │
   ┌───────┤ 产出解析结果 + 增量标记
   │       │
   ▼       ▼
┌──────────────────────────────┐     ┌──────────────────────┐
│   增量合并与去重            │────→│  启用的订阅源 →      │
│ 1. Parser: 去注释/空行/提取  │     │  EnableFilters()    │
│ 2. URL 去重 + ID 去重       │     │  setFilters()       │
│ 3. 原子文件替换             │     │  initFiltering()    │
│ 4. syncUpdatedFilters()     │     │  重建 urlfilter     │
│    回写 Name/RulesCount/    │     │  .DNSEngine         │
│    checksum                 │     └──────────────────────┘
└──────────────────────────────┘
```

### 8.1 关键协作点详解

1. **订阅源 → 调度**
   - `listsToUpdate()` 从订阅源读取 `Enabled` 和 `LastUpdated`
   - 根据 `conf.FiltersUpdateIntervalHours` 计算过期时间
   - 只有满足条件的才会进入待更新列表

2. **调度 → 合并去重**
   - 调度调用 `update()` 下载内容
   - `Parser.Parse()` 完成解析清理（去空行、去注释、算校验和）
   - 增量（checksum 对比）判断在调度层完成

3. **合并 → 订阅源**
   - `syncUpdatedFilters()` 将更新后的元数据（`LastUpdated`、`Name`、`RulesCount`、`checksum`）回写到 `conf.Filters` / `conf.WhitelistFilters`
   - 通过 ID + URL 双字段匹配定位要更新的条目

4. **合并 → 过滤引擎**
   - 只要有至少一个订阅源内容变化（`updNum > 0`），就调用 `EnableFilters(async=false)`
   - `EnableFilters()` 收集所有 `Enabled=true` 的订阅源 + 自定义规则
   - `initFiltering()` 重建 `rulesStorage` + `filteringEngine`（黑名单和白名单各一套）
   - `engineLock` 加写锁完成新旧引擎指针的原子替换

5. **并发安全保障**

| 锁名称 | 类型 | 保护对象 | 用途 |
|--------|------|----------|------|
| `conf.filtersMu` | RWMutex | `conf.Filters` / `WhitelistFilters` / `UserRules` | 配置列表读写 |
| `refreshLock` | Mutex | 整个刷新流程 | 防止多个刷新并发（TryLock） |
| `engineLock` | RWMutex | `rulesStorage` / `filteringEngine` 等引擎指针 | 匹配时读锁、重建时写锁 |
| `filtersInitializerLock` | Mutex | 对 `filtersInitializerChan` 的写入 | 清空+推入的原子性 |

---

## 9. 完整刷新衔接：三块按顺序协作的函数调用与数据流

本节以"定时刷新黑名单 + 白名单（force=false）"为例，沿着实际代码路径，逐步拆解订阅源管理、刷新调度、合并去重三块在每一步如何交接。

### 9.1 事件触发：定时器到期（调度→订阅源管理）

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 9.1.1 | `filtering.go:1109` | `t.C` 触发，select 进入定时器分支 | — | — |
| 9.1.2 | `filtering.go:1115` | 调用 `periodicallyRefreshFilters(ivl)` | 当前间隔 `ivl`，全局 `d.conf` | `nextIvl` 新间隔 |

**数据流**：从调度器自身状态（`ivl`、`t`）进入，读取全局配置 `FiltersUpdateIntervalHours`。

---

### 9.2 调度 → 订阅源管理：筛选待更新列表

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.2.1 | `filtering.go:1123` | `tryRefreshFilters(true, true, false)` | block=true, allow=true, force=false | (updated, isNetErr, ok) |
| 10.2.2 | `filter.go:265` | `refreshLock.TryLock()` 获取刷新锁 | — | ok=true/false（失败直接返回） |
| 10.2.3 | `filter.go:416` | `refreshFiltersIntl(block, allow, force)` | 三个布尔标志 | (updNum, isNetErr) |

进入黑名单处理分支（白名单完全对称）：

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.2.4 | `filter.go:430` | `refreshFiltersArray(ctx, &d.conf.Filters, force)` | 指向 `conf.Filters` 的指针，force=false | `(updNum, lists, toUpd, isNetErr)` |
| 10.2.5 | `filter.go:318` | `listsToUpdate(filters, force)` 筛选需更新的订阅源 | `conf.Filters` 切片（RLock 保护），force=false | `updateFilters []FilterYAML`（副本） |

**关键交接点**：`listsToUpdate()` 从**订阅源管理**（`conf.Filters`）读取以下字段作为输入：
- `Enabled`：必须为 true
- `LastUpdated`：+ `FiltersUpdateIntervalHours` 与 `now` 比较是否过期
- `URL` / `ID`：用于拷贝构造输出副本

输出的 `updateFilters` 是独立拷贝（值语义），后续所有对订阅源的修改都在这个副本上进行，不会影响原列表——这是三块之间的第一个"隔离边界"。

**数据流**：`conf.Filters[].{Enabled, LastUpdated, URL, ID, Name, checksum, RulesCount}` → 拷贝 → `updateFilters []FilterYAML`

---

### 9.3 调度 → 合并去重：逐个更新订阅源

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.3.1 | `filter.go:323` | `updateFilterList(ctx, updateFilters)` 遍历更新副本列表 | `updateFilters []FilterYAML` | `(failNum, updateFlags []bool)` |
| 10.3.2 | `filter.go:345` | 对每个 `uf = &updateFilters[i]` 调用 `d.update(uf)` | 单个订阅源指针 | `(updated bool, err error)` |

深入单个 `update()`：

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.3.3 | `filter.go:483` | `updateIntl(ctx, filter)` 下载+解析 | `&updateFilters[i]` 的 URL/ID | `(b bool, err error)` + 副作用：创建临时文件 |
| 10.3.4 | `filter.go:506` | `aghrenameio.NewPendingFile()` 创建临时文件 | `dataDir/filters/<id>.txt` | `PendingFile`（`<id>.txt.tmp`） |
| 10.3.5 | `filter.go:517-521` | 分支判断：绝对路径走 `readFromFile()`，URL 走 `readFromHTTP()` | `filter.URL` | `(*ParseResult, error)` |
| 10.3.6 | `parser.go:49` | `Parser.Parse(tmpFile, src, buf)` 边读边写边解析 | 源数据 Reader，目标 tmpFile Writer | `ParseResult{Title, RulesCount, BytesWritten, Checksum}` |
| 10.3.7 | `filter.go:527` | 增量判断：`res.Checksum != flt.checksum` | 新/旧 CRC-32 | `updated bool` |
| 10.3.8 | `filter.go:585` | `finalizeUpdate()` 根据 updated 标志决定 | `updated`、`PendingFile`、`ParseResult` | 副作用：原子替换或清理临时文件 |
| 10.3.9 | `filter.go:484` | ⚠️ `filter.LastUpdated = time.Now()` | — | 副作用：**无论成功失败**都覆写 LastUpdated |

**合并去重实际发生在 10.3.6（Parser.Parse）**：
- 去空行、去注释（`#` / `!`）
- 提取 Title
- HTML/二进制检测
- 有效规则行才累加 CRC-32（即"有效去重"后的真正内容校验）

**关键交接点**：`finalizeUpdate()` 把 `ParseResult`（解析产物）的三个字段**回写到副本**：
```go
flt.ensureName(res.Title)       // 若 Name 为空，填入解析的标题
flt.checksum = res.Checksum     // 覆盖旧校验和
flt.RulesCount = res.RulesCount // 更新规则数
```
此时改动仍只在 `updateFilters` 副本上，**尚未触及** `conf.Filters`（订阅源主存储）。

---

### 9.4 调度 → 订阅源管理：回写元数据

全部订阅源更新完毕后，进入回写阶段：

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.4.1 | `filter.go:328` | `d.conf.filtersMu.Lock()` 取写锁 | — | — |
| 10.4.2 | `filter.go:331` | `syncUpdatedFilters(ctx, filters, updateFilters, updateFlags)` | `&conf.Filters`（主列表）、`updateFilters`（副本）、`updateFlags` | `updateCount int` |
| 10.4.3 | `filter.go:369-391` | 双重循环：按 `ID == uf.ID && URL == uf.URL` 定位条目；`LastUpdated` 无条件同步；仅 `updated=true` 时同步 `Name/RulesCount/checksum` | — | 副作用：修改 `conf.Filters[k]` |
| 10.4.4 | `filter.go:329` | `defer d.conf.filtersMu.Unlock()` 释放写锁 | — | — |

**关键交接点**：`syncUpdatedFilters()` 是第二块（调度/合并）向第一块（订阅源管理）正式提交数据的唯一入口。通过 `filtersMu` 写锁保证期间主列表不被 API 读取或修改。

白名单处理与以上完全对称（`filter.go:433-437`），结果累加到 `updNum`、`lists`、`toUpd`、`isNetErr`。

---

### 9.5 合并去重 → 过滤引擎：重建并热替换

全部名单回写完毕后，进入引擎重建：

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.5.1 | `filter.go:444-450` | 短路判断：全网络错误返回(0,true)；无变化返回(0,false) | `isNetErr`、`updNum` | 可能直接 return |
| 10.5.2 | `filter.go:452` | `d.EnableFilters(false)` 同步重建引擎 | `async=false` | — |
| 10.5.3 | `filter.go:672` | `enableFiltersLocked()`：收集所有 `Enabled=true` 的 FilterYAML → 转换为 `[]Filter{ID, FilePath}`，并加入自定义规则（ID=IDCustom） | `conf.Filters`、`conf.WhitelistFilters`、`conf.UserRules` | `blockFilters []Filter`、`allowFilters []Filter` |
| 10.5.4 | `filtering.go:390` | `setFilters(async=false)`：`filtersInitializerLock` 锁定 → 初始化通道若有旧任务则清空 → 直接 `initFiltering(ctx, allowFilters, blockFilters)` | 两组 Filter | — |
| 10.5.5 | `filtering.go:746` | `initFiltering()`：分别为 blacklist 和 whitelist 调用 `newRuleStorage()` → 构建 `urlfilter.NewDNSEngine()` | 两组 Filter | 两套 storage + engine |
| 10.5.6 | `filtering.go:760-769` | `engineLock.Lock()` → `reset(ctx)` 释放旧引擎 → 指针赋值新 storage/engine → `engineLock.Unlock()` | — | 原子替换全局引擎 |
| 10.5.7 | `filtering.go:772` | `debug.FreeOSMemory()` 回收内存 | — | — |

---

### 9.6 收尾：清理旧文件（调度）

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.6.1 | `filter.go:454-458` | 遍历 `lists` + `toUpd`，对 `toUpd[i]==true` 的调用 `removeOldFilterFile()` | — | 删除 `.old` 后缀文件（部分 rename 策略的残留） |
| 10.6.2 | `filter.go:460` | `refreshFiltersIntl` 返回 `(updNum, false)` | — | 回到 periodicallyRefreshFilters |

---

### 9.7 回调度：调整下一次间隔

| 步骤 | 位置 | 动作 | 输入 | 输出 |
|------|------|------|------|------|
| 10.7.1 | `filtering.go:1125-1129` | `ok && !isNetErr` → `ivl=1h`；`isNetErr` → `ivl*=2; ivl=max(ivl, 1h)` | (updated, isNetErr, ok) | 新 `ivl` |
| 10.7.2 | `filtering.go:1109` | `t.Reset(nextIvl)` 重置定时器 | 新 `ivl` | — |

---

### 9.8 三大块在每一步的分工总表

```
        ┌──────────────────────────────────────────────────────────────┐
        │                     一次完整刷新                       │
        └──────────────────────────────────────────────────────────────┘
阶段      10.1 触发    10.2 筛选     10.3 更新   10.4 回写   10.5 重建   10.7 调整
          ──────     ────────    ───────   ───────   ───────   ──────

订阅源     提供配置     提供Enabled   →副本→     接收同步    提供Enabled  无
管理       读接口       LastUpdated   (隔离)    (写锁)       收集项
          (只读)       (只读)                              (只读)

刷新调度  定时器到期    listsToUpdate  update()  sync      Enable     period调
           t.C         TryLock       updateIntl Updated   Filters    ivl计算
                                   finalizeUpd           initFilt

合并去重     —            —           Parser.    —        (隐含     —
                                     Parse             dedup-ID)
                                   checksum对比
                                   原子替换
```

隔离边界：
- **边界 A（10.2 → 10.3）**：`listsToUpdate()` 值拷贝，修改不影响原 `conf.Filters`
- **边界 B（10.3 → 10.4）**：`filtersMu.Lock()` 保证同步期间主列表不变
- **边界 C（10.5.6）**：`engineLock.Lock()` 保证匹配期间引擎指针原子切换

---

## 10. 热替换并发机制：旧查询与新引擎接管的协作

### 10.1 并发模型：单写多读（RWMutex）

引擎热替换的并发安全基于 `sync.RWMutex` 实现（`filtering.go:284`）：

```go
type DNSFilter struct {
    engineLock sync.RWMutex   // 读写锁
    ...
}
```

**读路径（DNS 查询匹配）**：持有读锁 RLock → RUnlock
**写路径（引擎热替换）**：持有写锁 Lock → Unlock

### 10.2 读路径：查询时如何持有引擎指针

以 `matchHost()` 为例（`filtering.go:904-920`）：

```go
d.engineLock.RLock()
// 注释强调：不仅 Match() 时要持锁，使用返回的规则期间也要持锁
// TODO(e.burkov): Inspect if the above is true.
defer d.engineLock.RUnlock()

if setts.ProtectionEnabled && d.filteringEngineAllow != nil {
    dnsres, ok := d.filteringEngineAllow.MatchRequest(ufReq)
    ...
}
...
if d.filteringEngine != nil {
    dnsres, ok = d.filteringEngine.MatchRequest(ufReq)
    ...
}
```

**关键点**：
- 整个匹配过程在**单次 RLock 保护**下完成
- 期间访问 `d.filteringEngineAllow` 和 `d.filteringEngine` 两个指针
- `defer RUnlock()` 保证即使 panic 也会释放锁
- 只要在 RLock 期间读到了指针，后续 `MatchRequest()` 调用使用的就是**同一个引擎实例**（即使替换发生，旧引擎也不会被中途释放）

### 10.3 写路径：引擎替换的原子性

`initFiltering()` 中的替换逻辑（`filtering.go:760-769`）：

```go
func() {
    d.engineLock.Lock()
    defer d.engineLock.Unlock()

    d.reset(ctx)               // 1. 释放旧引擎内存
    d.rulesStorage = rulesStorage       // 2. 赋值新 storage
    d.filteringEngine = filteringEngine // 3. 赋值新 engine
    d.rulesStorageAllow = rulesStorageAllow
    d.filteringEngineAllow = filteringEngineAllow
}()
```

**替换的原子性分析**：
- 在**单次 Lock 保护**下完成所有指针赋值
- 对外部观察者（读路径）而言：要么看到全部旧指针，要么看到全部新指针，不会出现"黑名单是新的、白名单是旧的"中间状态
- 但指针赋值本身有先后顺序，在 Go 内存模型下，如果没有锁保护并发读可能看到部分更新 —— 但这里读写都通过 `engineLock` 同步，所以安全

### 10.4 并发时序：替换发生时正在进行的查询

```
时间轴 →

Goroutine A (查询):          Goroutine B (替换):
  RLock()                        ...构建新引擎...
  engine.MatchRequest()
  ...使用返回的规则...              Lock() ← 阻塞，等 A 释放读锁
  ...                               ...
  RUnlock()
                                  ← 获取写锁
                                  reset() 释放旧引擎
                                  赋值新指针
                                  Unlock()
```

**关键结论**：
1. **进行中的查询安全**：已经获取读锁的查询会继续使用旧引擎完成全部匹配，不会被新替换打断
2. **新查询立即生效**：写锁释放后到达的新查询，会直接读到新引擎指针
3. **旧引擎内存安全**：只有当所有持有旧引擎的读锁都释放后，`reset()` 才会被调用（因为写锁要等所有读锁释放），不会出现"正在使用时被释放"的 use-after-free
4. **替换期间阻塞**：替换进行时（持有写锁），新到达的查询会阻塞等待写锁释放，表现为一次查询延迟（通常毫秒级，取决于引擎构建时间）

### 10.5 读-写公平性与查询饥饿

`sync.RWMutex` 的 Go 标准实现是**写优先**：当有写者等待时，新到来的读者会被阻塞，避免写者饥饿。

对 AdGuardHome 的影响：
- 引擎热替换（写操作）不会被源源不断的 DNS 查询（读操作）饿死
- 但替换期间到达的查询会排队等待，造成短暂延迟
- 由于引擎替换频率很低（最快 1 小时一次），且耗时很短（内存指针赋值），实际影响可忽略

### 10.6 待确认的隐患（代码 TODO）

代码注释中有一个待确认的问题（`filtering.go:905-908`）：

```go
// Keep in mind that this lock must be held no just when calling Match() but
// also while using the rules returned by it.
//
// TODO(e.burkov):  Inspect if the above is true.
```

即：返回的规则指针是否指向引擎内部存储？如果引擎被释放，这些指针是否失效？

从 Go 的 `urlfilter.DNSEngine` 设计来看，`MatchRequest` 返回的 `DNSResult` 通常包含规则的**值拷贝或共享不可变数据**，只要引擎对象本身还存活就安全。而由于引擎替换时 `reset()` 在写锁内执行，且旧引擎只有在所有读锁释放后才会被释放，所以实际使用中是安全的。

---

## 11. Web UI 配置修改到 updatesLoop 的完整调用链路

### 11.1 总览：两类配置修改路径

用户从 Web UI 修改过滤相关配置有两大类操作，通向 `updatesLoop` 的路径不同：

| 操作类型 | 代表接口 | 是否走 filtersInitializerChan | 是否影响刷新调度 |
|----------|---------|----------------------------|-----------------|
| **订阅源/规则改动** | add_url / remove_url / set_url / set_rules / config | ✅ 是（EnableFilters→setFilters→channel） | 间接（只触发引擎重建，不改变刷新节奏） |
| **手动刷新** | refresh | ❌ 否（直接调用 tryRefreshFilters） | 直接（立即执行一次刷新） |

### 11.2 路径一：订阅源/规则改动 → filtersInitializerChan → 引擎重建

以最典型的"添加订阅源"为例（`http.go:65-172`）：

```
Web UI 发送 POST /control/filtering/add_url
        │
        ▼
handleFilteringAddURL()
  ├── json 解码请求体
  ├── validateFilterURL() 校验 URL
  ├── filterExists() 检查重复
  ├── idGen.next() 分配新 ID
  │
  ├── d.update(&filt)        【步骤1：下载内容+写入磁盘】
  │     └── updateIntl() → Parser.Parse() → finalizeUpdate()
  │         （与定时刷新完全相同的更新逻辑）
  │
  ├── d.filterAdd(filt)       【步骤2：加入配置列表】
  │     └── conf.filtersMu.Lock()
  │         追加到 conf.Filters 或 conf.WhitelistFilters
  │
  ├── d.conf.ConfModifier.Apply(ctx)  【步骤3：持久化配置文件】
  │
  └── d.EnableFilters(true)   【步骤4：触发引擎重建】
        │
        ▼
      enableFiltersLocked()
        │  收集所有 Enabled=true 的过滤器
        │  组装 blockFilters []Filter / allowFilters []Filter
        │
        ▼
      setFilters(async=true)  【推入初始化通道】
        │
        ├── filtersInitializerLock.Lock()
        ├── for { 清空通道中已挂起的旧任务 removeLoop }
        ├── filtersInitializerChan <- {allowFilters, blockFilters}
        │   （容量为 1 的缓冲通道，确保只有一个最新任务）
        │
        └── filtersInitializerLock.Unlock()
              │
              ▼
        updatesLoop() 的 select 分支1 消费通道
              │
              ▼
        initFiltering(allowFilters, blockFilters)
              │
              ├── 构建 ruleStorage + urlfilter.DNSEngine（黑白各一套）
              ├── engineLock.Lock()
              ├── reset() + 指针赋值
              └── engineLock.Unlock()
```

**同类操作的对比**：

| 操作 | 下载内容 | 修改配置 | 持久化 | EnableFilters |
|------|---------|---------|-------|---------------|
| add_url | ✅ 立即下载 | ✅ 追加 | ✅ | ✅ async=true |
| remove_url | ❌ | ✅ 删除 | ✅ | ✅ async=true |
| set_url（改 URL/名称/开关） | ⚠️ 仅 URL 变化时重下 | ✅ 修改 | ✅ | ⚠️ 仅当需要重启时 |
| set_rules（自定义规则） | ❌ | ✅ 改 UserRules | ✅ | ✅ async=true |
| config（总开关/刷新间隔） | ❌ | ✅ 改全局参数 | ✅ | ✅ async=true |

### 11.3 关键机制：合并推送（Coalescing）

`setFilters(async=true)` 中的 `removeLoop` 清空逻辑（`filtering.go:372-382`）：

```go
// async = true 时
d.filtersInitializerLock.Lock()
removeLoop:
for {
    select {
    case <-d.filtersInitializerChan:
        // fall through，继续丢弃
    default:
        break removeLoop
    }
}
d.filtersInitializerChan <- filtersInitializerParams{
    allowFilters: allowFilters,
    blockFilters: blockFilters,
}
d.filtersInitializerLock.Unlock()
```

**设计意图**：
- 通道容量 = 1
- 如果短时间内多次调用 `EnableFilters(true)`（如用户快速操作），只保留**最后一次**的参数
- 避免 `updatesLoop` 被重复的引擎重建任务淹没
- `filtersInitializerLock` 保护"清空+推入"的原子性，防止并发写入

### 11.4 路径二：手动刷新 → 直接调用刷新逻辑

`handleFilteringRefresh()`（`http.go:366-407`）：

```
Web UI 点击"立即刷新"
  │
  ▼
POST /control/filtering/refresh
  │
  ▼
handleFilteringRefresh()
  ├── json 解码 { whitelist: bool }
  ├── 异步执行（go func）
  │     │
  │     └── tryRefreshFilters(!req.White, req.White, true)
  │           ├── refreshLock.TryLock()
  │           └── refreshFiltersIntl(block, allow, force=true)
  │                 （与定时刷新完全相同的内部逻辑，但 force=true）
  │
  └── 立即响应 "OK" 给前端（不等刷新完成）
```

**特点**：
- **不走初始化通道**，直接在独立 goroutine 中执行完整刷新流程
- `force=true` 跳过过期检查，立即刷新所有已启用的订阅源
- HTTP 请求立即返回，刷新在后台进行
- 前端需要通过 `/control/filtering/status` 轮询查看结果

### 11.5 刷新间隔配置修改的特殊情况

`handleFilteringConfig()` 修改 `FiltersUpdateIntervalHours`（`http.go:480-490`）：

```go
func() {
    d.conf.filtersMu.Lock()
    defer d.conf.filtersMu.Unlock()
    d.conf.FilteringEnabled = req.Enabled
    d.conf.FiltersUpdateIntervalHours = req.Interval
}()
d.conf.ConfModifier.Apply(ctx)
d.EnableFilters(true)
```

**注意**：修改刷新间隔**不会主动通知 `updatesLoop` 调整定时器**。

实际效果：
- `updatesLoop` 仍然按当前 `ivl` 等待下一次触发
- 下一次 `periodicallyRefreshFilters()` 执行时，才会读取新的 `FiltersUpdateIntervalHours`
- 如果新间隔更短，实际生效会延迟（最多等待旧的 ivl 时长）
- 如果新间隔设为 0（禁用），下一次触发时发现为 0 → 直接返回，后续不再刷新（但定时器还在按原间隔 tick，只是不做事）

**这是一个隐性设计**：配置修改不直接干预调度循环，而是通过"下次检查时读取最新值"的方式渐进生效。

---

## 12. 监控与指标：刷新成功率、耗时、错误数的暴露情况

### 12.1 结论先行：没有专门的 metrics 层

**AdGuardHome 的过滤刷新模块没有实现 Prometheus metrics 或专门的指标层。** 刷新状态的暴露仅通过以下两种方式：

| 方式 | 内容 | 粒度 |
|------|------|------|
| 结构化日志 | `slog.Logger` 记录开始/结束/错误 | 每个订阅源 |
| HTTP Status API | `/control/filtering/status` 返回元数据 | 每个订阅源 |

### 12.2 日志指标（Log-based Metrics）

刷新链路中通过 `slog.Logger` 输出的关键日志：

| 日志级别 | 位置 | 事件 | 字段 |
|---------|------|------|------|
| `Debug` | `filter.go:420-422` | 刷新开始/结束 | `updated=N` |
| `Info` | `filter.go:602` | 保存内容成功 | `id`, `path` |
| `Info` | `filter.go:610-616` | 单个订阅源更新完成 | `id`, `bytes_written`, `rules_count` |
| `Info` | `filter.go:380-386` | 回写元数据完成 | `id`, `rules_count`, `prev_rules_count` |
| `Error` | `filter.go:349` | 单个订阅源更新失败 | `url`, `error` |
| `Error` | `filter.go:492` | 更新文件 mtime 失败 | `error` |
| `Debug` | `filter.go:596` | 无变化跳过 | `id`, `url` |

**可通过日志采集间接获得**：
- 刷新成功率 = （Info 条数）/ （Info + Error 条数）
- 刷新耗时 = 同一次刷新中 "starting update" 到 "finished update" 的时间差
- 错误类型分布 = Error 日志的 `error` 字段分类

但这些都需要外部日志系统（如 ELK、Loki）做聚合，模块本身不提供统计能力。

### 12.3 HTTP Status API 的可用字段

`GET /control/filtering/status` 返回结构（`http.go:415-421`）：

```json
{
  "filters": [
    {
      "id": 1,
      "enabled": true,
      "url": "https://...",
      "name": "AdGuard Simplified Domain Names filter",
      "rules_count": 56789,
      "last_updated": "2024-01-15T10:30:00Z"
    }
  ],
  "whitelist_filters": [...],
  "user_rules": ["..."],
  "interval": 24,
  "enabled": true
}
```

**能从中推断的信息**：
- `rules_count`：每个订阅源的规则量（历史上一次成功刷新的结果）
- `last_updated`：上次更新时间，可推算"距离上次更新多久了"
- `enabled` + `interval`：可推算是否应该已经刷新过

**缺失的指标**：
- ❌ 刷新成功率（success rate）
- ❌ 单次刷新耗时（duration）
- ❌ 连续失败次数（consecutive failures）
- ❌ 错误类型分布（error breakdown）
- ❌ 刷新延迟/调度抖动（scheduling jitter）
- ❌ 引擎重建耗时（engine reload time）

### 12.4 全局 stats 模块 vs 过滤刷新

项目中有 `internal/stats` 模块，提供 `/control/stats` 接口，但它**只统计 DNS 查询层面**的数据：

- 总 DNS 查询数
- 被过滤的查询数（按原因分类：广告、成人、安全浏览等）
- 热门域名排行
- 客户端查询统计
- 按时间单位（小时/天）聚合

**完全不包含**过滤列表刷新的成功率、耗时、错误数等运维指标。

### 12.5 新架构（rulelist）的 metrics 现状

新架构 `rulelist.Engine` / `rulelist.Storage` 同样没有 metrics 接口，只有：
- `RulesCount` 属性（当前引擎的规则总数）
- `LastUpdated` 概念（通过刷新时间推断）
- 日志记录刷新事件

### 12.6 小结：当前监控现状与改进空间

| 维度 | 现状 | 可改进方向 |
|------|------|-----------|
| 刷新成功率 | ❌ 无，仅靠日志 | 增加计数器，按订阅源维度统计成功/失败 |
| 刷新耗时 | ❌ 无，仅靠日志 | 增加 Histogram，区分 HTTP 下载/解析/引擎重建 |
| 错误数/类型 | ❌ 无，仅靠日志 | 增加错误类型计数器（网络/解析/磁盘/校验） |
| 调度间隔 | ⚠️ 可通过 status API 间接推断 | 增加下次刷新时间戳 |
| 引擎规则总数 | ✅ 通过 status API 可获得 | 保持现状 |
| Prometheus 格式 | ❌ 完全没有 | 增加 `/metrics` 端点或接入全局 metrics |

---

## 13. 异常场景分析：ctx 取消、锁泄漏、文件状态与 atomic 失败回滚

### 13.1 ctx 被取消时 updatesLoop 的收尾

#### 13.1.1 实际使用的 ctx：全是 `context.TODO()`，不传递取消信号

代码全量 grep 结果：刷新链路中所有 ctx 创建都来自 `context.TODO()`：

- `refreshFiltersIntl()` `filter.go:417` → `ctx := context.TODO()`
- `update()` `filter.go:481` → `ctx := context.TODO()`
- `Start()` `filtering.go:1087` → `go d.updatesLoop(context.TODO())`
- `Close()` `filtering.go:402` → `d.reset(context.TODO())`

**HTTP Client 未设置请求 ctx**（`filter.go:532` `d.conf.HTTPClient.Get(urlStr)`），也未将链路 ctx 传入 HTTP 请求。

**结论：ctx 取消信号完全没有从外部进入刷新链路的路径。** 用户取消 API 请求不会中断正在进行的刷新；刷新 goroutine 本身也无法因 ctx 超时而提前退出。

#### 13.1.2 真正的退出机制：`done` 通道 + `Close()`

退出路径（`filtering.go:394-402`）：

```go
func (d *DNSFilter) Close() {
    d.engineLock.Lock()     // 第 1 个锁：防止与 initFiltering/匹配并发
    defer d.engineLock.Unlock()

    if d.done != nil {
        d.done <- struct{}{}   // 发送退出信号
    }

    d.reset(context.TODO())    // 释放引擎
}
```

`updatesLoop` 中的接收（`filtering.go:1131-1137`）：

```go
case doneCh := <-d.done:
    if !t.Stop() { <-t.C }    // 停止并清空定时器
    d.done <- doneCh          // 回写到 done 通道（奇怪的回环）
    return                    // 退出 goroutine
```

#### 13.1.3 异常场景推演：刷新中途收到 done 信号

由于 **三个 select 分支互斥**，有两种情形：

**情形 1：信号到达时，updatesLoop 阻塞在 select 上**（最常见）
- `done` 分支被选中 → `t.Stop()` + `return` → goroutine 正常退出
- ✅ 无资源泄漏

**⚠️ 情形 2：信号到达时，periodicallyRefreshFilters() 正在执行（刷新已启动）**
- select 会**继续阻塞**，直到 `periodicallyRefreshFilters()` 返回
- 期间 `refreshLock` 已被持有、HTTP 请求正在进行、临时文件可能已创建
- 等刷新完成回到 select 后，才消费 `done` 信号退出
- 可能的风险：`Close()` 先 `engineLock.Lock()`，而刷新结束时要 `EnableFilters()` → `initFiltering()` 也要 `engineLock.Lock()` → **潜在死锁**

死锁路径：
```
goroutine A (Close):           goroutine B (updatesLoop 正在刷新):
  engineLock.Lock() ◄──已锁
  done <- struct{}{}
                                   refreshFiltersIntl() 完成
                                   EnableFilters(false)
                                     enableFiltersLocked → setFilters → initFiltering
                                       engineLock.Lock()  ◄── 永久阻塞！
  d.reset(ctx)  ◄── 永远等不到，因为 B 阻塞在拿 engineLock
```

**但 Close 中的 `done <- doneCh` 回环使得 B 有机会在进入 EnableFilters 之前先退出 select：** 实际 `updatesLoop` 中 `periodicallyRefreshFilters()` 返回后，会回到 for 循环头的 select 下一轮，此时先读到 done 信号 → return，EnableFilters 不再被执行。**这个回环是有意设计的死锁规避手段。**

#### 13.1.4 小结

| 问题 | 结果 |
|------|------|
| ctx 取消能否中断刷新？ | ❌ 不能。全部 ctx=TODO，HTTP 也没传 ctx |
| 如何退出？ | `Close()` → `done` 通道 |
| goroutine 泄漏？ | ✅ 无。回环确认最终退出 |
| 死锁风险？ | ⚠️ Close 与刷新中 EnableFilters 存在理论死锁，done 回环规避之 |
| done 通道泄漏？ | ❓ done 容量=1。若没人 Close，通道不会关；Close 后可重复写/读。（可接受） |

---

### 13.2 锁与文件状态的泄漏风险

#### 13.2.1 各类锁的获取-释放配对检查

| 锁 | 获取位置 | 释放方式 | 异常路径覆盖 | 泄漏可能 |
|----|---------|---------|-------------|---------|
| `refreshLock` | `tryRefreshFilters()` TryLock | `defer unlock`（同一函数内） | ✅ defer 覆盖所有 return | ❌ 无 |
| `conf.filtersMu` (R) | `listsToUpdate()` RLock | `defer RUnlock` | ✅ defer | ❌ 无 |
| `conf.filtersMu` (R) | `EnableFilters()` RLock | `defer RUnlock` | ✅ defer | ❌ 无 |
| `conf.filtersMu` (W) | `refreshFiltersArray()` Lock | `defer Unlock` | ✅ defer | ❌ 无 |
| `conf.filtersMu` (W) | `filterAdd/Del/SetProps/HandleSetURL` Lock/RLock | `defer Unlock/RUnlock` | ✅ defer | ❌ 无 |
| `filtersInitializerLock` | `setFilters()` Lock | `defer Unlock` | ✅ defer | ❌ 无 |
| `engineLock` (R) | `matchHost/ApplyBypassSafesearch` 等匹配 | `defer RUnlock` | ✅ defer | ❌ 无 |
| `engineLock` (W) | `initFiltering()` 内匿名函数 Lock | `defer Unlock` | ✅ defer | ❌ 无 |
| `engineLock` (W) | `Close()` 入口 Lock | `defer Unlock` | ✅ defer | ❌ 无 |

**结论：** 所有锁都用 `defer` 确保释放，且均在同一函数内获取/释放，没有跨越 goroutine 或未配对的情况。正常流程和所有 panic 路径（被 defer 覆盖）都安全。

#### 13.2.2 临时文件状态的泄漏风险

**临时文件生命周期**：

| 事件 | 调用 | 位置 |
|------|------|------|
| 创建 | `NewPendingFile(flt.Path(dataDir), 0644)` | `filter.go:506` |
| 写入 | `Parser.Parse(tmpFile, src, buf)` → tmpFile.Write() | `parser.go:49` |
| 无变化时清理 | `file.Cleanup()`（close + unlink tmp file） | `filter.go:599` |
| 有变化时替换 | `file.CloseReplace()`（close + atomically rename） | `filter.go:604` |
| 中途异常清理 | `errors.WithDeferred(returned, file.Cleanup())` | `filter.go:599`（`!updated` 分支） |

**底层实现（Unix）**：`google/renameio/v2` 的 `PendingFile`：
- 在同目录创建 `.tmp-<rand>-<name>`
- `Cleanup()` 会 `os.Remove` 该文件
- `CloseReplace()` 完成 `fsync` + `rename`（POSIX rename 原子覆盖）

**异常路径检查**：

| 异常点 | 文件状态 | 最终结果 |
|--------|---------|---------|
| 创建前（URL 错误、NewPendingFile 失败） | 无文件 | ✅ 无泄漏 |
| 创建后，Parser.Parse() 中途出错 | 部分写的 tmp 文件存在 | ✅ 走 `!updated` 分支 `errors.WithDeferred(returned, Cleanup())` 清理 |
| finalizeUpdate 前 goroutine panic | tmp 文件留在磁盘 | ❗ defer 未覆盖此路径！Go defer 在同 goroutine 内生效，panic 会触发 defer；**但若进程被 SIGKILL 杀**，tmp 文件残留 |
| CloseReplace() 中 rename 失败（跨盘/权限） | tmp 文件 + 原文件均保留 | ✅ 返回 err 给上层，调用方不会同步元数据，下次刷新重试 |
| 断电 / 崩溃 | tmp 文件残留 | ❗ 重启后留存在 `dataDir/filters/`，不再被引用但占空间 |

**残留 tmp 文件的影响**：每次刷新产生一个新随机名 tmp，`.tmp-*-<id>.txt` 文件可能累积。可通过定期清理 `dataDir/filters/` 下非 `<id>.txt` 命名的文件来处理。

---

### 13.3 atomic（CloseReplace）失败场景：缓存与锁的回滚分析

#### 13.3.1 atomic 更新失败的触发条件

Unix 上 `CloseReplace()` = `renameio.PendingFile.CloseAtomicallyReplace()` 内部：
```
fsync(tmpFd) → close(tmpFd) → rename(tmpPath, targetPath)
```

可能失败的情况：
1. **fsync 失败**：磁盘 IO 错误、磁盘满
2. **rename 失败**：跨设备（EXDEV）、目标目录权限、target 在写入中被另一个进程删改

#### 13.3.2 失败后的代码行为（`filter.go:585-622`）

```go
func (d *DNSFilter) finalizeUpdate(...) (err error) {
    if !updated {
        return errors.WithDeferred(returned, file.Cleanup())  // 路径 A
    }

    err = file.CloseReplace()    // 路径 B：这里失败
    if err != nil {
        return fmt.Errorf("finalizing update: %w", err)  // ⬅️ 直接 return！
    }
    // 以下（元数据更新）不再执行
    flt.ensureName(res.Title)
    flt.checksum = res.Checksum
    flt.RulesCount = rulesCount
    return nil
}
```

**关键：CloseReplace 失败时 `return err`，后面的元数据更新（`ensureName`、`checksum`、`RulesCount`）被跳过！**

#### 13.3.3 锁状态分析

| 锁 | CloseReplace 失败时状态 | 是否需要回滚 |
|----|-------------------------|-------------|
| `refreshLock` | ✅ 由外层 tryRefreshFilters 的 defer 释放 | 不需要 |
| `conf.filtersMu` | ⬅️ 此阶段还没拿！要在 syncUpdatedFilters 前才拿 | 不需要 |
| `engineLock` | 此阶段还没碰！ | 不需要 |

**结论：** atomic 失败不涉及任何锁的释放问题。所有相关锁在更外层或更内层的 defer 保护下。

#### 13.3.4 缓存与状态回滚检查

**1）副本 `updateFilters[i]` 的状态（内存）：**
- `LastUpdated` 已被 `update()` 设为 `time.Now()`（无论成功失败，`filter.go:484`）
- `Name`/`checksum`/`RulesCount`：仍为旧值（CloseReplace 失败时跳过）
- **错位副作用 A**：`LastUpdated` 已更新为"现在"，但实际内容没更新 → 下次定时刷新要等完整 Interval 后才重试该条目！force=true 才会绕过。

**2）主列表 `conf.Filters` 的状态（内存）：**
- `syncUpdatedFilters` 中 `updated == updateFlags[i]`，而 `updateFlags[i]` 是 `d.update()` 返回的 `b`
- 关键：`d.update()` 返回的 `b` = `updateIntl()` 返回值 = `res.Checksum != flt.checksum` → 在 CloseReplace 之前就已决定
- 如果**内容确实不同（b=true）但 CloseReplace 失败**，则：
  - `updateFlags[i]=true`
  - `syncUpdatedFilters` 会尝试同步元数据（`Name/RulesCount/checksum`）
  - 但副本中这三个字段没被更新（仍为旧值） → **结果：主列表元数据也不变**
  - ✅ `LastUpdated` 无条件同步 → 与副本一致（同为错误的"现在"）

**3）磁盘文件状态：**
- **tmp 文件**：renameio 内部 CloseAtomicallyReplace 出错时，会尝试 `Cleanup()` 删除 tmp（取决于具体失败阶段）
  - fsync 前失败：tmp 删除 ✅
  - fsync 后、rename 前失败：tmp 可能残留 ❗（renameio 文档说明"尽力而为"）
- **旧文件 <id>.txt**：未动，仍是之前的版本 ✅
- **缓存一致性**：主列表的 checksum 还是旧值，磁盘文件也是旧内容 → **内存元数据和磁盘内容一致**（这点没问题）

**4）过滤引擎状态：**
- `updNum`：syncUpdatedFilters 返回的 updateCount
- 由于副本 checksum 没更新 → syncUpdatedFilters 中 `uf.RulesCount == f.RulesCount`（没变） → `updateCount` 可能不会增加？
  - 实际：`updateCount++` 只看 `updateFlags[i]==true`（不看值是否变了），所以 b=true 时 updNum 仍增加
- 所以 `EnableFilters(false)` 会被调用（`filter.go:452`）
- `enableFiltersLocked` 会按 FilePath（`<id>.txt`）重新加载引擎 → 加载的是**旧文件**（因为 rename 失败）
- 但此时主列表 `f.RulesCount` 还是旧值（与旧文件实际内容一致）
- **结论：引擎实际内容是正确的（旧版本），但系统误以为"完成了一次更新"**

#### 13.3.5 错位副作用汇总表

| 错位副作用 | 现象 | 影响 | 严重度 |
|-----------|------|------|--------|
| A. LastUpdated 前移 | 不管成功失败都写 `time.Now()` | 该条目下一个 Interval 周期内不再重试 | 中 |
| B. 误判更新成功 | `updNum` 计数增加（因为 b=true），但实际文件没变 | 触发一次无意义的引擎重建；日志中 `filter updated` 但实际无变化 | 低 |
| C. 调度间隔被推长 | 由于 `!isNetErr`（CloseReplace 非网络错误），`periodicallyRefreshFilters` 设 `ivl=1h` | 下一轮定时刷新仍然是 1 小时，不影响 Interval 内的重试 | 低 |
| D. tmp 文件残留（极端） | fsync 后 rename 前失败 | 磁盘占空间；下次刷新生成新 tmp，旧 tmp 成为孤儿 | 低 |

**无回滚动作**：代码中没有针对 CloseReplace 失败的补偿逻辑（不 rollback LastUpdated、不 decrement updNum、不重新 try rename 等）。所有"状态回滚"实际上都是依赖"元数据未更新 → 自然不一致被最小化"。

---

## 14. 异常场景下的改进建议（代码潜在问题）

基于上述分析，当前实现中可考虑优化的点：

### 14.1 LastUpdated 前移问题（错位副作用 A）
将 `filter.LastUpdated = time.Now()` 从 `update()` 无条件赋值，改为仅在 `updated=true || (err == nil && !updated)` 时赋值，或从 `finalizeUpdate` 内部在 CloseReplace 成功后赋值。

### 14.2 updNum 虚增问题（错位副作用 B）
`updateFlags[i]` 的取值应结合 CloseReplace 成功与否：`b = updateIntl()` 只表示 checksum 不同，不等于最终更新成功。建议引入"最终成功"标志或在 syncUpdatedFilters 中同时读取 `f.RulesCount != uf.RulesCount`（实际上更可靠）。

### 14.3 ctx 传递链路
考虑将 `updatesLoop(context.TODO())` 改为使用可取消的 ctx，配合 `http.NewRequestWithContext` 让 Close/退出时能够中断进行中的 HTTP 请求。

---

## 15. 关键代码索引（已校准行号，更新版）

| 功能 | 精确定位 |
|------|----------|
| `FilterYAML` 结构定义 | `internal/filtering/filter.go:33` |
| `Filter` 基础结构 | `internal/filtering/filtering.go:307` |
| `filtersInitializerParams` 结构 | `internal/filtering/filtering.go:236` |
| `DNSFilter` 核心结构 | `internal/filtering/filtering.go:253` |
| 调度启动 `Start()` | `internal/filtering/filtering.go:1077` |
| 主循环 `updatesLoop()` | `internal/filtering/filtering.go:1087` |
| 周期调整 `periodicallyRefreshFilters()` | `internal/filtering/filtering.go:1115` |
| 刷新锁入口 `tryRefreshFilters()` | `internal/filtering/filter.go:265` |
| 内部刷新 `refreshFiltersIntl()` | `internal/filtering/filter.go:416` |
| 筛选待更新列表 `listsToUpdate()` | `internal/filtering/filter.go:277` |
| 单源更新入口 `update()` | `internal/filtering/filter.go:480` |
| 内容更新 `updateIntl()` | `internal/filtering/filter.go:501` |
| HTTP 下载解析 `readFromHTTP()` | `internal/filtering/filter.go:532` |
| 文件读取解析 `readFromFile()` | `internal/filtering/filter.go:558` |
| 更新收尾 `finalizeUpdate()` | `internal/filtering/filter.go:585` |
| 元数据回写 `syncUpdatedFilters()` | `internal/filtering/filter.go:359` |
| URL 去重 `deduplicateFilters()` | `internal/filtering/filter.go:245` |
| ID 去重 `idGenerator.fix()` | `internal/filtering/idgenerator.go:47` |
| Parser 解析入口 `Parse()` | `internal/filtering/rulelist/parser.go:49` |
| ParseResult 结构 | `internal/filtering/rulelist/parser.go:31` |
| 校验和计算行 | `internal/filtering/rulelist/parser.go:120` |
| 启用过滤器 `EnableFilters()` | `internal/filtering/filter.go:664` |
| 异步/同步设置 `setFilters()` | `internal/filtering/filtering.go:359` |
| 引擎重建 `initFiltering()` | `internal/filtering/filtering.go:746` |
| 主程序创建 DNSFilter | `internal/home/dns.go:103` |
| 主程序启动 `filters.Start()` | `internal/home/dns.go:491` |
| 新架构 Filter 定义 | `internal/filtering/rulelist/filter.go:26` |
| 新架构 Engine 定义 | `internal/filtering/rulelist/engine.go:21` |
| 新架构 Engine.Refresh() | `internal/filtering/rulelist/engine.go:108` |
| 新架构 Storage 定义 | `internal/filtering/rulelist/storage.go:16` |
| 手动刷新 HTTP Handler | `internal/filtering/http.go:366` |
| 添加订阅源 HTTP Handler | `internal/filtering/http.go:65` |
| 刷新数组 `refreshFiltersArray()` | `internal/filtering/filter.go:313` |
| 更新列表循环 `updateFilterList()` | `internal/filtering/filter.go:339` |
| 移除旧文件 `removeOldFilterFile()` | `internal/filtering/filter.go:465` |
| 关闭清理 `Close()` | `internal/filtering/filtering.go:394` |
| done 回环（死锁规避） | `internal/filtering/filtering.go:1131-1137` |
| enableFiltersLocked（启用内部） | `internal/filtering/filter.go:672` |
| PendingFile 接口定义 | `internal/aghrenameio/renameio.go:20` |
| Unix CloseReplace（atomic rename） | `internal/aghrenameio/renameio_unix.go:27` |
| 查询匹配读锁 `matchHost()` | `internal/filtering/filtering.go:904` |
| 引擎替换写锁 `initFiltering()` | `internal/filtering/filtering.go:761` |
| 配置修改 Handler `handleFilteringConfig` | `internal/filtering/http.go:462` |
| 状态查询 Handler `handleFilteringStatus` | `internal/filtering/http.go:442` |
| 合并推送 `removeLoop` 清空逻辑 | `internal/filtering/filtering.go:372` |
| `filterToJSON` 状态序列化 | `internal/filtering/http.go:425` |
| 手动刷新 Handler `handleFilteringRefresh` | `internal/filtering/http.go:366` |
| `filterSetProperties` 设属性 | `internal/filtering/filter.go:220` |
| `filterAdd` 添加订阅源 | `internal/filtering/filter.go:200` |
| `filterDel` 删除订阅源 | `internal/filtering/filter.go:228` |

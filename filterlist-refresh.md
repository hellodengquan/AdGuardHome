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

## 9. 关键代码索引（已校准行号）

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

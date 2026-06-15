# AdGuardHome 黑白名单远端订阅、定时刷新及增量合并流程分析

## 1. 概述

AdGuardHome 的黑白名单过滤系统由三大部分组成：远端订阅源管理、定时刷新调度、增量合并与去重。三者协作完成了从订阅源获取、定时更新到最终合并应用的完整生命周期。

核心代码位于 `internal/filtering/` 目录下，涉及的关键文件：

| 文件 | 职责 |
|------|------|
| `filtering.go` | 核心服务结构定义、主刷新调度入口 |
| `filter.go` | 订阅源定义、刷新流程、增量合并、去重逻辑 |
| `http.go` | HTTP API 接口、手动刷新触发 |
| `rulelist/parser.go` | 规则解析、校验和计算 |
| `rulelist/filter.go` | 新架构下的 Filter 定义与单个订阅源刷新 |
| `rulelist/engine.go` | 过滤引擎构建、批量刷新 |
| `rulelist/storage.go` | 引擎存储管理 |
| `idgenerator.go` | 过滤列表 ID 生成与去重 |

---

## 2. 远端订阅源管理

### 2.1 数据结构定义

订阅源由 `FilterYAML` 结构定义（`internal/filtering/filter.go:30`）：

```go
type FilterYAML struct {
    Enabled     bool
    URL         string    // URL 或本地文件路径
    Name        string    // 订阅源名称
    RulesCount  int       // 规则数量
    LastUpdated time.Time // 上次更新时间
    checksum    uint32    // 文件数据的 CRC-32 校验和
    white       bool      // 是否为白名单

    Filter `yaml:",inline"` // 内嵌基础 Filter 结构（包含 ID、FilePath、Data）
}
```

其中 `Filter` 基础结构（`internal/filtering/filtering.go:306`）：

```go
type Filter struct {
    FilePath string          // 过滤规则文件路径
    Data     []byte       // 文件内容
    ID       rules.ListID // 自动分配的唯一 ID
}
```

### 2.2 订阅源分类与存储

黑白名单分别存储在两个独立的切片中（`internal/filtering/filtering.go:145`）：

- **黑名单（Blocklist）：`d.conf.Filters []FilterYAML`
- **白名单（Allowlist）：`d.conf.WhitelistFilters []FilterYAML`

### 2.3 订阅源操作 API

HTTP API 入口在 `internal/filtering/http.go` 中定义，主要接口：

| 方法 | 路径 | 功能 |
|------|------|------|
| POST | `/control/filtering/add_url` | 添加订阅源 |
| POST | `/control/filtering/remove_url` | 删除订阅源 |
| POST | `/control/filtering/set_url` | 更新订阅源属性 |
| POST | `/control/filtering/refresh` | 手动触发刷新 |
| GET | `/control/filtering/status` | 获取过滤配置状态 |

### 2.4 添加订阅源流程

添加订阅源的调用链（`internal/filtering/http.go:65`）：

1. `handleFilteringAddURL()` - 接收 HTTP 请求
2. `validateFilterURL()` - 校验 URL 合法性（支持 HTTP/HTTPS 和本地绝对路径）
3. `filterExists()` - 检查 URL 重复检测
4. `d.update()` - 下载并解析订阅内容
5. `filterAdd()` - 加入配置列表
6. `EnableFilters()` - 重新加载过滤引擎

URL 合法性校验逻辑（`internal/filtering/http.go:26`）：

- 本地文件路径：校验路径匹配安全模式 `SafeFSPatterns
- 远程 URL：校验 HTTP/HTTPS 协议

---

## 3. 定时刷新调度

### 3.1 调度器启动

定时刷新在 `DNSFilter.Start()` 中启动（`internal/filtering/filtering.go:1077`）：

```go
func (d *DNSFilter) Start() {
    d.filtersInitializerChan = make(chan filtersInitializerParams, 1)
    d.done = make(chan struct{}, 1)
    d.RegisterFilteringHandlers()
    go d.updatesLoop(context.TODO())  // 启动定时刷新循环
}
```

### 3.2 主循环 `updatesLoop()`

主循环逻辑（`internal/filtering/filtering.go:1086`）采用多路复用模式处理三类事件：

```
┌─────────────────────────────────────────────────────────────┐
│                  updatesLoop()                        │
├─────────────────────────────────────────────────────────────┤
│                                                   │
│  select {                                         │
│  ├── filtersInitializerChan: 异步初始化新过滤器     │
│  ├── t.C (定时器): 定期检查并执行刷新           │
│  └── done: 退出信号                           │
│  }                                               │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 刷新周期动态调整策略 `periodicallyRefreshFilters()`

核心逻辑（`internal/filtering/filtering.go:1115`）：

```go
func (d *DNSFilter) periodicallyRefreshFilters(ivl time.Duration) (nextIvl time.Duration) {
    const maxInterval = time.Hour

    if d.conf.FiltersUpdateIntervalHours == 0 {
        return ivl  // 禁用自动刷新
    }

    isNetErr, ok := d.tryRefreshFilters(true, true, false)

    if ok && !isNetErr {
        ivl = maxInterval  // 成功后：1 小时
    } else if isNetErr {
        ivl *= 2           // 网络错误：指数退避，最长 max(ivl, maxInterval)
    }

    return ivl
}
```

调度策略总结：

| 场景 | 初始间隔 | 调整后间隔 |
|------|----------|-------------|
| 刷新成功 | 5秒 | 1小时 |
| 网络错误 | 5秒 | 指数退避（翻倍），上限1小时 |
| 刷新配置禁用 | - | 保持当前值 |
| 刷新锁被占用 | - | 保持当前值 |

### 3.4 刷新锁机制

使用 `sync.Mutex.TryLock()` 实现非阻塞锁（`internal/filtering/filter.go:265`）：

```go
func (d *DNSFilter) tryRefreshFilters(block, allow, force bool) (updated int, isNetworkErr, ok bool) {
    if ok = d.refreshLock.TryLock(); !ok {
        return 0, false, false  // 刷新正在进行，直接返回
    }
    defer d.refreshLock.Unlock()

    updated, isNetworkErr = d.refreshFiltersIntl(block, allow, force)
    return updated, isNetworkErr, true
}
```

该机制确保同一时刻只有一个刷新流程在执行，避免重复刷新。

---

## 4. 增量合并与去重

### 4.1 增量判断：CRC-32 校验和机制

通过对比新旧内容的 CRC-32 校验和判断是否需要更新：

**校验和计算在规则解析时计算（`internal/filtering/rulelist/parser.go:120`）：

```go
p.checksum = crc32.Update(p.checksum, crc32.IEEETable, trimmed)
```

增量判断逻辑（`internal/filtering/filter.go:501` `updateIntl()`）：

```go
// 下载并解析新内容，获取新校验和 res.Checksum

return res.Checksum != flt.checksum, nil  // 校验和不同才认为有变化
```

只有当校验和不相同时，才执行后续的文件替换和引擎重载。

### 4.2 规则解析与清理

`rulelist.Parser 负责在下载/读取时进行预处理（`internal/filtering/rulelist/parser.go:49`）：

解析处理内容清理操作：

1. **去除空行**：跳过长度为 0 的行
2. **去除注释**：以 `#` 或 `!` 开头的行
3. **提取标题**：识别 `! Title: xxx` 格式的标题行
4. **二进制检测**：检测非打印字符，防止加载
5. **HTML 检测**：识别 HTML 内容，防止错误内容报错
6. **规范化**：去除首尾空白，统一换行符

解析结果结构 `ParseResult`（`internal/filtering/rulelist/rulelist/parser.go:31`）：

```go
type ParseResult struct {
    Title        string // 标题
    RulesCount   int    // 有效规则数
    BytesWritten int    // 写入字节数
    Checksum     uint32 // CRC-32 校验和
}
```

### 4.3 URL 级别去重

**初始化时去重 `deduplicateFilters()`（`internal/filtering/filter.go:245`）：

```go
func deduplicateFilters(filters []FilterYAML) (deduplicated []FilterYAML) {
    urls := container.NewMapSet[string]()
    lastIdx := 0
    for _, filter := range filters {
        if !urls.Has(filter.URL) {
            urls.Add(filter.URL)
            filters[lastIdx] = filter
            lastIdx++
        }
    }
    return filters[:lastIdx]
}
```

基于 URL 的去重，保留首次出现的订阅源。

### 4.4 ID 级别去重

`idGenerator.fix()`（`internal/filtering/idgenerator.go:47`）：

- 为 ID 为 0 的过滤器分配新 ID
- 检测重复 ID 的过滤器重新分配新 ID
- 使用 Set 保证所有 ID 唯一

### 4.5 原子文件更新

使用 `aghrenameio.PendingFile 实现原子文件替换（`internal/filtering/filter.go:506`）：

```
临时文件
    ↓
写入解析后的内容
    ↓
CloseReplace() 原子替换
```

流程：
1. 创建临时待处理文件 `<id>.txt.tmp
2. 写入解析后内容
3. 成功：`CloseReplace()` 原子重命名为 `<id>.txt
4. 失败：`Cleanup()` 删除临时文件

保证在 `finalizeUpdate()`（`internal/filtering/filter.go:585`）根据 `updated` 标志决定执行替换或清理。

---

## 5. 完整刷新流程

### 5.1 调用链总览

```
Start()
  │
  ▼
updatesLoop() [goroutine]
  │
  ├── 定时器触发
  │     │
  │     ▼
  │   periodicallyRefreshFilters()
  │     │
  │     ▼
  │   tryRefreshFilters()  [TryLock 获取刷新锁
  │     │
  │     ▼
  │   refreshFiltersIntl()
  │     │
  │     ├── listsToUpdate()  筛选需更新的列表
  │     │     │  检查 Enabled
  │     │     │  检查 LastUpdated + interval 是否过期
  │     │     │
  │     │     ▼
  │     │   updateFilterList()  逐个更新每个订阅源
  │     │     │
  │     │     ▼
  │     │   update()
  │     │     │
  │     │     ├── updateIntl()
  │     │     │     │
  │     │     │     ├── readFromHTTP() / readFromFile()
  │     │     │     │     │
  │     │     │     │     ▼
  │     │     │     │   Parser.Parse()  解析+校验和计算
  │     │     │     │
  │     │     │     ▼
  │     │     │   对比校验和是否变化
  │     │     │
  │     │     ▼
  │     │   finalizeUpdate()
  │     │     ├── 无变化：Cleanup 临时文件
  │     │     └── 有变化：CloseReplace 原子替换 + 更新元数据
  │     │
  │     ▼
  │   syncUpdatedFilters()  同步元数据回写到主列表
  │     │
  │     ▼
  │   EnableFilters()
  │     │
  │     └── setFilters() / initFiltering()  重建过滤引擎
  │
  └── 手动刷新（HTTP 触发同样流程同上
```

### 5.2 刷新详细步骤

**步骤 1：筛选待更新列表 `listsToUpdate()`（`internal/filtering/filter.go:277`）

```go
func (d *DNSFilter) listsToUpdate(filters *[]FilterYAML, force bool) (toUpd []FilterYAML)
```

筛选条件：
- `Enabled == true`
- `force == true` 或 `now >= LastUpdated + FiltersUpdateIntervalHours`

**步骤 2：批量更新 `updateFilterList()`（`internal/filtering/filter.go:339`）

对每个待更新的订阅源执行 `d.update(uf)

**步骤 3：单个订阅源更新 `update()`（`internal/filtering/filter.go:480`）

```go
func (d *DNSFilter) update(filter *FilterYAML) (b bool, err error) {
    b, err = d.updateIntl(ctx, filter)      // 实际更新内容
    filter.LastUpdated = time.Now()       // 无论成功失败，更新时间戳
    if !b {
        os.Chtimes(...)  // 无变化，更新文件时间戳
    }
    return b, err
}
```

**步骤 4：内容更新 `updateIntl()`（`internal/filtering/filter.go:501`）

- 创建临时文件
- 根据 URL 类型选择读取方式：
  - 本地绝对路径：`readFromFile()`
  - 远程 URL：`readFromHTTP()`
- 对比新旧校验和返回是否有变化

**步骤 5：HTTP 下载与解析 `readFromHTTP()`（`internal/filtering/filter.go:532`）

```go
resp, err := d.conf.HTTPClient.Get(urlStr)
// 检查 StatusCode == 200
// LimitReader(resp.Body, MaxHTTPSize)
Parser.Parse(tmpFile, httpBody, buf)
```

**步骤 6：最终完成更新 `finalizeUpdate()`（`internal/filtering/filter.go:585`）

| updated=false：
```go
if !updated {
    return file.Cleanup()  // 删除临时文件，保留旧文件
}
```

updated=true：
```go
file.CloseReplace()  // 原子替换
flt.ensureName(res.Title)
flt.checksum = res.Checksum
flt.RulesCount = rulesCount
```

**步骤 7：同步回写 `syncUpdatedFilters()`（`internal/filtering/filter.go:359`）

遍历更新后的订阅源列表，匹配 ID+URL，同步 `LastUpdated
如有变化，同步 Name/RulesCount/checksum

**步骤 8：重建引擎 `EnableFilters()`（`internal/filtering/filter.go:664`）

```go
func (d *DNSFilter) EnableFilters(async bool) {
    // 收集所有启用的过滤器（含自定义规则）
    // setFilters() → initFiltering()
    // 重建：
    //   rulesStorage (block) + filteringEngine (block)
    //   rulesStorageAllow (allow) + filteringEngineAllow (allow)
}
```

引擎重建过程 `initFiltering()`（`internal/filtering/filtering.go:746`）：

```go
rulesStorage, err := newRuleStorage(blockFilters)
rulesStorageAllow, err := newRuleStorage(allowFilters)
filteringEngine := urlfilter.NewDNSEngine(rulesStorage)
filteringEngineAllow := urlfilter.NewDNSEngine(rulesStorageAllow)
// 加锁替换旧引擎
```

---

## 6. 新架构（rulelist 包）架构

AdGuardHome 同时存在两套架构：**旧架构**（`filtering.go`/`filter.go`）和**新架构**（`rulelist/`）正在逐步迁移中。

### 6.1 新架构核心组件

| 组件 | 文件 | 职责 |
|------|------|------|
| `rulelist.Filter | `rulelist/filter.go` | 单个订阅源（支持 http/https/file |
| `rulelist.Engine` | `rulelist/engine.go` | 单引擎（组合多个 Filter） |
| `rulelist.Storage` | `rulelist/storage.go` | 黑白双引擎 + 自定义规则存储 |
| `rulelist.Parser` | `rulelist/parser.go` | 规则解析器 |

### 6.2 新架构刷新流程

`Engine.Refresh()（`rulelist/engine.go:108`）：

```go
func (e *Engine) Refresh(...) (err error) {
    filtersToRefresh := 所有启用的 Filter
    engineRefresh.process(filtersToRefresh)
      │
      └── 逐个 Filter.Refresh()
      │     ├── setFromHTTP() / setFromFile()
      │     ├── Parser.Parse() 解析+校验和
      │     └── 校验和对比（若有变化更新元数据
      │
    filterlist.NewRuleStorage(ruleLists) 构建规则存储
    e.resetStorage()  原子替换引擎
}
```

### 6.3 两套架构对比

| 特性 | 旧架构 | 新架构 |
|------|---------|---------|
| 调度 | `updatesLoop()` + timer | 外部调用 `Storage.Refresh()` |
| 锁 | `refreshLock` Mutex | `refreshMu` Mutex |
| 校验和 | CRC-32 | CRC-32 |
| 原子文件 | `aghrenameio.PendingFile | `aghrenameio.PendingFile |
| 引擎 | `urlfilter.DNSEngine | `urlfilter.DNSEngine |
| ID 去重 | `idGenerator` | `rules.ListID |
| 黑白名单 | 两个独立列表 | allow/block 两个 Engine |

---

## 7. 协作关系总结

三者之间的协作关系可以总结为：

```
┌──────────────────────────┐
│   远端订阅源        │
│  (FilterYAML)         │
└──────────┬───────────┘
           │
           │  URL/Enabled/LastUpdated/checksum
           │
           ▼
┌──────────────────────────┐
│   定时刷新调度        │
│  (updatesLoop)        │
└──────────┬───────────┘
           │
           │  listsToUpdate → 筛选过期
           │  update → 下载+解析
           │  校验和对比
           │
           ▼
┌──────────────────────────┐
│  增量合并与去重      │
│  (Parser/deduplicate   │
│  idGenerator.fix    │
└──────────┬───────────┘
           │
           │  EnableFilters → initFiltering
           │  重建过滤引擎
           │
           ▼
┌──────────────────────────┐
│   DNS 过滤引擎          │
│  (urlfilter.DNSEngine) │
└──────────────────────────┘
```

**关键协作点：**

1. **订阅源 → 调度**：调度器从订阅源列表读取 `Enabled`、`LastUpdated`、`URL` 判断是否需要刷新

2. **调度 → 合并**：调度调用 Parser 解析下载内容，计算新 Parser 去重（URL/ID/checksum 对比判断增量

3. **合并 → 订阅源**：合并去重后更新订阅源元数据（Name/RulesCount/checksum/LastUpdated

4. **合并 → 引擎**：`EnableFilters()` 收集所有启用的订阅源，重建过滤引擎

5. **并发安全机制：

- `conf.filtersMu RWMutex 保护配置读写
- refreshLock Mutex 保证刷新串行化
- engineLock RWMutex 保护引擎切换

---

## 8. 关键代码索引

| 功能 | 文件:行号 |
|------|-----------|
| 订阅源结构定义 | `internal/filtering/filter.go:30 |
| 调度启动 | `internal/filtering/filtering.go:1077 |
| 主循环 | `internal/filtering/filtering.go:1086 |
| 周期调整 | `internal/filtering/filtering.go:1115 |
| 刷新锁 | `internal/filtering/filter.go:265 |
| 筛选待更新列表 | `internal/filtering/filter.go:277 |
| 单源更新 | `internal/filtering/filter.go:480 |
| HTTP下载 | `internal/filtering/filter.go:532 |
| 文件读取 | `internal/filtering/filter.go:558 |
| 原子更新完成 | `internal/filtering/filter.go:585 |
| 同步元数据 | `internal/filtering/filter.go:359 |
| URL去重 | `internal/filtering/filter.go:245 |
| ID去重 | `internal/filtering/idgenerator.go:47 |
| 规则解析 | `internal/filtering/rulelist/parser.go:49 |
| 引擎重建 | `internal/filtering/filtering.go:746 |
| 启用过滤器 | `internal/filtering/filter.go:664 |
| 新架构Filter | `internal/filtering/rulelist/filter.go:26 |
| 新架构Engine | `internal/filtering/rulelist/engine.go:21 |
| 新架构Storage | `internal/filtering/rulelist/storage.go:16 |

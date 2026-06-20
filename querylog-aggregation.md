# AdGuard Home 查询日志写盘与统计聚合协同机制分析

## 1. 架构概览

AdGuard Home 的查询日志（Query Log）和统计聚合（Statistics）是两条完全独立的数据处理路径，在 DNS 请求处理流程中并行执行，但在数据结构、存储介质、锁策略上完全解耦，避免了并发高峰时的相互争锁。

```
DNS 请求处理完成
        │
        ▼
processQueryLogsAndStats [dnsforward/stats.go:19-76]
        │
        ├───────────────────────────────────┐
        │                                   │
        ▼                                   ▼
  queryLog.Add(params)                stats.Update(entry)
        │                                   │
        ▼                                   ▼
[内存缓冲区 RingBuffer]               [当前统计单元 unit]
        │                                   │
        ▼                                   ▼
[异步批写 JSON 文件]                [每小时滚动写入 bbolt DB]
```

## 2. 查询日志写盘路径（Query Log Path）

### 2.1 核心数据结构

**queryLog 结构体** [querylog/qlog.go:26-54]

```go
type queryLog struct {
    buffer     *container.RingBuffer[*logEntry]  // 环形内存缓冲区
    bufferLock sync.RWMutex                      // 保护 buffer
    fileFlushLock sync.Mutex                     // 同步 flush 协程
    fileWriteLock sync.Mutex                     // 保护文件写入
    flushPending bool                            // flush 标记
}
```

### 2.2 写盘流程

**Add 入口** [querylog/qlog.go:219-266]

1. 读取配置（无需加锁，使用 confMu.RLock）
2. 参数校验，创建 logEntry
3. **加 bufferLock 写锁**，将 entry 推入 RingBuffer
4. 检查缓冲区是否达到阈值（`buffer.Len() >= memSize`）
5. 若达到阈值且未在 flush 中，启动**异步 goroutine** 执行 flushLogBuffer

**flushLogBuffer 批写** [querylog/querylogfile.go:19-32]

1. **加 fileFlushLock 互斥锁**（防止并发 flush）
2. 调用 encodeEntries：
   - **加 bufferLock 写锁**
   - 将缓冲区所有条目编码为 JSON
   - 清空缓冲区，设置 flushPending = false
   - **释放 bufferLock**
3. 调用 flushToFile：
   - **加 fileWriteLock 互斥锁**
   - 以 O_APPEND 模式打开文件
   - 一次性写入整个 JSON 缓冲区
   - **释放 fileWriteLock**

### 2.3 批写策略关键特性

| 特性 | 实现细节 |
|------|----------|
| **触发条件** | 缓冲区达到配置的 MemSize（默认可能是 1000 条） |
| **批量大小** | 整个缓冲区一次性编码、一次性写入 |
| **异步执行** | flush 在独立 goroutine 中执行，不阻塞请求处理 |
| **锁细粒度** | 三级锁分层保护，持有时间最短化 |

**锁的持有时间分析**：
- `bufferLock`：仅在编码和清空缓冲区时持有（内存操作，微秒级）
- `fileFlushLock`：防止并发 flush（互斥，但不阻塞 Add 路径）
- `fileWriteLock`：仅在磁盘 I/O 时持有（毫秒级，但不阻塞 Add）

### 2.4 Buffer 满时的 Backpressure 丢弃策略

**RingBuffer 底层实现** [golibs/container/ringbuffer.go:4-105]

```go
type RingBuffer[T any] struct {
    buf  []T
    cur  uint
    full bool
}

func (rb *RingBuffer[T]) Push(e T) {
    if len(rb.buf) == 0 {
        return
    }
    rb.buf[rb.cur] = e                 // 直接写入当前指针位置
    rb.cur = (rb.cur + 1) % uint(cap(rb.buf))
    if rb.cur == 0 {                   // 绕回起点时标记 full
        rb.full = true
    }
}
```

**丢弃策略：静默 Drop Tail（覆盖最旧元素）**

| 阶段 | full 标志 | Push 行为 | 是否丢弃 | 丢弃个数 |
|------|-----------|-----------|---------|---------|
| 缓冲区未满前 | `false` | 顺序写入 `buf[0..MemSize-1]` | 否 | 0 |
| 缓冲区第一次绕回 | `false→true` | 写入 `buf[MemSize-1]`，`cur` 归零 | 否 | 0 |
| 缓冲区已满后 | `true` | **直接覆盖** `buf[cur]`（即最早的未被刷写的元素） | **是** | **每次 Push 丢弃 1 条** |

**丢弃个数计算分支——代码中不存在显式分支**：

整个丢弃逻辑完全由环形指针 `cur` + `full` 标志位的数学性质隐式实现：
- 没有 `if overflow { dropCount++ }` 之类的判断分支
- 没有 `dropped` 计数器字段，不累计丢弃总数
- 不打日志、不返回错误、不上报指标
- `Push` 是 `void` 返回类型，调用方 `queryLog.Add` 无法感知是否发生了覆盖

**触发场景与可观测性黑洞**：

当并发高峰期间磁盘 I/O 变慢导致 `flushLogBuffer` 协程来不及消费时：
1. `buffer` 在 `MemSize` 条之后仍持续收到新的 `Push`（因为 `bufferLock` 已被释放，Add 路径不阻塞）
2. 旧条目被**静默覆盖**，上层完全无感知
3. 最终用户在 UI 查询日志时会出现"时间跳变"或"中间时段缺失"，但无任何告警

与 flush 触发阈值的关系：
```go
// [qlog.go:255-256] 触发 flush 的条件是 buffer.Len() >= memSize
if !l.flushPending && fileIsEnabled && l.buffer.Len() >= memSize {
    l.flushPending = true
    go l.flushLogBuffer(...)  // 启动异步 flush
}
```
当 flush 协程已启动但尚未完成 `encodeEntries` 中的 `buffer.Clear()` 时，新到达的 `Push` 仍会覆盖未刷写的旧数据。

### 2.5 RingBuffer 丢弃时的 Prometheus 指标——完全未实现

**结论前置：整个 AdGuard Home 代码库（含 golibs 依赖）既未引入 prometheus/client_golang，也没有任何 metrics 子系统，丢弃计数不存在任何可观测性出口。**

三层证据链：

1. **项目级依赖缺失**：`go.mod` 中搜不到 `prometheus` / `client_golang` / `promhttp` 字样，说明官方发行版根本不提供 Prometheus 指标端点。

2. **golibs RingBuffer 无计数器预留字段**：`golibs/container/ringbuffer.go` 的结构体只有 `buf`、`cur`、`full` 三个字段，`Push` 方法是纯值语义实现（void 返回、无 log、无 atomic），没有 `dropped uint64` 字段可供外部读取。

3. **querylog 包零指标出口**：`internal/querylog` 包中不存在 `metrics`、`counter`、`gauge` 相关 import；`handleQueryLog` HTTP 接口仅返回配置信息和日志查询结果，没有暴露内部统计量的 API。

**运维侧目前唯一可间接观测丢弃的方法**：对比同一时间段内 stats 的 `num_dns_queries` 与 querylog.json 实际行数，差值即近似丢弃量。但这种间接对账受到 §4.4 所述 6 个一致性断层影响，误差可能较大。

#### 2.5.1 querylog_drop_total 告警规则模板——零提供

**结论：`querylog_drop_total` 指标在代码中不存在，因此不可能有配套的告警规则模板。**

全量搜索四层证据：

| 搜索目标 | 搜索范围 | 结果 |
|---------|---------|------|
| `querylog_drop` / `drop_total` 关键词 | 整个代码库 `**/*.go` | 0 匹配 |
| `alerting` / `alert_rules` / `recording_rules` / `prometheus_rules` 关键词 | 整个代码库 `**/*.{go,yml,yaml,json,tmpl,tpl,conf,cfg}` | 0 匹配 |
| `serviceMonitor` / `PodMonitor`（K8s Prometheus Operator CRD） | 整个代码库 `**/*.{go,yml,yaml,json}` | 0 匹配 |
| `prometheus` / `client_golang` / `promhttp` | `go.mod` | 0 匹配 |

此外：
- 项目根目录无 `deploy/` / `kubernetes/` / `charts/` / `monitoring/` / `examples/` 等子目录存放 Prometheus 告警模板
- GitHub 仓库的 Releases 附件中也不含独立的 `*.rules.yml` 文件
- `Dockerfile` 中无暴露 `/metrics` 端口的指令（默认 HTTP 端口 3000 仅提供 Web UI + API）

**如果运维需要自建告警，可行路径**：
1. 在 AdGuard Home 前置一个 metrics exporter（社区项目如 `adguardhome-exporter`），通过 `/control/stats` API 轮询 `num_dns_queries`
2. 在 querylog 侧旁路日志分析工具（如 Filebeat → Logstash → Elasticsearch），统计实际写入行数
3. 在两者之间配置 PromQL 告警：`stats_num_dns_queries - querylog_actual_lines > threshold`
4. 但这种方案本质上仍是"外挂式"，无法感知 RingBuffer 内部的静默覆盖事件

### 2.6 滚动文件策略

**日志滚动** [querylog/querylogfile.go:103-121]

- 每小时检查一次日志文件时间
- 当最早的日志条目超过 RotationIvl 时，将 querylog.json 重命名为 querylog.json.1
- 实际保留时间 = 2 × RotationIvl（新旧两个文件）

## 3. 统计聚合路径（Statistics Path）

### 3.1 核心数据结构

**StatsCtx 结构体** [stats/stats.go:110-151]

```go
type StatsCtx struct {
    currMu *sync.RWMutex       // 保护 curr
    curr   *unit               // 当前统计单元（小时级）
    db     atomic.Pointer[bbolt.DB]  // 嵌入式数据库
    
    confMu *sync.RWMutex       // 保护配置
    limit  time.Duration       // 统计保留时长
}
```

**unit 统计单元** [stats/unit.go:95-129]

```go
type unit struct {
    id          uint32              // 小时级ID（Unix时间/3600）
    domains     map[string]uint64   // 域名请求计数
    blockedDomains map[string]uint64 // 被拦截域名计数
    clients     map[string]uint64   // 客户端请求计数
    nResult     []uint64            // 各类型结果计数
    nTotal      uint64              // 总请求数
    timeSum     uint64              // 总处理时间（微秒）
}
```

### 3.2 聚合流程

**Update 入口** [stats/stats.go:278-303]

1. **加 confMu 写锁**，检查是否启用
2. 参数校验
3. **加 currMu 写锁**
4. 调用 `curr.add(e)` 更新内存中的统计单元：
   - 递增对应域名计数
   - 递增对应客户端计数
   - 递增结果类型计数
   - 更新总请求数和总处理时间
5. **释放 currMu 写锁**

**滚动窗口与持久化** [stats/stats.go:420-502]

`periodicFlush` 协程每秒检查一次：

1. 生成当前小时的 unitID（`time.Now().Unix() / 3600`）
2. 若 ID 变化，说明进入新的一小时：
   - **加 confMu 写锁 + currMu 写锁**
   - 创建新的空 unit，替换 curr
   - 序列化旧 unit 为 unitDB
   - 开启 bbolt 事务
   - 将旧 unit 写入数据库 bucket
   - 删除最旧的 bucket（超过保留期限）
   - 提交事务
   - **释放锁**

### 3.3 滚动窗口关键特性

| 特性 | 实现细节 |
|------|----------|
| **窗口粒度** | 1小时（由 unitID 生成逻辑决定） |
| **窗口切换** | 每秒检查，跨小时时原子切换 |
| **存储介质** | bbolt 嵌入式键值数据库 |
| **数据保留** | 可配置 1/7/30/90 天，自动删除旧 bucket |
| **聚合方式** | 内存实时聚合 + 数据库持久化 |

### 3.4 进程重启时的快照恢复路径

**启动时从 DB 恢复当前小时快照** [stats/stats.go:155-213]

`stats.New()` 在构造阶段就执行快照恢复（注意代码注释 TODO 建议移到 Start 方法）：

```
 进程启动
    │
    ▼
 stats.New(conf)
    │
    ├── openDB()                      ── 打开 stats.db（bbolt）
    │
    ├── id = unitIDGen()              ── 生成当前小时 ID = UnixNow()/3600
    │
    ├── db.Begin(true)                ── 开启写事务
    │     │
    │     ├── deleteOldUnits(tx, id - limit.Hours() - 1)  ── 先清理超期 bucket
    │     │
    │     └── udb = loadUnitFromDB(tx, id)  ── 尝试加载当前小时的已有快照
    │           │
    │           └── bucket.Get([]byte{0})  → gob.Decode → *unitDB
    │
    ├── finishTxn(tx, deleted>0)      ── 提交事务
    │
    ├── curr = newUnit(id)            ── 创建空的内存 unit
    │
    └── curr.deserialize(udb)         ── 若 udb != nil，反序列化恢复内存状态
            │
            ├── nTotal, nResult 从 udb 复制
            ├── domains / blockedDomains / clients 由 countPair slice 转回 map
            └── timeSum = TimeAvg * NTotal （精度损失点，见下文）
```

**恢复的数据源与覆盖边界**：

| unit 归属 | 是否能从 DB 恢复 | 原因 |
|----------|-----------------|------|
| **当前小时（id）** | ✅ 能，部分或完整 | `loadUnitFromDB(tx, id)` 加载上一次写入的快照 |
| **已完整结束的历史小时** | ✅ 完整 | 小时边界切换时已通过 `periodicFlush → flushDB` 完整写入 bucket |
| **超期的最旧小时** | ❌ 不能 | 启动时 `deleteOldUnits` 已主动删除 |

**快照写入的两种触发场景**：

当前小时的数据在以下两个时间点被写入 DB（从而在重启时可恢复）：

1. **优雅关闭 Close()** [stats/stats.go:246-274]
   ```go
   // currMu.RLock 下序列化 + 事务写入
   udb := s.curr.serialize()
   tx, _ := db.Begin(true)
   s.flushUnitToDB(udb, tx, s.curr.id)
   tx.Commit()
   ```

2. **跨小时滚动 periodicFlush → flushDB** [stats/stats.go:446-488]
   ```go
   // 切换 curr 后，将旧 unit 持久化
   s.curr = newUnit(id)          // 新小时内存 unit
   udb := ptr.serialize()        // ptr = 刚结束的旧小时 unit
   s.flushUnitToDB(udb, tx, ptr.id)
   ```

**精度损失点（TimeAvg 四舍五入误差）**：

重启恢复时的 `timeSum` 是逆向推导的近似值，非原始数据：
```go
// serialize 写入时
timeAvg := uint32(u.timeSum / u.nTotal)   // ← 截断取整，丢失小数部分

// deserialize 恢复时 [unit.go:314]
u.timeSum = uint64(udb.TimeAvg) * udb.NTotal  // ← 放大回时偏差 = (余数 × NTotal)
```
例如 1000 条请求总耗时 1234567μs，写入时 `TimeAvg=1234`，恢复时 `timeSum=1234×1000=1234000`，误差 567μs。小时窗口越大（请求数越多），绝对误差越大，但相对误差仍在微秒级可忽略。

**崩溃 vs 优雅关闭的恢复差异**：

| 场景 | 当前小时数据恢复程度 |
|------|-------------------|
| **正常调用 Close() 后重启** | 恢复到 Close() 时刻的完整状态（timeSum 仍有四舍五入） |
| **跨小时滚动发生后崩溃** | 已结束的旧小时 100% 完整；当前崩溃时刻的小时从 DB 恢复到上次 Close/滚动的快照点 |
| **进程刚启动不久崩溃（无 Close）** | 若崩溃时刻的小时之前从未被写过 DB，则 `loadUnitFromDB` 返回 nil，`curr` 从空开始 |

**关闭顺序的设计意图** [home/dns.go:522-547]：
```go
func closeDNSServer(ctx context.Context) {
    // 先关 dnsServer（停止接收新请求，不再调用 Add/Update）
    globalContext.dnsServer.Close(ctx)
    // 再关统计（flush 当前小时快照到 DB）
    globalContext.stats.Close()
    // 最后关查询日志（flush buffer 到 JSON 文件）
    globalContext.queryLog.Shutdown(ctx)
}
```
先停止请求入口，再各自持久化，保证两条路径的关闭时数据都能落盘。

### 3.5 SIGKILL 强杀场景：15 分钟快照不存在，完全无补偿

**结论前置：代码中不存在 15 分钟周期性快照机制，SIGKILL（`kill -9`）强杀时，当前小时内未落盘的统计数据 100% 永久丢失，没有任何补偿（WAL、补算、对账、快照）手段。**

#### 3.5.1 持久化触发点盘点——只有两个

stats 模块中写入 bbolt 的代码路径只有两条，均不包含"15 分钟周期 flush"：

| 触发方式 | 发生时机 | 写入内容 | SIGKILL 能否命中 |
|---------|---------|---------|----------------|
| **Close() 优雅关闭** | 接收 SIGTERM/SIGINT 后走 `home.closeDNSServer` 显式调用 | 当前小时完整快照 | ❌ SIGKILL 不传递信号，直接终止进程，Close 不会被执行 |
| **periodicFlush → flushDB** | 后台 goroutine 每秒循环检查 `time.Now().Unix()/3600` 是否变化（即跨小时） | 上一个完整小时的数据 | ✅ 若跨小时已发生则那个小时已落盘；但**当前小时仍在内存中** |

periodicFlush 的循环实现 [stats/stats.go:496-502]：
```go
func (s *StatsCtx) periodicFlush() {
    for cont, sleepFor := true, time.Duration(0); cont; time.Sleep(sleepFor) {
        cont, sleepFor = s.flush()   // flush() 返回 sleepFor = time.Second
    }
}
// flush() 内部：ptr.id == id 时 return true, time.Second，不做 DB 写入
// 只有 ptr.id != id（跨小时）时才走 flushDB 写 bbolt
```
因此 periodicFlush 本质是 **1 秒粒度的"跨小时检查器"**，不是周期快照。代码库全量 grep `15.*Minute` / `quarter` / `snapshot.*flush` 无任何匹配。

#### 3.5.2 SIGKILL 的信号传递盲区

在 UNIX 信号模型中：
- SIGTERM（`kill` 默认）、SIGINT（Ctrl+C）：可被 `signal.Notify` 捕获，从而触发 `service.Shutdown → closeDNSServer → stats.Close()` 优雅链路
- **SIGKILL（`kill -9`）/ SIGSTOP**：POSIX 规定不可被捕获、不可被忽略、不可被阻塞，进程直接被内核终止，用户态清理逻辑 **零执行机会**

AdGuard Home 的 `ossvc` 层只注册了 SIGTERM + SIGINT [ossvc/service_openbsd.go:298]（其他平台类似）：
```go
signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
```
没有、也不可能注册 SIGKILL 的处理函数。

#### 3.5.3 丢失窗口量化

| 崩溃时刻相对小时边界 | 丢失的统计数据量 |
|-------------------|----------------|
| 00:00:01（刚跨小时） | 整个小时的 3599 秒聚合（最坏情况） |
| HH:30:00（小时中点） | 半小时聚合（平均情况） |
| HH:59:59（快跨小时） | 仅剩 1 秒聚合（最好情况） |

丢失的字段：所有 `curr` 内存 unit 中的 `domains / blockedDomains / clients / nResult / nTotal / timeSum`，且因为 querylog 与 stats 是两条独立路径（§4.4），**querylog.json 即使完整也无法回灌 stats**——没有提供从查询日志事件重建统计聚合的"回放/补偿"API。

#### 3.5.4 为什么没有补偿

从代码设计取向看：
1. 没有 WAL（Write-Ahead Log）：stats 直接在内存 map 聚合，未落盘的增量不存在任何持久化中间层
2. 没有 replay 接口：`StatsCtx` 对外只暴露 `Update(entry)` 单向写入，不暴露"从 querylog.json 批量回灌"
3. 没有对账 API：`handleStats` 返回的 `num_dns_queries` 与 querylog 行数之差没有被系统自动计算或告警
4. 定位是"趋势展示而非计费"：Dashboard 展示的是粗略指标，容忍小时级数据缺口

### 3.6 bbolt Journal 损坏场景的 Fallback 路径

**结论前置：stats.db 的 bbolt 打开使用 `nil` Options（即全默认值），无任何自定义日志恢复配置。Journal 损坏时唯一的二级 fallback 是 `clear()` → 删库重建（全部历史数据归零）。**

#### 3.6.1 bbolt.Open 的 Options 实际值

`openDB` 调用链 [stats/stats.go:389-418]：

```go
func (s *StatsCtx) openDB() (err error) {
    db, err = bbolt.Open(s.filename, aghos.DefaultPermFile, nil)
    //                                                            ^^^
    //                                              第三个参数 Options = nil
    ...
}
```

`nil` Options 意味着 bbolt 使用全默认 `Options{}`，关键字段：

| Options 字段 | 默认值 | 含义 |
|-------------|--------|------|
| `Timeout` | 0 | 打开数据库时不等待排他锁（若另一个进程占用则立即返回错误） |
| `NoGrowSync` | false | 文件增长时执行 fsync（安全但慢） |
| `FreelistType` | `FreelistArrayType` | 使用数组管理空闲页（简单但不适合超大数据文件） |
| `NoSync` | false | **每次 Commit 都执行 fsync**（最安全，性能最低） |
| `NoFreelistSync` | false | **freelist 变更时也同步到磁盘**（避免 freelist 损坏） |
| `PageSize` | 0（= OS 页大小） | 使用操作系统默认页大小 |

**安全特性**：`NoSync=false` + `NoFreelistSync=false`，意味着每次 `tx.Commit()` 都会 `fdatasync`，freelist 也同步刷盘。这是最安全的模式，也是性能最慢的模式。

**没有自定义的 `StrictSync`**：bbolt v1.3.x 新增了 `StrictSync` 选项（确保 mmap 写入前先 sync），但 AdGuard Home 的 `go.mod` 中引用的 bbolt 版本未使用此选项。

#### 3.6.2 bbolt Journal 自身损坏的三种场景与代码处理

| 损坏场景 | 触发原因 | `bbolt.Open` 行为 | 代码处理 |
|---------|---------|-------------------|---------|
| **1. Journal 文件不完整**（mmap 的 meta page 写到一半断电） | SIGKILL / 内核 panic / 硬件掉电 | bbolt 内部自动选择两个 meta page 中较新的那个（写时双缓冲） | **透明恢复**，代码无感知 |
| **2. 两个 meta page 都损坏**（磁盘坏块 / 文件系统损坏） | 磁盘硬件故障 | `bbolt.Open` 返回 `ErrInvalid` 或类似错误 | `openDB` 返回 error → `New()` 失败 → **进程启动失败** |
| **3. Freelist 损坏**（freelist 页写了一半断电，`NoFreelistSync=false` 时概率极低） | 极端情况下写入中断 | `bbolt.Open` 可能成功但后续 `Begin(true)` 返回 `freelist: corrupted` 错误 | `flushDB` / `Close` 中 `db.Begin(true)` 返回 error → **仅日志告警，periodicFlush 继续 sleep 1 秒重试** |

**场景 2 的处理——启动时 `openDB` 失败**：

`openDB` 返回的错误会被 `New()` 直接 return：
```go
// stats/stats.go:187-189
err = s.openDB()
if err != nil {
    return nil, fmt.Errorf("opening database: %w", err)
}
```
此时 `StatsCtx` 未创建，stats 功能完全不可用。进程不会崩溃但 stats 相关 API 全部失效。

唯一的非代码人工恢复手段：手动 `rm stats.db`，重启进程让 `openDB` 创建空数据库。

**场景 3 的处理——运行时 `Begin(true)` 失败**：

在 `flushDB` 中 [stats/stats.go:452-458]：
```go
tx, err := db.Begin(true)
if err != nil {
    s.logger.Error("opening transaction", slogutil.KeyError, err)
    return true, 0   // ← 返回 cont=true, sleepFor=0
}
```
`periodicFlush` 继续循环，下次 `flush()` 仍会尝试 `db.Begin(true)`。如果 DB 持续损坏，日志每秒刷一条 Error，但进程不会退出、不会自愈。

**场景 3 的唯一自动 fallback——`clear()` 方法** [stats/stats.go:524-569]：

```go
func (s *StatsCtx) clear() (err error) {
    db := s.db.Swap(nil)        // 原子交换，后续操作使用 nil DB
    if db != nil {
        tx, err = db.Begin(true)
        finishTxn(tx, false)    // 回滚事务
        db.Close()              // 关闭旧 DB
    }
    os.Remove(s.filename)       // ← 删除损坏的 stats.db 文件
    s.openDB()                  // ← 重建空数据库
    s.curr = newUnit(s.unitIDGen())  // ← 重置内存 unit
    return nil
}
```

`clear()` 的触发路径**只有一条**：用户主动调用 `POST /control/stats_reset` API → `handleStatsReset` → `s.clear()`。

**代码中没有自动检测 bbolt 损坏后触发 clear() 的逻辑**。即：
- `flushDB` 中 `Begin(true)` 失败只打日志，不自动 clear
- `loadUnitFromDB` 中 gob 解码失败只打日志，不自动 clear
- `finishTxn` 中 `Commit()` 失败只打日志，不自动 clear

#### 3.6.3 二级 Fallback 总结

```
bbolt journal 损坏
        │
        ├── 场景1: 单 meta page 损坏
        │     └── bbolt 自动恢复（双 meta page 冗余）
        │         ✅ 对应用层透明
        │
        ├── 场景2: 双 meta page 都损坏
        │     └── bbolt.Open() 失败
        │         └── New() 返回 error → 进程启动失败
        │             ❌ 需人工 rm stats.db + 重启
        │
        └── 场景3: Freelist/数据页损坏
              └── bbolt.Open() 可能成功
                  └── Begin(true) 返回 error
                      └── periodicFlush 持续打 Error 日志
                          └── 不自动 clear，不自动退出
                              ❌ 需人工调 POST /stats_reset
                              ❌ 全部历史统计归零
```

没有"仅丢弃损坏 bucket 而保留其他 bucket"的局部恢复逻辑。一旦 `clear()` 被执行，所有历史统计数据永久丢失。

## 4. 并发协同与锁避免机制

### 4.1 两条路径的完全解耦

| 维度 | 查询日志路径 | 统计聚合路径 | 冲突避免 |
|------|-------------|-------------|---------|
| **调用时机** | dnsforward 并行调用 | dnsforward 并行调用 | 同一请求内顺序执行，无交叉 |
| **数据结构** | RingBuffer[logEntry] | unit（map 聚合） | 完全独立的内存结构 |
| **锁体系** | bufferLock/fileFlushLock/fileWriteLock | confMu/currMu/bbolt 事务 | 锁空间完全隔离，无共享锁 |
| **存储介质** | JSON 文本文件 | bbolt 数据库 | 不同文件，I/O 不竞争 |
| **执行模式** | 缓冲区满时异步批写 | 内存实时更新 + 小时级滚动 | 高峰期 I/O 操作错开 |

### 4.2 关键锁设计模式

**1. 查询日志的三级锁分层** [querylog/querylogfile.go]

```
Add 路径 (请求线程)        flush 路径 (后台 goroutine)
      │                           │
      ▼                           │
  bufferLock.Lock()               │
  buffer.Push(entry)              │
  bufferLock.Unlock()             │
      │                           │
      └─── 触发条件满足 ───────────►
                                  ▼
                          fileFlushLock.Lock()
                                  │
                                  ▼
                          bufferLock.Lock()
                          编码所有条目 + Clear
                          bufferLock.Unlock()  <-- 尽早释放
                                  │
                                  ▼
                          fileWriteLock.Lock()
                          磁盘 I/O 写入
                          fileWriteLock.Unlock()
                                  │
                                  ▼
                          fileFlushLock.Unlock()
```

**设计亮点**：
- `bufferLock` 仅在内存操作时持有，磁盘 I/O 前已释放
- `fileFlushLock` 确保只有一个 flush 在进行，但不阻塞 Add
- Add 路径的锁持有时间极短（仅 Push 操作）

**2. 统计聚合的读写锁 + 原子切换** [stats/stats.go:420-489]

```go
func (s *StatsCtx) flushDB(id, limit uint32, ptr *unit) {
    // 此时 confMu 和 currMu 已加写锁
    s.curr = newUnit(id)  // 原子切换：新请求立即写入新 unit
    
    // 解锁 currMu，后续数据库操作不阻塞新请求
    // 序列化旧 unit（内存操作）
    udb := ptr.serialize()
    
    // 数据库事务（磁盘 I/O）
    tx, _ := db.Begin(true)
    s.flushUnitToDB(udb, tx, ptr.id)
    tx.DeleteBucket(idToUnitName(id - limit))
    tx.Commit()
}
```

**设计亮点**：
- 原子切换 curr 指针后，新请求不会被数据库 I/O 阻塞
- 旧 unit 的序列化和数据库操作在锁外进行
- currMu 写锁持有时间仅够完成指针替换

### 4.3 高峰期协同机制

**并发查询高峰时的行为**：

1. **查询日志路径**：
   - 每个请求只做内存 Push（微秒级）
   - 缓冲区满时触发异步 flush
   - flush 期间 Add 仍可继续（bufferLock 已释放）
   - 即使磁盘 I/O 慢，也只阻塞 flush 协程，不阻塞请求

2. **统计聚合路径**：
   - 每个请求只做内存 map 递增（微秒级）
   - 只有在跨小时的那一秒才会触发数据库写入
   - 跨小时时通过原子切换 curr 指针，避免阻塞新请求

3. **两条路径之间**：
   - 无共享数据结构，无共享锁
   - 存储介质不同（文件 vs 数据库），I/O 不竞争
   - 触发时机不同（缓冲区满 vs 跨小时），高峰期通常不会同时触发

### 4.4 查询日志与 Stats DB 的数据一致性边界

**入口点：同一中间件内顺序调用，无事务包裹** [dnsforward/requesthandler.go:33-54 + stats.go:19-76]

```go
// dnsforward 中间件链，processQueryLogsAndStats 排在最后一位
mods := []modProcessFunc{
    s.processInitial, ... , s.processUpstream,
    s.processFilteringAfterResponse, s.ipset.process,
    s.processQueryLogsAndStats,    // ← 最后一步才写两条路径
}

// processQueryLogsAndStats 内部串行执行：
func (s *Server) processQueryLogsAndStats(...) {
    s.serverLock.RLock()
    defer s.serverLock.RUnlock()

    if s.shouldLog(...) {
        s.logQuery(dctx, ip, processingTime)    // 路径1: queryLog.Add(p)
    }
    if s.shouldCountStat(...) {
        s.updateStats(dctx, ipStr, processingTime) // 路径2: stats.Update(e)
    }
}
```

两个调用在同一个 goroutine 内顺序执行，但没有任何跨路径的事务或原子保证。从"一条请求在两个系统中都有一致镜像"的角度，存在 **6 个明确的一致性断层**：

---

#### 断层 1：独立的准入过滤（ShouldLog vs ShouldCount）

| 过滤维度 | 查询日志路径 | 统计路径 | 可能不一致的场景 |
|---------|------------|---------|----------------|
| **配置开关** | `conf.Enabled` + `conf.FileEnabled` | `conf.Enabled` + `conf.Limit != 0` | 用户仅开启查询日志不关统计（或反之） |
| **域名忽略列表** | `querylog.Ignored.Has(host)` 独立引擎 | `stats.Ignored.Has(host)` 独立引擎 | 两个 IgnoreEngine 配置不同源 |
| **客户端豁免** | `client.IgnoreQueryLog` 字段 | `!shouldCountClient(ids)` 函数 | 同一客户端设置了"不记录日志"但"计数统计" |
| **特殊报文类型** | 仅对 `TypeANY && RefuseAny` 跳过 | 无此跳过逻辑 | ANY 类型请求会计入 stats 但不写 qlog |

代码证据 [dnsforward/stats.go:80-96]：
```go
func (s *Server) shouldLog(...) bool {
    if qt == dns.TypeANY && s.conf.RefuseAny { return false } // 仅 qlog 过滤 ANY
    return s.queryLog.ShouldLog(host, qt, cl, ids)
}
func (s *Server) shouldCountStat(...) bool {
    return s.stats.ShouldCount(host, qt, cl, ids) // stats 不过滤 ANY
}
```

---

#### 断层 2：存储介质完全独立 + 不同持久化时机

| 维度 | 查询日志 | 统计聚合 |
|------|---------|---------|
| **文件** | `querylog.json`（追加写文本 JSON） | `stats.db`（bbolt B+树，bucket 随机写） |
| **持久化触发** | 异步：buffer 满时后台 goroutine flush | 同步：小时边界原子切换；Close 主动 flush |
| **fsync 策略** | `OpenFile(O_APPEND)` + Go 标准库写缓冲，无显式 fsync | bbolt 内部 `fdatasync`（`strict_sync=false` 时可配置） |
| **崩溃丢失窗口** | 最多丢失最后 `MemSize` 条（约数秒至数分钟） | 最多丢失当前小时内未被 Close 持久化的聚合计数（可达 1 小时） |

因此即使两条路径都成功返回 `Add`/`Update`，落盘仍非原子：
- 查询日志可能丢数据但 stats 完整（磁盘写文本慢但 bbolt 提交快）
- Stats 可能丢数据但查询日志完整（进程崩溃在未到 Close 时）

---

#### 断层 3：时间粒度不对齐

| 粒度 | 查询日志 | 统计聚合 |
|------|---------|---------|
| **写入时间戳** | 每条 `logEntry.Time = time.Now()`（ns 级） | 归属 `unit.id = UnixNow()/3600`（1 小时桶） |
| **数据建模** | 逐条事件溯源（event sourcing） | 时间窗口聚合（window aggregation） |

后果：无法从 stats 的"1 小时 NTotal=12345"精确还原出 querylog.json 中的 12345 条逐条记录（除非关闭时间窗口内系统无重启、无 RingBuffer 溢出）。

---

#### 断层 4：故障隔离（单向失败不传播）

```
logQuery → queryLog.Add(p)
│
└── 内部仅 log.Error 不 panic、不返回 error
    （Add 的签名是 void，且内部所有错误走 logger）

updateStats → stats.Update(e)
│
└── 同理：e.validate() 失败仅 Debug 日志，不向上传播
```

因此：
- 若 `queryLog.Add` 在创建 entry 过程中 panic 被 recover，stats.Update 仍已成功执行
- 若 `stats.Update` 在 `curr.add` 中 OOM panic，queryLog 中的 entry 已推入 RingBuffer
- 上层 `processQueryLogsAndStats` 始终返回 `resultCodeSuccess`，调用方永远不知道部分失败

---

#### 断层 5：保留/过期策略各自独立

| 策略 | 查询日志 | 统计聚合 |
|------|---------|---------|
| **保留配置项** | `config.QueryLog.Interval`（RotationIvl） | `config.Stats.Interval`（Limit） |
| **实际保留** | 2×RotationIvl（querylog.json + .1） | 精确 Limit（小时 bucket 粒度删除） |
| **用户可独立设置** | ✅ 两个 YAML 字段不同 | ✅ 各自 `Enabled` 开关不同 |

用户可设置"查询日志保留 1 天、统计保留 30 天"，此时 Dashboard 展示的统计数字远超查询日志可回溯的原始事件。

---

#### 断层 6：重配置（Reconfigure）的重建时机

重配置流程 [dnsforward.go:848-884]：
```go
func (s *Server) Reconfigure(ctx, conf) {
    s.stopLocked(ctx)       // 停 DNS 代理（不释放 qlog/stats）
    time.Sleep(100ms)       // 等 fd 关闭
    s.Prepare(ctx, conf)    // 内部可能重建 dnsServer，但 qlog/stats 指针不变
    s.startLocked(ctx)      // 重启 DNS 代理
}
```
而 `home.initDNS` 中重建 `globalContext.stats` / `globalContext.queryLog` 仅在**进程级全量重启**时发生。重配置期间两条路径仍持有旧内存 buffer/unit，保证了重配置时数据不中断但也造成"旧配置下的条目与新配置的过滤规则混存"的一致性窗口。

---

**一致性保证的官方态度总结**：

代码中没有任何"对账"（reconciliation）逻辑、没有 WAL（Write-Ahead Log）、没有跨系统的 checkpoint。从设计取向看，AdGuard Home 对两条路径的定位是：
- **查询日志**：面向运维排障的事件流，允许小概率丢失但要求逐条可查
- **统计聚合**：面向 Dashboard 的趋势展示，要求聚合计数稳定可恢复但不要求可精确逐条还原

两者之间"最终一致但不保证严格一致"，可观测层面没有提供任何交叉校验接口。

## 5. 潜在问题与优化点

### 5.1 已知问题

1. **查询日志 TODO** [querylog/qlog.go:258]
   ```go
   // TODO(s.chzhen):  Fix occasional rewrite of entires.
   ```
   高并发下可能存在条目重写问题。

2. **统计删除 TODO** [stats/stats.go:477-478]
   ```go
   // TODO(e.burkov):  Improve the algorithm of deleting the oldest bucket
   // to avoid the error.
   ```
   删除旧 bucket 时可能出现 BucketNotFound 错误。

3. **统计每日聚合 TODO** [stats/unit.go:515-517]
   ```go
   // TODO(s.chzhen):  Improve collection of statistics for frontend.
   // Dashboard cards should contain statistics for the whole interval
   // without rounding to days.
   ```
   前端展示时按天聚合可能丢失精度。

### 5.2 设计权衡

| 设计决策 | 优点 | 缺点 |
|---------|------|------|
| 查询日志使用 RingBuffer + 异步批写 | 低延迟，高吞吐量 | 崩溃可能丢失最后一批数据 |
| 统计使用内存 map 实时聚合 | 实时性好，查询快 | 内存占用随域名/客户端数量增长 |
| 小时级滚动窗口 | 数据库写入频率低 | 数据精度限制在小时级 |
| 两条路径完全独立 | 无锁竞争，可独立扩展 | 数据重复处理，存储成本翻倍 |

### 5.3 存储路径、文件名与 bbolt Bucket 名的硬编码与可配置性

**结论前置（先澄清一个常见误解）：查询日志不使用 bbolt，只有 stats 使用 bbolt。** 两者的存储介质完全不同（JSON 文本文件 vs bbolt 嵌入式 KV 数据库），因此"共用 boltdb 桶名"的假设本身不成立。以下分两个系统分别梳理硬编码点与可配置性。

#### 5.3.1 查询日志：路径可配置，文件名和压缩后缀硬编码

查询日志存储相关的可配置项 [home/config.go:402-427 + querylog/querylog.go:36-82]：

| 配置项 | YAML 字段 | 是否可配置 | 硬编码位置 |
|-------|----------|-----------|-----------|
| **存储目录** | `querylog.dir_path` | ✅ 可自定义（空值时用 `getDataDir` 默认数据目录） | `home/dns.go:85-87` |
| **文件名** | 无 | ❌ 硬编码 `querylog.json` | `querylog/qlog.go:23 const queryLogFileName` |
| **滚动后缀** | 无 | ❌ 硬编码 `.1` | `querylog/querylogfile.go:103-121 renameTo + filename + ".1"` |
| **压缩后缀** | 无 | ❌ 硬编码 `.gz`（注释中提及） | `querylog/qlog.go:21-22` 注释 |
| **MemSize** | `querylog.size_memory` | ✅ 可自定义（0 时自动降级为 1） | `querylog/querylog.go:69-71` |
| **RotationIvl** | `querylog.interval` | ✅ 可自定义 | `querylog/querylog.go:64-67` |

目录拼接在 `home/dns.go` 中完成 [home/dns.go:85-87]：
```go
querylogDir := config.QueryLog.DirPath
if querylogDir == "" {
    querylogDir = globalContext.getDataDir()
}
qlConf.BaseDir = querylogDir
```
文件名在 `querylog.newQueryLog` 中通过 `filepath.Join(conf.BaseDir, queryLogFileName)` 拼接，**运维侧无法通过 YAML 把文件名改成如 `queries.log`**。

#### 5.3.2 Stats：DB 目录可配置，文件名 `stats.db` 硬编码，Bucket 名由小时 ID 序列化生成

Stats 存储相关的可配置项 [home/config.go:429-446 + stats/stats.go:48-95]：

| 配置项 | YAML 字段 | 是否可配置 | 硬编码/生成位置 |
|-------|----------|-----------|----------------|
| **DB 存储目录** | `statistics.dir_path` | ✅ 可自定义（空值时用默认数据目录） | `home/dns.go:55-57` |
| **DB 文件名** | 无 | ❌ 硬编码 `stats.db` | `home/dns.go:59` 的 `filepath.Join(statsDir, "stats.db")` + `stats_internal_test.go:30` |
| **保留期限 Limit** | `statistics.interval` | ✅ 可自定义（1/7/30/90 天） | `stats/stats.go:198-205` |
| **Bucket 命名规则** | 无 | ❌ 由 `idToUnitName(id)` 固定算法生成，不可自定义 | `stats/unit.go:206-212` |

**Bucket 名生成算法** [stats/unit.go:200-223]：

```go
const bucketNameLen = 8   // 8 字节 = uint64 的长度

func idToUnitName(id uint32) (name []byte) {
    n := [bucketNameLen]byte{}
    binary.BigEndian.PutUint64(n[:], uint64(id))
    return n[:]
}
```

Bucket 名本质是**小时 ID 的 8 字节大端二进制编码**。例如：
- 小时 ID `123456` → Bucket 名为字节序列 `\x00\x00\x00\x00\x00\x01\xe2@`
- 运维侧无法通过 YAML 把 bucket 前缀改成带命名空间的字符串（如 `stats:unit:123456`），因为 `CreateBucketIfNotExists(idToUnitName(id))` 直接用二进制字节定位

**运维侧能做的调整边界**：
1. 改 `dir_path` → 把 `stats.db` / `querylog.json` 挪到不同磁盘分区（可行）
2. 改 `interval` → 调整保留期限（可行）
3. 改文件名 / 改 bucket 名 / 加命名空间前缀 → 必须修改源码重新编译（不可通过配置实现）

#### 5.3.3 为什么 Bucket 名用二进制而非字符串

设计上的三个理由：
1. **排序效率**：bbolt 的 bucket 和 key 按字节序排序，大端编码的 uint64 字节序与数值序一致，遍历最旧 → 最新 bucket 时 `ForEach` 天然按时间升序
2. **空间紧凑**：8 字节固定长度，比字符串 `"1840972"` 少 1 字节，百万级 bucket 累积节省可观
3. **编码一致性**：与 `sessionstorage`、`filtering` 等其他 bbolt 使用方保持同一种 ID 编码风格

代价是运维用 `bbolt stats.db list` 调试时看到的 bucket 名是不可读的二进制字节，需要 `unitNameToID` 逆向解码。

#### 5.3.4 配置项的热更新支持矩阵——存储路径不可热改，运行参数可热改

**结论前置：`dir_path`（存储目录）、`Filename`（DB 文件名）、`queryLogFileName`（日志文件名）在 `New()` 构造时固定，不支持运行时热更新。`enabled`/`ignored`/`interval`/`limit` 可通过 HTTP API 运行时热改，不要求重启进程。**

##### 运行时可热更新的配置项

两个子系统都通过 `ConfigModifier.Apply` 回调链实现配置热更新，完整调用链如下：

```
HTTP API 请求（PUT /control/stats/config/update）
    │
    ├── 修改内存字段（confMu.Lock 保护）
    │     ├── s.ignored = engine    ← 运行时切换忽略引擎
    │     ├── s.limit = ivl         ← 运行时修改保留期限
    │     └── s.enabled = bool      ← 运行时开关
    │
    ├── defer s.configModifier.Apply(ctx)
    │     └── defaultConfigModifier.Apply → config.write()
    │         ├── WriteDiskConfig: 从内存读当前配置
    │         │     ├── stats: limit/ignored/enabled
    │         │     └── querylog: rotationIvl/ignored/enabled/anonymizeIP
    │         └── YAML 序列化写回 AdGuardHome.yaml
    │
    └── 无需重启进程，新配置立即生效
```

| 配置项 | 热更新 API | 是否立即生效 | 是否写回 YAML |
|-------|-----------|------------|-------------|
| **stats.enabled** | `PUT /control/stats/config/update` | ✅ | ✅ |
| **stats.limit (interval)** | `PUT /control/stats/config/update` | ✅ | ✅ |
| **stats.ignored** | `PUT /control/stats/config/update` | ✅ | ✅ |
| **querylog.enabled** | `PUT /control/querylog/config/update` | ✅ | ✅ |
| **querylog.rotationIvl** | `PUT /control/querylog/config/update` | ✅ | ✅ |
| **querylog.ignored** | `PUT /control/querylog/config/update` | ✅ | ✅ |
| **querylog.anonymizeClientIP** | `PUT /control/querylog/config/update` | ✅ | ✅ |

##### 运行时不可热更新的配置项——必须重启进程

| 配置项 | 原因 | 热改后果 |
|-------|------|---------|
| **querylog.dir_path** | `logFile` 在 `newQueryLog()` 中通过 `filepath.Join(conf.BaseDir, queryLogFileName)` 固定写入 `l.logFile` 字段，后续所有 flush 操作引用此字段 | HTTP API 不暴露 `dir_path` 修改入口；修改 YAML 后重启生效 |
| **stats.dir_path** | `Filename` 在 `StatsCtx.New()` 时固定到 `s.filename` 字段，`openDB()` 使用此字段打开 DB | HTTP API 不暴露 `dir_path` 修改入口；修改 YAML 后重启生效 |
| **stats.Filename (stats.db)** | 同上，硬编码在 `home/dns.go:59` 的 `filepath.Join(statsDir, "stats.db")` | 修改源码重新编译 |
| **querylog.queryLogFileName** | 硬编码 `const queryLogFileName = "querylog.json"` | 修改源码重新编译 |
| **querylog.memSize** | `buffer = NewRingBuffer[*logEntry](memSize)` 在构造时创建，运行时不变更 RingBuffer 容量 | 修改 YAML 后重启生效 |
| **bucket 命名规则** | `idToUnitName()` 是纯函数，无状态可改 | 修改源码重新编译 |

**关键区分**：`ConfigModifier.Apply` 只负责"内存 → YAML 文件"的单向同步，不负责"YAML → 内存"的反向加载。运行时配置变更完全通过 HTTP API 触发，`config.yaml` 文件只是持久化手段而非热加载源。

**热更新验证链路**（以 stats.interval 为例）：

```
1. PUT /control/stats/config/update  {"interval": 86400000, "enabled": true}
2. handlePutStatsConfig:
   ├── validateIvl(ivl)                    ← 校验
   ├── s.confMu.Lock()
   ├── s.limit = ivl                       ← 内存生效
   ├── s.confMu.Unlock()
   └── defer s.configModifier.Apply(ctx)
3. defaultConfigModifier.Apply:
   └── config.write()                      ← 写回 YAML
4. periodicFlush 下次循环:
   └── limit := uint32(s.limit.Hours())    ← 使用新值
```

无需重启 DNS Server，无需调用 `dnsServer.Reconfigure`。

##### DNS 配置的热更新分界线

DNS 相关的配置变更分两档：
- **非重启型**（如 `ProtectionEnabled`、`DNSSECEnabled`、`DisableIPv6`）：`setConfig` 返回 `shouldRestart=false`，内存立即生效
- **重启型**（如 `Upstreams`、`BootstrapDNS`、`ListenAddr`）：`setConfig` 返回 `shouldRestart=true`，触发 `dnsServer.Reconfigure`（停止代理 → 重新 Prepare → 启动）

但 `querylog.dir_path` 和 `stats.dir_path` 属于"DNS 配置之外"的存储层参数，即使 `Reconfigure` 也不会重新初始化 stats/querylog 实例。

## 6. 关键代码索引

### 6.1 查询日志写盘路径

| 功能 | 文件位置 |
|------|---------|
| 查询日志 Add 入口 | [querylog/qlog.go:219-266] |
| 查询日志批写 flush | [querylog/querylogfile.go:19-32] |
| 查询日志缓冲区编码 | [querylog/querylogfile.go:36-77] |
| 查询日志文件写入 | [querylog/querylogfile.go:80-101] |
| 查询日志滚动（文件改名） | [querylog/querylogfile.go:103-121] |
| 查询日志滚动 ticker（1 小时周期） | [querylog/querylogfile.go:150-163] |
| **RingBuffer Push（丢弃覆盖实现）** | **golibs/container/ringbuffer.go:19-29** |
| **RingBuffer 数据结构（cur + full，无 dropped 字段）** | **golibs/container/ringbuffer.go:4-8** |
| **querylog.json 文件名常量硬编码** | **[querylog/qlog.go:21-23]** |
| **YAML querylog 配置结构（含 dir_path/size_memory/interval）** | **[home/config.go:402-427]** |
| **querylog 热更新 HTTP API（handlePutQueryLogConfig）** | **[querylog/http.go:221-277]** |
| **querylog 热更新应用（applyQueryLogConfig + ConfigModifier.Apply）** | **[querylog/http.go:309-337]** |

### 6.2 统计聚合路径

| 功能 | 文件位置 |
|------|---------|
| 统计 Update 入口 | [stats/stats.go:278-303] |
| 统计 unit add 逻辑 | [stats/unit.go:318-340] |
| 统计滚动 flush（periodicFlush → flushDB） | [stats/stats.go:496-502, 420-489] |
| 统计数据库持久化（flushUnitToDB） | [stats/unit.go:343-363] |
| **启动时快照恢复（New → loadUnitFromDB）** | **[stats/stats.go:155-213]** |
| **序列化/反序列化（timeSum 精度点）** | **[stats/unit.go:258-315]** |
| **优雅关闭 flush（Close）** | **[stats/stats.go:246-274]** |
| **idToUnitName（Bucket 名生成，8 字节大端编码）** | **[stats/unit.go:200-213]** |
| **unitNameToID（Bucket 名逆向解码）** | **[stats/unit.go:215-223]** |
| **periodicFlush 的 1 秒 sleep 粒度（非 15 分钟快照）** | **[stats/stats.go:420-439, 496-502]** |
| **YAML statistics 配置结构（含 dir_path/interval）** | **[home/config.go:429-446]** |
| **stats.db 文件名在 home/dns.go 中硬编码拼接** | **[home/dns.go:55-60]** |
| **openDB（bbolt.Open 使用 nil Options，全默认安全模式）** | **[stats/stats.go:387-418]** |
| **clear（删库重建 fallback，POST /stats_reset 触发）** | **[stats/stats.go:524-569]** |
| **flushDB 中 Begin(true) 失败处理（仅日志告警不自动 clear）** | **[stats/stats.go:452-458]** |
| **stats 热更新 HTTP API（handlePutStatsConfig）** | **[stats/http.go:225-282]** |

### 6.3 协同、调用边界与关闭顺序

| 功能 | 文件位置 |
|------|---------|
| DNS 中间件链定义（两条路径的入口位置） | [dnsforward/requesthandler.go:33-54] |
| processQueryLogsAndStats（双路径串行调用） | [dnsforward/stats.go:19-76] |
| shouldLog / shouldCountStat 准入过滤差异 | [dnsforward/stats.go:80-96] |
| dnsServer Reconfigure（重配置不重建指针） | [dnsforward/dnsforward.go:848-884] |
| DNS setConfig/setConfigRestartable（重启/非重启分界线） | [dnsforward/http.go:586-652] |
| **全局启动顺序（filters→stats→querylog→dns）** | **[home/dns.go:469-500]** |
| **全局关闭顺序（dns→stats→querylog）** | **[home/dns.go:522-547]** |
| home.initDNS 双系统配置构造（两个 IgnoreEngine 独立） | [home/dns.go:57-101] |
| **OSSVC 信号注册（仅 SIGTERM/SIGINT，未注册 SIGKILL）** | **[ossvc/service_openbsd.go:294-300]（其他平台同模式）** |
| **go.mod 依赖列表（无 prometheus/client_golang）** | **[go.mod]** |
| **ConfigModifier 接口定义（Apply 方法：内存→YAML 单向同步）** | **[agh/agh.go:14-18]** |
| **defaultConfigModifier.Apply（实际写 YAML 回调）** | **[home/config.go:1007-1014]** |
| **config.write + WriteDiskConfig（运行时配置序列化回 YAML）** | **[home/config.go:890-942]**


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

### 2.5 滚动文件策略

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

## 6. 关键代码索引

### 6.1 查询日志写盘路径

| 功能 | 文件位置 |
|------|---------|
| 查询日志 Add 入口 | [querylog/qlog.go:219-266] |
| 查询日志批写 flush | [querylog/querylogfile.go:19-32] |
| 查询日志缓冲区编码 | [querylog/querylogfile.go:36-77] |
| 查询日志文件写入 | [querylog/querylogfile.go:80-101] |
| 查询日志滚动（文件改名） | [querylog/querylogfile.go:103-121] |
| **RingBuffer Push（丢弃覆盖实现）** | **golibs/container/ringbuffer.go:19-29** |
| **RingBuffer 数据结构（cur + full）** | **golibs/container/ringbuffer.go:4-8** |

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

### 6.3 协同、调用边界与关闭顺序

| 功能 | 文件位置 |
|------|---------|
| DNS 中间件链定义（两条路径的入口位置） | [dnsforward/requesthandler.go:33-54] |
| processQueryLogsAndStats（双路径串行调用） | [dnsforward/stats.go:19-76] |
| shouldLog / shouldCountStat 准入过滤差异 | [dnsforward/stats.go:80-96] |
| dnsServer Reconfigure（重配置不重建指针） | [dnsforward/dnsforward.go:848-884] |
| **全局启动顺序（filters→stats→querylog→dns）** | **[home/dns.go:469-500]** |
| **全局关闭顺序（dns→stats→querylog）** | **[home/dns.go:522-547]** |
| home.initDNS 双系统配置构造（两个 IgnoreEngine 独立） | [home/dns.go:57-101] |

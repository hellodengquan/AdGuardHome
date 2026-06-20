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

### 2.4 滚动文件策略

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

| 功能 | 文件位置 |
|------|---------|
| 查询日志 Add 入口 | [querylog/qlog.go:219-266] |
| 查询日志批写 flush | [querylog/querylogfile.go:19-32] |
| 查询日志缓冲区编码 | [querylog/querylogfile.go:36-77] |
| 查询日志文件写入 | [querylog/querylogfile.go:80-101] |
| 统计 Update 入口 | [stats/stats.go:278-303] |
| 统计滚动 flush | [stats/stats.go:420-489] |
| 统计 unit add 逻辑 | [stats/unit.go:318-340] |
| 统计数据库持久化 | [stats/unit.go:343-363] |
| DNS 处理后双路径调用 | [dnsforward/stats.go:19-76] |

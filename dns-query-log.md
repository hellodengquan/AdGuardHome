# AdGuardHome DNS 查询日志处理流程分析

## 目录
- [整体架构概览](#整体架构概览)
- [一、DNS 查询入站与日志生成](#一dns-查询入站与日志生成)
- [二、日志落盘与滚动归档](#二日志落盘与滚动归档)
- [三、热查询：内存索引检索](#三热查询内存索引检索)
- [四、冷数据：磁盘回读](#四冷数据磁盘回读)
- [五、统计面板：过滤与导出](#五统计面板过滤与导出)
- [关键文件索引](#关键文件索引)

---

## 整体架构概览

AdGuardHome 的 DNS 查询日志系统采用 **内存缓冲区 + 磁盘文件** 的双层架构：

```
DNS 请求入站
    ↓
dnsforward.Server.logQuery() — 构造 AddParams
    ↓
queryLog.Add() — 写入内存环形缓冲区 (RingBuffer)
    ↓  (缓冲区满/达到阈值)
flushLogBuffer() — JSON 编码后批量追加写入磁盘
    ↓  (定时检查)
periodicRotate() — 日志滚动归档 (querylog.json → querylog.json.1)
    ↓
查询请求: GET /control/querylog
    ├─ searchMemory() — 内存热数据检索
    └─ searchFiles()  — 磁盘冷数据检索
           ├─ seekTS()     — 二分查找按时间戳定位
           └─ ReadNext()   — 反向逐行读取
```

---

## 一、DNS 查询入站与日志生成

### 1.1 入口：DNS 请求处理完成后

文件：`internal/dnsforward/stats.go:19-76`

DNS 请求在 `processQueryLogsAndStats()` 函数中触发日志记录：

```go
func (s *Server) processQueryLogsAndStats(ctx context.Context, l *slog.Logger, dctx *dnsContext) (rc resultCode) {
    // 1. 提取请求元数据：域名、客户端IP、处理时间
    host := aghnet.NormalizeDomain(q.Name)
    processingTime := time.Since(dctx.startTime)
    ip := pctx.Addr.Addr().AsSlice()
    
    // 2. 判断是否需要记录（检查忽略列表、客户端忽略设置）
    if s.shouldLog(host, qt, cl, ids) {
        s.logQuery(dctx, ip, processingTime)  // ← 触发日志写入
    }
}
```

### 1.2 日志参数构造

文件：`internal/dnsforward/stats.go:98-140`

`logQuery()` 将 DNS 请求/响应的所有细节封装为 `querylog.AddParams`：

| 字段 | 来源 | 说明 |
|------|------|------|
| `Question` | `pctx.Req` | DNS 请求报文 |
| `Answer` | `pctx.Res` | 实际返回给客户端的响应 |
| `OrigAnswer` | `dctx.origResp` | 上游原始响应（未被过滤修改的） |
| `Result` | `dctx.result` | 过滤引擎结果（是否拦截、拦截原因、匹配规则等） |
| `ClientID` / `ClientIP` | 客户端标识 | 支持 ClientID 和 IP 双重识别 |
| `ClientProto` | `pctx.Proto` | 协议：DoH/DoQ/DoT/DNSCrypt/Plain |
| `Upstream` | `pctx.Upstream` | 上游 DNS 服务器地址 |
| `Elapsed` | `processingTime` | 请求处理耗时 |
| `Cached` | `qs.Main()[0].IsCached` | 是否命中缓存 |

### 1.3 日志条目结构

文件：`internal/querylog/entry.go:15-45`

每条日志最终被序列化为 `logEntry` 结构体，落盘时采用 JSON 格式：

```go
type logEntry struct {
    Time     time.Time `json:"T"`   // RFC3339Nano 格式时间戳
    QHost    string    `json:"QH"`  // 查询域名 (已规范化)
    QType    string    `json:"QT"`  // 记录类型 (A/AAAA/CNAME 等)
    QClass   string    `json:"QC"`  // 记录类 (IN)
    IP       net.IP    `json:"IP"`  // 客户端 IP
    ClientID string    `json:"CID"` // 可选的客户端标识
    ClientProto ClientProto `json:"CP"` // 协议类型
    
    Result   filtering.Result       // 过滤结果详情
    Answer   []byte                 // DNS 响应 (base64 编码)
    OrigAnswer []byte               // 原始上游响应
    
    Upstream string                 // 上游服务器
    Elapsed  time.Duration          // 处理耗时
    Cached   bool                   // 缓存命中
}
```

---

## 二、日志落盘与滚动归档

### 2.1 内存环形缓冲区与 OOM 保护

文件：`internal/querylog/querylog.go:158-179`、`internal/querylog/qlog.go:26-54`

日志先写入内存环形缓冲区 `RingBuffer`，这是一个定长循环队列：

```go
l = &queryLog{
    buffer: container.NewRingBuffer[*logEntry](memSize),  // 默认 1000 条
    // ...
}
```

#### 2.1.1 RingBuffer 的 OOM 保护机制

`RingBuffer` 采用 **定长环形队列** 设计，从架构层面天然防止 OOM：

- **容量固定**：创建时指定 `capacity`，后续不可动态扩容
- **满时覆盖**：当 `Push()` 调用时若缓冲区已满，最旧的条目会被自动弹出（覆盖），保证内存用量恒定
- **零分配**：内部使用切片实现，Push/Pop 均为 O(1) 操作，不会产生额外内存分配

对于 DNS 查询日志场景，这意味着即使遭遇 DNS 洪水攻击，内存占用也被严格限制在 `MemSize × 单条日志大小` 的范围内，不会因日志堆积导致服务 OOM。

#### 2.1.2 MemSize 自适应策略

文件：`internal/querylog/qlog.go:58-70`

`MemSize` 并非完全静态，有以下自适应规则：

1. **最小值保护**：若配置 `MemSize == 0`，`newQueryLog()` 会将其设为 `1`。因为即使文件日志完全关闭，`RingBuffer` 至少需要 1 个槽位来存储最新一条记录（用于即时查询/调试）
2. **文件未启用时**：若 `FileEnabled == false`，日志仅保留在内存中，此时 `MemSize` 就是全部可查询的数据量
3. **落盘阈值**：当 `buffer.Len() >= MemSize` 时触发异步 flush，这意味着缓冲区在 flush 瞬间最多可能包含 `2 × MemSize` 条记录（flush 过程中新请求继续写入）

**触发落盘的条件**（文件：`internal/querylog/qlog.go:218-266`）：
- 当 `buffer.Len() >= conf.MemSize` 时，启动异步 goroutine 执行落盘
- 使用 `flushPending` 标志防止重复触发 flush

```go
func (l *queryLog) Add(params *AddParams) {
    entry := newLogEntry(ctx, l.logger, params)
    
    l.bufferLock.Lock()
    l.buffer.Push(entry)  // 推入环形缓冲区
    
    // 达到阈值则异步 flush
    if !l.flushPending && fileIsEnabled && l.buffer.Len() >= memSize {
        l.flushPending = true
        go l.flushLogBuffer(ctx)
    }
}
```

### 2.2 批量编码与文件追加

文件：`internal/querylog/querylogfile.go:17-101`

落盘流程分两步：

**步骤 1：encodeEntries() — JSON 批量编码**
- 加 `bufferLock` 遍历缓冲区
- 使用 `json.Encoder` 流式编码到 `bytes.Buffer`
- 编码完成后清空缓冲区并重置 `flushPending`

**步骤 2：flushToFile() — 追加写入磁盘**
```go
func (l *queryLog) flushToFile(ctx context.Context, b *bytes.Buffer) (err error) {
    // O_APPEND 模式打开，保证并发安全
    f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, ...)
    defer f.Close()
    f.Write(b.Bytes())  // 一次性写入所有编码后的 JSON 行
}
```

磁盘上的日志文件为 **JSON Lines** 格式（每行一个完整 JSON 对象）：
```json
{"T":"2024-01-15T10:30:00.123Z","QH":"example.com","QT":"A","QC":"IN","IP":"192.168.1.100","Result":{...}}
{"T":"2024-01-15T10:30:01.456Z","QH":"test.org","QT":"AAAA","QC":"IN","IP":"192.168.1.101","Result":{...}}
```

### 2.3 滚动归档策略

文件：`internal/querylog/querylogfile.go:103-207`

#### 2.3.1 时钟漂移应对：基于内容时间戳而非系统 tick

AdGuardHome 采用 **日志内容时间戳驱动** 的旋转策略，而非简单的按系统时间 tick，有效避免了时钟漂移问题：

```go
func (l *queryLog) checkAndRotate(ctx context.Context) {
    // 读取文件第一条记录的时间戳
    oldest, err := l.readFileFirstTimeValue(ctx)
    if err != nil { return }

    // 用 "最旧记录时间 + 旋转间隔" 与当前时间比较
    if rotTime, now := oldest.Add(rotationIvl), time.Now(); rotTime.After(now) {
        return  // 还没到旋转时间
    }

    l.rotate(ctx)  // 执行旋转
}
```

**时钟漂移应对优势**：
- 系统时间回拨不会导致旋转过早发生
- 服务重启后，仍能正确基于实际日志内容判断是否需要旋转
- NTP 时间同步抖动不影响归档逻辑

**检查周期**：使用 `time.NewTicker(1 * time.Hour)` 每小时触发一次检查，检查频率远小于最小旋转间隔（6 小时），保证时间精度足够（参考 issue #3823）。

#### 2.3.2 滚动归档档位

旋转间隔采用 **双轨校验** 机制：

**1. 前端预设档位（checkInterval）**（文件：`internal/querylog/qlog.go:115-126`）

Web 管理面板只提供 5 个预设档位，这些是经过测试验证的推荐值：

| 常量 | 值 |
|------|-----|
| `quarterDay` | 6 小时 |
| `day` | 1 天 |
| `week` | 7 天 |
| `month` | 30 天 |
| `threeMonths` | 90 天 |

**2. 自定义档位支持（validateIvl）**（文件：`internal/querylog/qlog.go:128-140`）

YAML 配置文件支持自定义旋转间隔，只要满足以下范围即可：

```go
func validateIvl(ivl time.Duration) (err error) {
    if ivl < time.Hour { return errors.Error("less than an hour") }
    if ivl > timeutil.Day*365 { return errors.Error("more than a year") }
    return nil
}
```

即 **1 小时 ~ 1 年** 之间任意值均可。`checkInterval()` 仅用于旧版 API 兼容判断，实际旋转逻辑使用 `validateIvl()` 的宽松范围。

#### 2.3.3 旋转动作

```go
func (l *queryLog) rotate(ctx context.Context) error {
    from := l.logFile       // querylog.json
    to := l.logFile + ".1"  // querylog.json.1
    if _, err := os.Stat(to); err == nil {
        os.Remove(to)  // 先删除旧的归档文件
    }
    return os.Rename(from, to)  // 原子 rename
}
```

> 实际保留时间 ≈ 2 × RotationIvl，因为始终保留 2 个文件（当前 + 归档），刚旋转完时当前文件是空的

---

## 三、热查询：内存索引检索

### 3.1 查询入口

文件：`internal/querylog/search.go:100-141`

`search()` 函数先查内存，再查磁盘，最后合并结果：

```go
func (l *queryLog) search(ctx context.Context, params *searchParams) (entries []*logEntry, oldest time.Time) {
    cache := clientCache{}
    
    // 第一步：检索内存缓冲区
    memoryEntries, bufLen := l.searchMemory(ctx, params, cache)
    
    // 第二步：检索磁盘文件
    fileEntries, oldest, total := l.searchFiles(ctx, params, cache)
    
    // 合并 + 排序 + 分页
    entries = append(memoryEntries, fileEntries...)
    slices.SortStableFunc(entries, func(a, b *logEntry) int {
        return -a.Time.Compare(b.Time)  // 按时间倒序
    })
    
    if params.offset > 0 { entries = entries[params.offset:] }
    if len(entries) > totalLimit { entries = entries[:totalLimit] }
    
    return entries, oldest
}
```

### 3.2 searchMemory() — 内存检索

文件：`internal/querylog/search.go:52-95`

```go
func (l *queryLog) searchMemory(ctx context.Context, params *searchParams, cache clientCache) ([]*logEntry, int) {
    // Check memory size, as the buffer can contain a single log record.  See
    // [newQueryLog].
    if l.conf.MemSize == 0 {
        return nil, 0
    }

    l.bufferLock.Lock()
    defer l.bufferLock.Unlock()
    
    l.buffer.ReverseRange(func(entry *logEntry) (cont bool) {
        e := entry.shallowClone()  // 浅拷贝，仅修改 client 字段
        e.client, _ = l.client(e.ClientID, e.IP.String(), cache)  // 富集客户端信息
        
        if params.match(e) {
            entries = append(entries, e)
        }
        return true  // 继续遍历
    })
    
    return entries, int(l.buffer.Len())
}
```

**特点**：
- `ReverseRange` 从新到旧遍历（符合用户期望的时间顺序）
- 使用 `clientCache` 避免重复查询客户端信息
- `shallowClone()` 保护原始条目不被修改

#### 3.2.1 并发读写安全：为什么用 Lock() 而不是 RLock()

文件：`internal/querylog/qlog.go:46-47`

```go
// bufferLock protects buffer.
bufferLock sync.RWMutex
```

虽然 `bufferLock` 声明为 `sync.RWMutex`（读写锁），但 `searchMemory()` 实际使用的是 **写锁 `Lock()`** 而非读锁 `RLock()`。这一设计有以下原因：

1. **遍历期间修改条目**：`ReverseRange` 回调中调用 `entry.shallowClone()` 并修改 `e.client` 字段。虽然是浅拷贝后的副本，但为了防止遍历过程中 `RingBuffer` 发生 Push 导致元素被覆盖，需要完整排他锁
2. **RingBuffer 内部状态**：`RingBuffer` 的 `ReverseRange` 遍历依赖内部头尾指针的稳定性，而 `Push()` 操作会修改这些指针
3. **简化锁粒度**：读/写路径都用写锁，虽然牺牲了并发读的性能，但避免了"读-读共享 + 读-写互斥"可能引入的复杂竞态问题

**锁的持有方**：
- 写入路径 `Add()`：`bufferLock.Lock()` → `buffer.Push()`
- 读取路径 `searchMemory()`：`bufferLock.Lock()` → `buffer.ReverseRange()`
- 落盘路径 `flushLogBuffer()`：`bufferLock.Lock()` → `buffer.PopAll()` → 编码

由于所有操作都使用写锁，内存检索与日志写入、缓冲区落盘三者之间是完全互斥的，不存在并发读写导致的数据竞争问题。

#### 3.2.2 bufferLock 读多写少优化：为什么是 RWMutex 却都用 Lock()

从代码声明看，`bufferLock` 是 `sync.RWMutex`（读写锁），理论上支持读-读共享。但实际所有调用方（Add / searchMemory / flushLogBuffer）都使用写锁 `Lock()` 而非读锁 `RLock()`。这一看似"浪费"的设计有其架构考量：

**为什么不用 RLock() 做读优化**：

1. **RingBuffer 遍历与 Push 竞态**：`RingBuffer` 是循环队列，`Push()` 会移动头指针并可能覆盖旧元素。如果读用 `RLock()`，多个读 goroutine 可以并发读取，但此时如果有 `Push()` 操作，就需要写锁，会被读锁阻塞。反过来，如果正在读遍历中，Push 无法写入，效果上与写锁差异不大

2. **读取频率与写入频率对比**：DNS 查询日志是 **写多读少** 场景——每秒可能有上百次 DNS 请求写入，但用户查询日志面板的频率低得多。读写锁的优势场景是"读多写少"，对于"写多读少"反而可能因锁升级等开销更慢

3. **简化正确性证明**：全部用写锁，锁的语义简单清晰，不容易出现"读遍历 + 并发写入导致切片越界"之类的隐蔽 bug

**真正的读多写少锁：confMu**

实际上，系统中存在另一把真正的"读多写少"锁——`confMu`：
```go
// confMu protects configuration fields.
confMu sync.RWMutex
```

`confMu` 保护配置字段（Enabled、FileEnabled、MemSize、RotationIvl 等），这些字段读取频率极高（每次 Add、每次 search 都要读），修改频率极低（用户改配置时才写），因此：
- **读路径**：`Add()`、`ShouldLog()`、`searchMemory()`、`checkAndRotate()` 都用 `confMu.RLock()`
- **写路径**：配置更新时才用 `confMu.Lock()`

这是读多写少场景的正确优化方式。`bufferLock` 虽然也是 RWMutex 类型，但其用途更偏向"互斥锁语义"，属于预留了扩展空间但当前未启用读优化的设计。

### 3.3 搜索条件匹配

文件：`internal/querylog/searchparams.go:66-80`、`internal/querylog/searchcriterion.go`

每个 `searchParams` 包含一组 `searchCriterion`，支持三种类型：

| 类型 | 匹配字段 | 说明 |
|------|----------|------|
| `ctTerm` | QHost, ClientID, IP, 客户端 Name | 域名/客户端搜索，支持 IDNA Punycode 转写，支持精确/模糊匹配 |
| `ctFilteringStatus` | Result.Reason, Result.IsFiltered | 按过滤状态筛选（已废弃，推荐用 ctReason） |
| `ctReason` | Result.Reason | 按具体过滤原因筛选（白名单/黑名单/安全浏览/家长控制等） |

搜索条件值对照表：
| HTTP 参数值 | 含义 |
|-------------|------|
| `all` | 全部查询 |
| `filtered` | 所有被过滤的（拦截+白名单+重写） |
| `blocked` | 被拦截的（黑名单 + 阻止的服务） |
| `blocked_services` | 被阻止的服务 |
| `blocked_safebrowsing` | 安全浏览拦截 |
| `blocked_parental` | 家长控制拦截 |
| `whitelisted` | 白名单放行 |
| `rewritten` | DNS 重写 |
| `safe_search` | 安全搜索强制 |
| `processed` | 正常处理（未被规则拦截/放行） |

---

## 四、冷数据：磁盘回读

### 4.1 多文件读取器 qLogReader

文件：`internal/querylog/qlogreader.go:14-174`

`qLogReader` 管理两个日志文件（从新到旧）：
```
files := []string{
    l.logFile + ".1",  // 归档文件（较旧）
    l.logFile,         // 当前文件（较新）
}
```

核心状态：
- `qFiles []*qLogFile` — 按"旧→新"顺序排列的文件句柄数组
- `currentFile int` — 当前正在读取的文件索引（初始指向最新文件）

### 4.2 单文件读取器 qLogFile

文件：`internal/querylog/qlogfile.go:34-428`

`qLogFile` 实现**反向读取**（从文件末尾向头部逐行读取）：

```go
type qLogFile struct {
    file        *os.File
    buffer      []byte    // 当前读取的文件块缓存
    position    int64     // 当前读取位置（从文件末尾递减）
    bufferStart int64     // buffer 在文件中的起始偏移
    bufferLen   int
}
```

**ReadNext() 反向读取算法**：
1. 检查 `position` 是否在当前 buffer 范围内，否则调用 `initBuffer()` 重新加载前一块
2. 在 buffer 中从 `relativePos` 向前扫描 `\n`，定位上一行的起始
3. 提取该行内容，更新 `position` 到行首前一位置

### 4.3 seekTS() — 按时间戳二分查找

文件：`internal/querylog/qlogfile.go:106-240`

这是冷数据检索的核心优化——**通过二分查找快速定位时间范围起点**：

```
算法步骤：
1. 取文件中间位置 probe = fileSize / 2
2. 读取 probe 所在的完整一行（readProbeLine）
3. 解析该行的时间戳 T
4. 若 T > targetTS：目标在左半部分，end = lineIdx
   若 T < targetTS：目标在右半部分，start = lineEndIdx
5. 重复直到 T == targetTS 或搜索深度 > 100
```

搜索过程状态保存在 `tsSearchState` 中：
```go
type tsSearchState struct {
    start, end, probe   int64   // 当前搜索区间 [start, end) 和探测点
    lineIdx, lastProbeLineIdx int64
    depth               int     // 当前迭代深度（上限 maxSearchDepth=100）
}
```

#### 4.3.1 损坏文件兜底策略

二分查找的前提是日志文件的**时间戳单调递增**。如果文件损坏、被篡改、或写入过程中断电导致最后一行不完整，`seekTS` 有多层兜底机制：

**1. 最大搜索深度保护**（`maxSearchDepth = 100`）
- 每轮迭代 `depth++`，超过 100 次立即终止并返回 `errTSNotFound`
- 防止因文件损坏导致二分搜索陷入死循环或无限递归

**2. 同行重复探测检测**（`validateQLogLineIdx`）
```go
func (q *qLogFile) validateQLogLineIdx(lineIdx, lastProbeLineIdx, ts, fSize int64) (err error) {
    if lineIdx == lastProbeLineIdx {
        if lineIdx == 0 {
            return errTSTooEarly  // 目标时间比文件最早记录还早
        }
        // 同一行被探测两次 → 搜索区间无法再收敛 → 未找到
        return fmt.Errorf("looking up timestamp %d in %q: %w", ts, q.file.Name(), errTSNotFound)
    } else if lineIdx == fSize {
        return errTSTooLate  // 目标时间比文件最新记录还晚
    }
    return nil
}
```

**3. 时间戳解析失败容错**
- `readQLogTimestamp()` 如果解析时间戳失败，返回 0
- 0 值会被当作"最早记录"处理，继续二分但最终会通过深度限制退出

**4. 上层兜底：seekRecord 失败回退**（`qlogreader.go`）
- 如果在某个文件中 seekTS 失败，`qLogReader` 会自动尝试下一个（更旧的）文件
- 如果所有文件都 seek 失败，回退到 `SeekStart()` 从最新文件末尾开始顺序读取

这种设计保证了即使日志文件存在损坏或异常，搜索过程也不会崩溃，最多是退化为顺序扫描，性能下降但功能可用。

#### 4.3.2 maxSearchDepth 为何是常量 100：固定上限而非自适应

`maxSearchDepth = 100` 是一个**硬编码常量**，而非根据文件大小动态计算的自适应值。设计考量如下：

**理论推导**：二分查找的时间复杂度是 O(log n)。对于 1GB 的日志文件，假设每行平均 500 字节，约 200 万行记录，log₂(2,000,000) ≈ 21 次迭代即可完成。100 的上限是理论值的 5 倍左右，留有极大冗余。

**为什么不自适应**：

1. **常量足够大**：100 次迭代对于任何实际大小的日志文件都绰绰有余。即使文件损坏导致搜索范围收敛很慢，100 次也足以判断异常
2. **实现简单**：不需要根据 fileSize 计算理论深度，直接一个常量了事
3. **安全冗余**：对于"近乎有序但局部乱序"的损坏文件，二分查找可能失效导致深度增加，100 的上限能及时终止

**与损坏文件兜底的配合**：
- 正常文件：深度 ≈ log₂(行数)，通常 20~30 次
- 轻微损坏：深度 50~80 次，最终能找到目标但路径曲折
- 严重损坏：深度达到 100 → 触发 `errTSNotFound` → 上层回退到顺序扫描

即 maxSearchDepth 既是**性能上限**也是**损坏检测阈值**。

#### 4.3.3 时间戳解析 0 的告警与错误传播

当 `readQLogTimestamp()` 解析失败时返回 0，在不同调用上下文中有不同的处理策略：

**1. seekTS 路径：直接报错终止**（文件：`internal/querylog/qlogfile.go:196-204`）
```go
ts := readQLogTimestamp(ctx, l, line)
if ts == 0 {
    return false, fmt.Errorf(
        "looking up timestamp %d in %q: record %q has empty timestamp",
        timestamp, q.file.Name(), line,
    )
}
```
- 二分查找过程中遇到损坏行 → 立即返回错误
- 错误逐层上传至 `seekTS` → `qLogReader.seekTS` → `setQLogReader`
- 最终上层 `searchFiles` 收到 nil reader，回退为只查内存

**2. 顺序扫描路径：记录错误但继续**（文件：`internal/querylog/search.go:340-344`）
```go
if !params.quickMatch(ctx, l.logger, line, clientFinder.findClient) {
    ts = readQLogTimestamp(ctx, l.logger, line)  // 可能返回 0
    return nil, ts, nil  // 不报错，跳过这一行
}
```
- quickMatch 不通过时，需要读取时间戳来更新 `oldestNano` 游标
- 即使解析失败（返回 0），也只是跳过这一行继续下一行
- 不会因为个别坏行导致整个查询失败

**3. 告警日志**（文件：`internal/querylog/qlogfile.go:478-488`）
```go
if len(val) == 0 {
    logger.ErrorContext(ctx, "couldn't find timestamp", "line", str)
    return 0
}
tm, err := time.Parse(time.RFC3339Nano, val)
if err != nil {
    logger.ErrorContext(ctx, "couldn't parse timestamp", "value", val, slogutil.KeyError, err)
    return 0
}
```
- 两种失败场景都输出 `Error` 级别日志，便于运维排查
- 但不 panic、不中断服务，体现了"日志系统不应影响核心 DNS 服务"的设计原则

### 4.4 磁盘检索完整流程

文件：`internal/querylog/search.go:261-288`

```
searchFiles(params)
    ↓
setQLogReader(olderThan)
    ├─ 打开 querylog.json.1 和 querylog.json
    └─ seekRecord(olderThan)
           ├─ 若 olderThan 为空：SeekStart() → 直接定位到最新文件末尾
           └─ 否则：seekTS(olderThan) 二分查找 + ReadNext() 跳过目标行
    ↓
readEntries(r, params, totalLimit)
    └─ 循环读取：
        readNextEntry()
            ├─ ReadNext() 读取一行 JSON
            ├─ quickMatch() 快速字符串匹配（不解码完整 JSON）
            │     ├─ ctTerm: 直接用 readJSONValue 提取 "QH"/"IP"/"CID" 字段比较
            │     └─ ctReason: 提取 "Reason": 数值比较
            ├─ 若 quickMatch 通过：decodeLogEntry() 完整 JSON 解码
            ├─ params.match(e) 精确匹配过滤条件
            └─ 符合条件则加入结果集
        ↑ 直到达到 maxFileScanEntries（默认 50000）或 totalLimit
```

**quickMatch 优化**：不解码完整 JSON，仅用 `strings.Index` + 简单 JSON 值提取函数做快速预筛，大幅减少冷数据扫描的 CPU 开销。

#### 4.4.1 quickMatch 字段预筛误判机制

文件：`internal/querylog/searchcriterion.go:135-180`

`quickMatch` 是一种 **"宁可错杀，不可放过"** 的预筛策略——它只负责快速排除明显不匹配的记录，可能存在假阳性（误判为匹配），但绝不会出现假阴性（漏掉匹配项）。

**工作原理**：
```go
func (c *searchCriterion) quickMatch(ctx, logger, line string, findClient quickMatchClientFunc) (ok bool) {
    switch c.criterionType {
    case ctTerm:
        host := readJSONValue(line, `"QH":"`)     // 直接字符串索引提取
        ip := readJSONValue(line, `"IP":"`)
        clientID := readJSONValue(line, `"CID":"`)
        // ... 与搜索项比较
    case ctReason:
        reasonCode := readJSONNumericValue(line, `"Reason":`)
        // ... 数值比较
    case ctFilteringStatus:
        return true  // 完全不预筛，一律放行
    }
}
```

**可能产生误判的场景**：

1. **字段 key 出现在 value 中**：`readJSONValue` 用 `"QH":"` 作为查找前缀，如果某个字段的 value 值恰好包含这个字符串（理论可能，实际极低概率），会定位到错误位置

2. **JSON 转义字符干扰**：`readJSONValue` 是简单的字符串扫描，不处理 JSON 转义（如 `\"`），如果 value 中包含转义引号可能截断错误

3. **ctFilteringStatus 完全不预筛**：过滤状态类型的搜索条件，quickMatch 直接返回 `true`，所有记录都放过，完全依赖后续精确匹配

**误判的兜底：精确匹配二次校验**

```
quickMatch 通过 ?
    ├─ 是 → decodeLogEntry() 完整 JSON 解码 → params.match(e) 精确匹配
    │        └─ 精确匹配不通过 → 丢弃（这就是误判的修正）
    └─ 否 → 直接跳过，不解码
```

即 `quickMatch` 是"准入式"预筛：
- **假阳性（误判匹配）**：代价是多做一次 JSON 解码，CPU 有浪费但结果正确
- **假阴性（漏判）**：绝对不允许，这是设计底线

三层过滤的执行路径：
```
原始 JSON 行
    ↓
quickMatch() — 快速字符串预筛（约 1/10 解码耗时）
    ↓  通过（含误判）
decodeLogEntry() — 完整 JSON 反序列化
    ↓
params.match() — 精确字段匹配
    ↓
结果集
```

#### 4.4.2 quickMatch 二次校验的性能权衡

quickMatch + 精确匹配的"两阶段过滤"设计，本质是**用快速预筛换 CPU 时间**的经典优化。其性能收益取决于过滤命中率：

**性能模型分析**：

假设：
- quickMatch 耗时：T_q（约一次字符串 Index + 几次比较）
- 完整解码 + 精确匹配耗时：T_d（约 10~50 倍 T_q）
- 预筛通过率：P（0 < P < 1）

则平均每条记录的过滤耗时 = T_q + P × T_d

| 场景 | P（通过率） | 平均耗时 | 加速比 |
|------|------------|----------|--------|
| 搜索罕见域名 | 0.1% | ≈ T_q + 0.001×T_d | ~100x |
| 搜索常见关键词 | 10% | ≈ T_q + 0.1×T_d | ~10x |
| 全量查询（无过滤） | 100% | ≈ T_q + T_d | ~0.9x（略慢） |

**结论**：
- 当搜索条件较严格（命中率低）时，quickMatch 带来巨大性能提升
- 当全量查询（无 search 参数）时，quickMatch 反而有轻微 overhead，但这是可接受的

**ctFilteringStatus 为何完全跳过预筛**：

`ctFilteringStatus` 类型的搜索条件，quickMatch 直接返回 `true`。原因是：
- 过滤状态需要解析 `IsFiltered` 和 `Reason` 两个字段，并进行逻辑组合判断
- 简单的字符串提取容易出错（Reason 字段是数字，但还需要结合 IsFiltered 布尔值）
- 该过滤条件在实际使用中命中率中等，预筛的收益不确定，不如直接解码保证正确性

### 4.5 qLogReader 大文件超时保护

qLogReader 本身**没有显式的超时机制**，但通过多层设计间接防止了大文件扫描导致的服务不可用：

**1. maxFileScanEntries 软限制**（文件：`internal/querylog/searchparams.go:25-27`）
```go
// maxFileScanEntries is a maximum of log entries to scan in query log
// files at once.
maxFileScanEntries int
```
默认 50000 条的扫描上限，即使文件再大，单次请求也只扫 5 万条就返回，避免单次请求占用过长时间。

**2. Context 透传**

整个读取链路上下文是透传的：
```
search(ctx) → searchFiles(ctx) → setQLogReader(ctx) → seekTS(ctx) → readNextEntry(ctx)
```
如果上层 HTTP handler 设置了请求超时，会通过 `context.Done()` 传播。但实际实现中，`ReadNext()` 等读取操作是纯 CPU + 磁盘 IO 的同步操作，不会主动检查 context，超时只能在两次读取之间生效。

**3. 分批查询 + 游标分页**

前端通过 `older_than` 游标分页，每次只请求一页数据。大文件被拆分为多次小请求处理，单次请求的资源占用可控。

**4. 并发安全锁**

`qLogFile` 内部有 `sync.Mutex`，但 `qLogReader` 作为单次查询的临时对象，通常不会被并发访问。锁的主要作用是防止同一 reader 被并发调用导致的内部状态混乱。

> 总结：qLogReader 的"超时保护"不是通过 deadline 实现的硬性中断，而是通过 **扫描上限 + 分批查询** 的设计，从架构上避免单次请求处理过大文件。

---

## 五、统计面板：过滤与导出

### 5.1 HTTP API 接口

文件：`internal/querylog/http.go:63-77`

| 方法 | 路径 | 功能 |
|------|------|------|
| `GET` | `/control/querylog` | 查询日志（分页 + 过滤） |
| `POST` | `/control/querylog_clear` | 清空所有日志 |
| `GET` | `/control/querylog/config` | 获取日志配置 |
| `PUT` | `/control/querylog/config/update` | 更新日志配置 |

### 5.2 查询参数解析

文件：`internal/querylog/http.go:430-508`

`GET /control/querylog` 支持以下查询参数：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `older_than` | RFC3339Nano | 空 | 仅返回早于此时间的记录（用于无限滚动分页） |
| `limit` | int | 500 | 返回记录数上限 |
| `offset` | int | 0 | 偏移量（与 older_than 二选一） |
| `search` | string | 空 | 搜索关键词（域名/客户端IP/ID/名称） |
| `response_status` | string | 空 | 过滤状态（与 reason 互斥） |
| `reason` | string[] | 空 | 按过滤原因筛选（可多选） |

**注意**：使用 `offset` 时 `maxFileScanEntries` 自动设为 0（无扫描上限），因为需要遍历到准确的偏移位置。

### 5.3 前端过滤交互

文件：`client/src/components/Logs/Filters/Form.tsx`

前端过滤表单包含两个控件：
1. **搜索框** (`search`)：支持域名/客户端搜索，双引号包裹表示精确匹配
2. **响应状态下拉框** (`response_status`)：对应后端 `ctFilteringStatus`

```
用户输入 → useDebounce(300ms 防抖) → dispatch(setLogsFilter)
    → dispatch(setFilteredLogs) → apiClient.getQueryLog(params)
        → GET /control/querylog?search=xxx&response_status=yyy
```

### 5.4 前端无限滚动分页

文件：`client/src/actions/queryLogs.ts:10-68`

分页采用 **cursor-based** 策略（基于 `older_than` 时间游标）：

```
初始加载：older_than = ""，获取最新 N 条
    ↓
服务端返回 { data: [...], oldest: "2024-01-15T10:00:00Z" }
    ↓
滚动到底部：
    调用 getLogs() 携带 older_than = 上次返回的 oldest
    ↓
服务端 seekTS(oldest) 定位后继续向后读取
```

**短轮询优化** (`shortPollQueryLogs`)：当返回结果不足一页且 `oldest` 非空时，前端自动递归请求直到凑够一页或遍历完毕。

### 5.5 响应 JSON 格式

文件：`internal/querylog/json.go:24-98`

```json
{
  "data": [
    {
      "reason": "FilteredBlackList",
      "elapsedMs": "12.34",
      "time": "2024-01-15T10:30:00.123Z",
      "client": "192.168.1.100",
      "client_proto": "",
      "cached": false,
      "upstream": "https://dns.google/dns-query",
      "question": {
        "type": "A",
        "class": "IN",
        "name": "example.com",
        "unicode_name": "example.com"
      },
      "answer": [{"type": "A", "value": "93.184.216.34", "ttl": 3600}],
      "status": "NOERROR",
      "rules": [{"filter_list_id": 1, "text": "||example.com^"}],
      "rule": "||example.com^",
      "filterId": 1
    }
  ],
  "oldest": "2024-01-15T10:29:00.456Z"
}
```

### 5.6 清空日志

文件：`internal/querylog/qlog.go:151-180`

`clear()` 操作：
1. 加 `fileFlushLock`，清空内存环形缓冲区
2. 删除 `querylog.json.1`（归档文件）
3. 删除 `querylog.json`（当前文件）

### 5.7 IP 匿名化

文件：`internal/querylog/http.go:153-164`

当配置 `AnonymizeClientIP = true` 时：
- IPv4：清零最后 2 字节（如 `192.168.1.100` → `192.168.0.0`）
- IPv6：清零最后 10 字节

匿名化函数在返回响应前应用，同时匿名化后的 IP 不会附加 `client_info`（防止通过客户端名称反推）。

### 5.8 大批量流式导出：游标分页 + 渐进式拉取

AdGuardHome 没有单独的"导出" API 端点，而是通过查询接口的 **游标分页机制** 实现大批量数据的流式拉取。这种设计使得导出与查询共用同一条代码路径，避免了重复实现。

#### 5.8.1 两种分页模式的取舍

| 分页模式 | 参数 | 适用场景 | maxFileScanEntries |
|---------|------|----------|-------------------|
| 游标分页 | `older_than` + `limit` | 面板无限滚动、流式导出 | 50000（默认） |
| 偏移分页 | `offset` + `limit` | 精确定位跳页 | 0（无上限） |

**为什么 offset 模式取消扫描上限**（文件：`internal/querylog/http.go:460-462`）：
```go
// If we don't use "olderThan" and use offset/limit instead, we should change the default behavior
if !p.olderThan.IsSet() {
    p.maxFileScanEntries = 0
}
```
因为 offset 模式需要准确跳过 N 条记录，必须从最新记录开始一直扫描到 offset 位置，不能用 maxFileScanEntries 截断，否则 offset 会不准确。

#### 5.8.2 流式导出的实现路径

虽然没有官方的"导出"按钮，但基于现有 API 可以实现完整的全量导出：

```
第 1 次请求：GET /control/querylog?limit=500
    ← 返回 { data: [...500条...], oldest: "2024-01-15T10:00:00Z" }

第 2 次请求：GET /control/querylog?limit=500&older_than=2024-01-15T10:00:00Z
    ← 返回 { data: [...下一批...], oldest: "2024-01-15T09:00:00Z" }

... 循环 ...

第 N 次请求：返回 oldest 为空或 data 为空
    → 导出完成
```

每次请求的服务端处理流程：
```
seekTS(olderThan)  — O(log n) 二分定位
    ↓
ReadNext() 反向逐行读取
    ↓
quickMatch() 快速预筛 + decode + 精确匹配
    ↓
收集 limit 条结果后返回
    ← 同时返回本次扫描到的最旧时间戳作为下一页游标
```

#### 5.8.3 单批次扫描上限（maxFileScanEntries）

文件：`internal/querylog/searchparams.go:25-37`

默认 `maxFileScanEntries = 50000`，这是一个 **服务端自保机制**：
- 当过滤条件很严格（匹配率低）时，可能需要扫描大量记录才能凑够 limit 条
- 限制单次扫描上限，避免单次请求占用过多 CPU/IO
- 前端可通过 `oldest` 游标继续翻页，由多次请求分摊扫描成本

扫描上限的设计权衡：
- **值越大**：越少的请求次数，越高的单次延迟，越高的瞬时资源占用
- **值越小**：越多的请求次数，越低的单次延迟，更平滑的资源消耗

#### 5.8.2 50000 上限与分页参数的联动设计

`maxFileScanEntries` 与 `limit` / `offset` / `older_than` 三个分页参数之间存在复杂的联动关系：

**1. 游标分页模式（older_than + limit）**
- `maxFileScanEntries = 50000`（默认）
- 设计意图：扫描最多 5 万条，尽量凑够 limit 条返回
- 如果 5 万条内凑够了 limit 条 → 正常返回，oldest 作为下一页游标
- 如果扫了 5 万条还没凑够 limit → 提前返回，前端可继续翻页

**2. 偏移分页模式（offset + limit）**
- `maxFileScanEntries = 0`（自动取消上限）
- 原因：offset 需要精确跳过 N 条，必须从最新记录一直数到 offset 位置
- 如果有扫描上限，可能数到一半就停了，导致 offset 不准
- 代价：offset 越大，扫描量越大，延迟越高（全表扫描）

**3. 三种典型场景的扫描量**：

| 场景 | 参数 | 实际扫描量 | 原因 |
|------|------|-----------|------|
| 全量翻页第一页 | limit=500, 无过滤 | ~500 条 | 无过滤条件，每条都匹配，扫 500 条就够了 |
| 严格过滤 + 翻页 | search="罕见域名" + limit=500 | 最高 50000 条 | 匹配率低，需要扫很多条才能凑够 500 条 |
| offset 深分页 | offset=10000 + limit=500 | 至少 10500 条 | offset 模式无上限，必须数到第 10000 条 |

这种设计体现了**常用路径优化**的思路：游标分页是用户正常浏览的路径，有上限保护；offset 深分页是 API 调用者的路径，虽然慢但结果准确。

#### 5.8.3 shortPollQueryLogs 的放大攻击面与防护

前端 `shortPollQueryLogs` 的自动补页机制存在潜在的放大攻击风险，但有多层防护：

**风险分析**：
如果过滤条件非常严格（如搜索一个不存在的域名），每次请求可能扫描 50000 条却只返回 0 条匹配。shortPoll 检测到"数据不足一页且还有 oldest"，会递归发起下一次请求……理论上可能在一次用户操作中触发大量后端扫描。

**实际防护机制**：

**1. 服务端：maxFileScanEntries 限制**
每次请求最多扫 5 万条，即使递归 10 次也只有 50 万条，CPU 占用可控。

**2. 前端：isQueryTheSame 校验**
```typescript
const isQueryTheSame = 
    typeof previousQuery === 'string' && 
    typeof currentQuery === 'string' && 
    previousQuery === currentQuery;

const isShortPollingNeeded =
    (logs.length < QUERY_LOGS_PAGE_LIMIT || totalData.logs.length < QUERY_LOGS_PAGE_LIMIT) &&
    oldest !== '' &&
    isQueryTheSame;
```
只有搜索词相同才会自动补页。如果搜索词在短时间内多次变化，不会触发补页。

**3. 前端：oldest 空值终止**
当服务端返回的 `oldest` 为空字符串时，短轮询立即终止，不会无限递归。

**4. 自然终止条件**
- 日志文件只有 2 个，最多翻 2 个文件就到底了
- 即使每次 5 万条都匹配 0 个，最多也只递归 2 次（当前文件 + 归档文件）

**攻击面评估**：
实际很难被放大攻击。最坏情况下一次过滤操作触发 2~3 次后端请求，每次扫 5 万条，总共 10~15 万条扫描量，对于服务器来说完全可接受。

### 5.9 MemSize 热点时段动态调整策略

**当前实现：静态配置**

AdGuardHome 当前的 `MemSize` 是**静态配置**，启动时或修改配置时设置一次，运行中不会动态变化。但从架构设计来看，它具备动态调整的基础能力：

**配置热更新路径**：
```
用户修改配置 → PUT /control/querylog/config/update
    → queryLog.writeDiskConfig() 更新配置文件
    → 内部通过 confMu.RLock() / Lock() 切换配置
    → 下次 Add() 时读取新的 MemSize
```

**为什么不做"热点时段动态调整"**：

1. **RingBuffer 的 OOM 保护已经足够**：即使流量高峰，RingBuffer 满了就覆盖最旧的，不会内存爆炸
2. **落盘是异步的**：flush goroutine 后台写盘，不阻塞 DNS 请求处理
3. **读写频率不对等**：写远多于读，内存缓冲区主要作用是"批量写盘"而非"缓存查询"
4. **配置变更简单**：用户可以随时通过 API 调整 MemSize 并立即生效，不需要自动化

**隐含的"动态调整"：FileEnabled 开关**

虽然 MemSize 本身不动态变化，但有一个相关的"降级策略"：
- 如果 `FileEnabled = false`，日志只保留在内存中，`MemSize` 就是全部可查询数据量
- 如果 `FileEnabled = true`，内存缓冲区只是"写盘前的暂存"，热数据主要靠磁盘文件 + seekTS 二分查找

这种"内存缓冲区 + 磁盘文件"的分层架构，本身就是对不同访问频率数据的自然分级——最新的在内存（最快），稍旧的在当前文件（二分查找定位），最旧的在归档文件（顺序扫描）。

**如果要实现热点时段动态调整，可以基于以下扩展点**：
- 在 `periodicRotate` 检查时根据最近 1 小时的请求量动态调整 MemSize
- 需要创建新的 RingBuffer 并原子替换（现有 `bufferLock` 可以保护）
- 但考虑到 RingBuffer 的 OOM 保护和异步落盘已经足够稳健，实际收益不大

---

## 关键文件索引

| 文件 | 核心职责 |
|------|----------|
| `internal/querylog/querylog.go` | 对外接口 `QueryLog`、配置 `Config`、`New()` 构造函数 |
| `internal/querylog/qlog.go` | `queryLog` 结构体、`Add()` 入站方法、`Start()`/`Shutdown()` 生命周期 |
| `internal/querylog/entry.go` | `logEntry` 结构体、DNS 报文打包 |
| `internal/querylog/querylogfile.go` | `flushLogBuffer()` 落盘、`rotate()` 滚动归档 |
| `internal/querylog/qlogfile.go` | 单文件反向读取器 `qLogFile`、`seekTS()` 二分时间查找 |
| `internal/querylog/qlogreader.go` | 多文件联合读取器 `qLogReader` |
| `internal/querylog/search.go` | `search()` 主查询入口、内存/磁盘检索合并 |
| `internal/querylog/searchparams.go` | 搜索参数 `searchParams`、`match()`/`quickMatch()` |
| `internal/querylog/searchcriterion.go` | 搜索条件 `searchCriterion` 三类型实现 |
| `internal/querylog/decode.go` | JSON 行流式解码 `decodeLogEntry()` |
| `internal/querylog/json.go` | API 响应 JSON 序列化 `entriesToJSON()` |
| `internal/querylog/http.go` | HTTP 路由注册、请求解析、响应返回 |
| `internal/querylog/client.go` | 客户端信息缓存 |
| `internal/dnsforward/stats.go` | DNS 层触发日志写入的入口 `logQuery()` |
| `client/src/actions/queryLogs.ts` | 前端 Redux actions：获取/过滤/清空日志 |
| `client/src/components/Logs/` | 前端 UI 组件：过滤表单、无限滚动表格 |

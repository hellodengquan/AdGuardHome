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

### 2.1 内存环形缓冲区

文件：`internal/querylog/querylog.go:158-179`、`internal/querylog/qlog.go:26-54`

日志先写入内存环形缓冲区 `RingBuffer`，这是一个定长循环队列：

```go
l = &queryLog{
    buffer: container.NewRingBuffer[*logEntry](memSize),  // 默认 1000 条
    // ...
}
```

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

**定时检查周期**：每 1 小时检查一次（`rotationCheckIvl = 1 * time.Hour`）

**旋转条件**：
1. 读取当前日志文件第一条记录的时间戳 `oldest`
2. 若 `oldest + RotationIvl <= now`，执行旋转

**旋转动作**：
```go
func (l *queryLog) rotate(ctx context.Context) error {
    from := l.logFile       // querylog.json
    to := l.logFile + ".1"  // querylog.json.1
    return os.Rename(from, to)
}
```

**支持的旋转间隔**（文件：`internal/querylog/qlog.go:115-126`）：
| 常量 | 值 |
|------|-----|
| `quarterDay` | 6 小时 |
| `day` | 1 天 |
| `week` | 7 天 |
| `month` | 30 天 |
| `threeMonths` | 90 天 |

> 实际保留时间 = 2 × RotationIvl，因为始终保留 2 个文件（当前 + 归档）

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

# AdGuard Home 统计聚合与数据桶切换流程分析

## 核心文件一览

| 文件 | 职责 |
|------|------|
| `internal/stats/stats.go` | 主统计上下文 `StatsCtx`、周期性刷新、数据库操作、数据桶生命周期管理 |
| `internal/stats/unit.go` | 数据单元 `unit` 定义、序列化/反序列化、Top 统计计算、时段聚合 |
| `internal/stats/http.go` | HTTP API 处理器、请求参数解析、响应结构定义 |
| `internal/dnsforward/stats.go` | DNS 查询后处理：构造 `Entry`、调用统计更新 |

---

## 一、数据桶（Stats Bucket）切换机制

### 1.1 什么是数据桶

数据桶是 AdGuard Home 统计系统的基本存储单位，**每小时**一个桶，对应一个 `unit` 实例。每个桶拥有独立的 ID：

```go
// unit.go:184-188
func newUnitID() (id uint32) {
    const secsInHour = int64(time.Hour / time.Second)
    return uint32(time.Now().Unix() / secsInHour)
}
```

- ID = UNIX 时间戳 ÷ 3600（自 1970-01-01 以来的**绝对小时数**，使用 UTC，天然免疫时区与 DST）
- 在 bbolt 数据库中，每个桶对应一个 Bucket，键名为 8 字节大端编码的 ID：`unit.go:207-212` — `idToUnitName()` / `unitNameToID()`

### 1.2 桶切换的触发流程

桶切换由后台 goroutine `periodicFlush` 驱动，运行路径如下：

```
periodicFlush() [stats.go:496-502]
  └─> flush() [stats.go:420-442]
        ├─ 生成新 ID: id = unitIDGen()
        ├─ 检查: ptr.id == id ?
        │     ├─ 相同: sleep 1s 后重试（未到切换点）
        │     └─ 不同: 触发切换 → flushDB()
        └─> flushDB(id, limit, ptr) [stats.go:446-489]
              ├─ 开启数据库事务
              ├─ s.curr = newUnit(id)    // ① 替换当前桶为新空桶
              ├─ ptr.serialize()         // ② 旧桶序列化为 unitDB
              ├─ flushUnitToDB()         // ③ 写入旧桶到 bbolt
              └─ DeleteBucket(id-limit)  // ④ 删除最老的过期桶
```

**关键代码位置：**

- 切换判定：`stats.go:437` — `ptr.id == id` 时不切换
- 新桶创建：`stats.go:465` — `s.curr = newUnit(id)`
- 旧桶落盘：`stats.go:467-468` — `serialize()` + `flushUnitToDB()`
- 旧桶淘汰：`stats.go:474` — `DeleteBucket(id - limit)`

### 1.3 桶的数量限制与滑动窗口

`Limit` 配置决定保留多少小时的历史数据：

```
保留桶数 = limit.Hours()
例如：limit=24h → 保留 24 个桶（1 天）
     limit=720h → 保留 720 个桶（30 天）
```

每次切换时，淘汰 `id - limit` 对应的最旧桶，形成**滑动窗口**。

启动时还会执行一次清理：`stats.go:200` — `deleteOldUnits(tx, id-uint32(s.limit.Hours())-1)`

### 1.4 内存中的当前桶 vs 磁盘上的历史桶

```
┌──────────────────────────────────────────────────────┐
│                     StatsCtx                         │
│                                                      │
│  curr (*unit) ────────► 当前小时的内存桶（读写热点） │
│                         - domains map                │
│                         - blockedDomains map         │
│                         - clients map                │
│                         - upstreams* maps            │
│                         - nResult[]                  │
│                                                      │
│  db (bbolt.DB) ───────► 历史桶存储（只读 + 追加）    │
│                         Bucket [id-720] ... [id-1]   │
└──────────────────────────────────────────────────────┘
```

- **写入路径**：所有 `Update()` 只操作内存中的 `curr`（`stats.go:302`）
- **读取路径**：`loadUnits()` 同时加载磁盘桶 + 当前桶序列化（`stats.go:602-617`）

---

## 二、bbolt 持久化完整路径

### 2.1 启动加载（New → openDB → 加载当前桶 → 清理旧桶）

`New()` 函数在 `stats.go:155-214` 中完成冷启动加载：

```go
// stats.go:155-214
func New(conf Config) (s *StatsCtx, err error) {
    // 1. 校验配置
    err = validateIvl(conf.Limit)          // stats.go:158
    // 2. 打开 bbolt 数据库
    err = s.openDB()                       // stats.go:187
    // 3. 开启事务
    tx, err := s.db.Load().Begin(true)     // stats.go:195
    // 4. 清理过期桶（一次性删除所有 ID < firstID 的 Bucket）
    deleted := s.deleteOldUnits(tx, id-uint32(s.limit.Hours())-1)  // stats.go:200
    // 5. 加载当前小时桶（若不存在则返回 nil，后续 deserialize 跳过）
    udb := s.loadUnitFromDB(tx, id)        // stats.go:201
    // 6. 提交/回滚事务
    err = finishTxn(tx, deleted > 0)       // stats.go:203
    // 7. 构造内存桶并反序列化（如 udb=nil 则保持空桶）
    s.curr = newUnit(id)                   // stats.go:208
    s.curr.deserialize(udb)                // stats.go:209
}
```

**数据库打开细节** `stats.go:389-418` — `openDB()`：
- 使用 `bbolt.Open(filename, 0644, nil)` 以默认文件权限打开
- 若返回 "invalid argument" 错误，说明文件系统不支持 mmap/文件锁，打印告警提示
- `db` 通过 `atomic.Pointer[bbolt.DB]` 存储，支持无锁读取与 `clear()` 中的原子替换

**加载单个桶** `unit.go:277-297` — `loadUnitFromDB()`：
```go
func (s *StatsCtx) loadUnitFromDB(tx *bbolt.Tx, id uint32) (udb *unitDB) {
    bkt := tx.Bucket(idToUnitName(id))     // 按 8 字节大端 ID 找 Bucket
    if bkt == nil { return nil }
    var buf bytes.Buffer
    buf.Write(bkt.Get([]byte{0}))          // Bucket 内固定键 []byte{0} 存完整 GOB
    udb := &unitDB{}
    gob.NewDecoder(&buf).Decode(udb)       // GOB 反序列化
    return udb
}
```

> ⚠️ **冷启动数据完整性边界**：如果上一次进程异常退出（如 kill -9、掉电），当前小时内存桶的数据**完全丢失**，因为只有 `periodicFlush` 到整点或 `Close()` 才会写盘。bbolt 提供单事务原子性，但不会自动刷未提交的内存桶。

### 2.2 periodicFlush 写盘节奏与掉电边界

后台 goroutine `periodicFlush()` `stats.go:496-502` 的执行节奏：

```go
func (s *StatsCtx) periodicFlush() {
    for cont, sleepFor := true, time.Duration(0); cont; time.Sleep(sleepFor) {
        cont, sleepFor = s.flush()
    }
}
```

`flush()` `stats.go:420-442` 的行为：
1. **非整点**：`ptr.id == id` → 返回 `(true, 1s)`，每秒轮询一次
2. **整点刚过**：`ptr.id != id` → 调用 `flushDB()` 原子切换，返回 `(true, 0)`，立即进入下一轮（此时又回到非整点，sleep 1s）

**掉电边界（数据丢失窗口）**：
```
[桶 N 写入 bbolt] ──── [接下来最多 1 小时的内存增量] ──── [下一次 flushDB]
                    ↑ 这段时间掉电 = 丢失整个小时数据
```

**具体 flushDB 事务原子性** `stats.go:446-489`：
```go
func (s *StatsCtx) flushDB(id, limit uint32, ptr *unit) (cont bool, sleepFor time.Duration) {
    tx, err := db.Begin(true)              // stats.go:453 开启读写事务
    defer func() { err = finishTxn(tx, isCommitable) }()  // stats.go:459-463 统一提交/回滚

    s.curr = newUnit(id)                   // stats.go:465 ① 先换桶（写请求立刻到新桶）

    udb := ptr.serialize()                 // ② 旧桶序列化（不会再被写入）
    flushErr := s.flushUnitToDB(udb, tx, ptr.id)  // ③ 写入旧 Bucket
    delErr := tx.DeleteBucket(idToUnitName(id - limit))  // ④ 删最旧 Bucket

    // 两个操作任一失败（非 BucketNotFound）→ isCommitable=false → 整体回滚
}
```

> 💡 **提交原子性**：bbolt 保证单事务内的"写入新 Bucket + 删除旧 Bucket"要么一起生效要么都不生效。但要注意：`s.curr = newUnit(id)` 发生在事务提交之前，这意味着如果事务回滚，内存中已经开始写入的"新桶"数据会被**下一次成功切换时覆盖**（不会丢数据，只是新桶 ID 和磁盘上的对不上时会再次触发 flush）。

### 2.3 停服 flush（Close 方法）

优雅关闭时 `Close()` `stats.go:246-274` 保证当前内存桶落盘：

```go
func (s *StatsCtx) Close() (err error) {
    db := s.db.Swap(nil)                   // ① 原子取出 DB 指针，阻止新的读写事务
    if db == nil { return nil }
    defer func() { cerr := db.Close(); ... }()  // ② 最后关闭数据库文件

    s.currMu.RLock()                       // stats.go:262 ③ 先锁 currMu（注释强调：与事务联用时必须先锁此锁）
    defer s.currMu.RUnlock()

    udb := s.curr.serialize()              // ④ 序列化当前桶
    tx, err := db.Begin(true)              // ⑤ 开启事务
    defer func() { err = errors.WithDeferred(err, finishTxn(tx, err == nil)) }()

    return s.flushUnitToDB(udb, tx, s.curr.id)  // ⑥ 写入 bbolt，不删旧桶
}
```

**停服掉电边界**：
- 发送 SIGTERM 后，如果能在 `db.Swap(nil)` 和后续 `db.Close()` 之间完成写入 → 数据完整
- 如果 SIGKILL / 断电在 `Close()` 之前到达 → 当前小时数据全部丢失（与运行时掉电窗口一致）

### 2.4 掉电恢复与反序列化失败容错

#### 2.4.1 GOB 反序列化失败的处理

`loadUnitFromDB()` `unit.go:277-297` 中，如果 GOB 解码失败（典型场景：掉电导致写入半截数据、文件系统损坏、版本升级导致结构不兼容）：

```go
func (s *StatsCtx) loadUnitFromDB(tx *bbolt.Tx, id uint32) (udb *unitDB) {
    bkt := tx.Bucket(idToUnitName(id))
    if bkt == nil { return nil }          // 桶不存在 → nil，上层用空桶补位
    // ...
    err := gob.NewDecoder(&buf).Decode(udb)
    if err != nil {
        s.logger.Error("gob decode", slogutil.KeyError, err)  // 只打 Error 日志
        return nil                                                // 返回 nil
    }
    return udb
}
```

**容错策略：失败即丢弃，不抛出错误**。返回 `nil` 后由上层 `deserialize()` 处理：

```go
// unit.go:301-314
func (u *unit) deserialize(udb *unitDB) {
    if udb == nil { return }          // nil 直接跳过，保持空桶状态
    // ... 正常赋值
}
```

#### 2.4.2 启动加载阶段的错误传播

`New()` `stats.go:155-214` 中有三处容错：

| 错误点 | 代码位置 | 处理方式 | 是否影响启动 |
|---|---|---|---|
| `openDB()` 打开失败 | `stats.go:187` | 直接 return err | ✅ 启动失败 |
| `Begin(true)` 事务开启失败 | `stats.go:195` | 直接 return err | ✅ 启动失败 |
| `finishTxn()` 提交失败 | `stats.go:203-206` | 仅 Error 日志，继续 | ❌ 不影响启动 |
| `loadUnitFromDB()` 加载当前桶失败 | `stats.go:201` | udb=nil，deserialize 跳过 | ❌ 不影响启动 |

> ⚠️ **重要边界**：bbolt 数据库文件如果整体损坏（如头部 magic number 不对），`bbolt.Open()` 会返回错误，导致整个 stats 模块初始化失败，进程启动失败。这是一种 fail-fast 策略，避免在损坏的数据库上继续写入造成更大破坏。

#### 2.4.3 loadUnits 时的损坏桶补位

读取 API 路径上 `loadUnits()` `stats.go:572-625` 对每个桶做容错：

```go
for i := firstID; i != curID; i++ {
    u := s.loadUnitFromDB(tx, i)
    if u == nil {
        u = &unitDB{NResult: make([]uint64, resultLast)}  // 空桶补位
    }
    units = append(units, u)
}
```

**行为**：如果中间某个历史桶损坏了（GOB 解码失败），它会被一个全零的空桶替代，不影响后续桶的读取。Dashboard 上对应那个小时的数据会显示为 0，而不是整个图表崩溃。

#### 2.4.4 flushDB 事务回滚后的内存桶状态

这是最精妙也最容易被忽略的边界。`flushDB()` `stats.go:446-489` 的执行顺序：

```go
func (s *StatsCtx) flushDB(id, limit uint32, ptr *unit) (cont bool, sleepFor time.Duration) {
    isCommitable := true
    tx, err := db.Begin(true)        // ① 开启事务
    defer func() { finishTxn(tx, isCommitable) }()  // ⑤ 最后提交/回滚

    s.curr = newUnit(id)             // ② 先换桶！事务还没提交

    udb := ptr.serialize()           // ③ 旧桶序列化
    flushErr := s.flushUnitToDB(udb, tx, ptr.id)  // ④a 写旧桶到 DB
    delErr := tx.DeleteBucket(id - limit)          // ④b 删最旧桶

    // flushErr / delErr 严重 → isCommitable=false → 事务回滚
    return true, 0
}
```

**如果事务回滚了，内存桶状态如何？**

| 位置 | 状态 |
|---|---|
| `s.curr` | **已经是新桶（ID = id）**，新的 `Update()` 会写入这个新桶 |
| 旧桶数据 | `ptr` 是局部变量，函数返回后被 GC → **旧桶这一小时增量丢失** |
| 磁盘状态 | 回滚后旧桶未写入、最旧桶未删除，与 flush 前一致 |

**后果推演**：
- 下一秒 `periodicFlush` 再次调用 `flush()`
- `ptr.id == id`？不，因为 `s.curr.id = id`，而 `unitIDGen()` 还是返回 `id`（同一小时内）
- 所以 `ptr.id == id` 为 **true**，不再触发 flush
- 结果：新桶一直在内存中增长，直到**下一个整点**才会再次触发 flush
- 丢失的是**上一个整点到本次失败之间**的所有数据（最多接近 1 小时）

> 💡 **设计取舍**：先换桶再写库，好处是换桶瞬间完成，新的 DNS 查询不会被阻塞；代价是一旦写库失败，旧桶数据就丢了。这是一个"可用性优先于数据完整性"的选择——DNS 查询延迟比统计数据准确更重要。

---

## 三、读写并发互斥锁真实代码位置与锁顺序

StatsCtx 持有两把 `sync.RWMutex`，职责与加锁位置如下：

### 3.1 锁的定义与保护范围

| 锁 | 定义位置 | 保护字段 |
|---|---|---|
| `currMu *sync.RWMutex` | `stats.go:116` | `curr *unit` — 当前小时内存桶的读写 |
| `confMu *sync.RWMutex` | `stats.go:134` | `ignored`、`limit`、`enabled` — 配置相关字段的读写 |

### 3.2 所有加锁位置汇总

#### currMu（保护 curr 内存桶）

| 操作 | 代码位置 | 锁类型 | 说明 |
|---|---|---|---|
| Close 序列化当前桶 | `stats.go:262-263` | RLock | 只读 serialize，不修改 curr |
| Update 写入 Entry | `stats.go:293-294` | Lock | 独占写，调用 `curr.add()` |
| flush 切桶 | `stats.go:428-429` | Lock | 独占写，替换 `s.curr = newUnit(id)` |
| clear 重置桶 | `stats.go:563-564` | Lock | 独占写，替换 `s.curr = newUnit(...)` |
| loadUnits 读桶 | `stats.go:580-581` | RLock | 只读，获取 cur 指针并 serialize |

#### confMu（保护配置）

| 操作 | 代码位置 | 锁类型 | 说明 |
|---|---|---|---|
| Update 检查 enabled/limit | `stats.go:279-280` | Lock | 先读配置再决定是否写入，写锁防并发 |
| WriteDiskConfig 读配置 | `stats.go:307-308` | RLock | 只读 ignored/limit/enabled |
| TopClientsIP 读配置 | `stats.go:317-318` | RLock | 只读 enabled/limit |
| flush 切桶读 limit | `stats.go:423-424` | Lock | 与 currMu 联用时的写锁 |
| ShouldCount 读 ignored | `stats.go:629-630` | RLock | 只读 shouldCountClient + ignored |
| handleStats 读 limit | `http.go:68-69` | RLock | IIFE 包一层，取 limit 快照 |
| handleStatsInfo 读配置 | `http.go:154-155` | RLock | 只读 enabled/limit |
| handleGetStatsConfig 读配置 | `http.go:181-182` | RLock | 只读 ignored/interval/enabled |
| handleStatsConfig 写 limit | `http.go:219-220` | Lock | 调用 setLimit 修改配置 |
| handlePutStatsConfig 写配置 | `http.go:276-277` | Lock | 同时改 ignored/limit/enabled |

### 3.3 锁顺序（防止死锁的硬规则）

代码中用注释明确标注了锁顺序约定：

```go
// stats.go:260-261 (Close 中)
// NOTE: This mutex, when combined with the database transaction, is
// required to be locked first.
s.currMu.RLock()

// stats.go:426-427 (flush 中)
// NOTE: This mutex, when combined with the database transaction, is
// required to be locked first.
s.currMu.Lock()
```

**合法的加锁顺序**：
```
confMu → currMu → bbolt 事务
（flush() 和 Update() 都是这个顺序）
```

`flush()` `stats.go:423-429` 的加锁顺序是典型示例：
```go
s.confMu.Lock()        // ① 先锁配置
defer s.confMu.Unlock()
s.currMu.Lock()        // ② 再锁当前桶
defer s.currMu.Unlock()
// ③ 最后开 bbolt 事务
tx, err := db.Begin(true)  // flushDB 内部
```

`Update()` `stats.go:279-294` 也是同样顺序：
```go
s.confMu.Lock()        // ①
...
s.currMu.Lock()        // ②
...
s.curr.add(e)
```

> ⚠️ **绝不允许**反过来 `currMu → confMu`，也不允许持有 bbolt 事务后再去请求 currMu，否则会形成死锁（bbolt 事务内部也有锁）。

### 3.4 多实例/集群部署：桶 ID 全局唯一性与 bbolt 文件锁

#### 3.4.1 桶 ID 在多实例下的唯一性

桶 ID 计算只依赖 `time.Now().Unix()` 这一个全局一致输入：

```go
// unit.go:184-188
func newUnitID() (id uint32) {
    const secsInHour = int64(time.Hour / time.Second)
    return uint32(time.Now().Unix() / secsInHour)
}
```

**唯一性分析**：

| 场景 | 是否唯一 | 说明 |
|---|---|---|
| 单进程单实例 | ✅ 绝对唯一 | 自增序列，不可能重复 |
| 同主机多进程（端口不同） | ⚠️ 同小时 ID 相同 | 两进程同一小时桶 ID 完全相同，但 bbolt 文件锁**阻止共享同一 db 文件** |
| 多主机集群（NTP 同步） | ⚠️ 同小时 ID 相同 | 各节点桶 ID 相同，但各写各自本地 db，**不做跨节点合并** |
| 多主机集群（时钟漂移 1h 内） | ❌ 不唯一 | 不影响各节点独立统计准确性，只是各节点按自己的本地时间切桶 |

**结论：stats 模块完全不支持集群部署下的跨节点统计合并。** AdGuard Home 是单节点设计：

- **Config 无节点标识**：无 Node/hostname 字段，无法区分桶数据来自哪台机器
- **无分布式锁**：只有进程内 mutex + 本机文件锁，不支持跨节点协调
- **无跨节点聚合 API**：`/control/stats` 只返回本节点数据
- **桶 ID 仅为时间轴坐标**：各节点写自己的内存桶和 bbolt 文件，互不干扰。如需集群汇总统计，必须由上层工具拉取各节点 API 后在外部聚合 Dashboard

#### 3.4.2 bbolt 文件锁的处理路径

`openDB()` 使用 `bbolt.Open(filename, 0644, nil)`，传 `nil` 作为 `Options`，即使用 bbolt 全部默认值：

```go
// stats.go:389-418
func (s *StatsCtx) openDB() (err error) {
    s.logger.Debug("opening database")
    var db *bbolt.DB
    db, err = bbolt.Open(s.filename, aghos.DefaultPermFile, nil)
    if err != nil {
        if err.Error() == "invalid argument" {
            // ... 文件系统不支持 mmap/文件锁的提示
        }
        return err
    }
    s.db.Store(db)
    return nil
}
```

bbolt 默认文件锁行为（基于 bbolt v1.x 源码）：
- **`Options.Timeout = 0`**：获取文件锁**无限期阻塞**，不返回超时错误
- **排他锁**：使用 `flock(LOCK_EX)`（BSD/Linux）或 `LockFileEx`（Windows）对整个 db 文件加排他锁
- **`NoFreelistSync = false`**：每次写事务提交时同步 freelist 页，崩溃恢复安全但略慢
- **`NoSync = false`**：每次写事务调用 `fdatasync`/`fsync` 刷盘，确保数据持久化

**多进程冲突场景**：

| 场景 | bbolt 行为 | 进程表现 |
|---|---|---|
| 同主机起两个 AGH 指向同一 stats.db | `Open()` 中 `flock` 阻塞 | 进程 2 启动 Hang 死等，直到进程 1 `Close()` 释放锁 |
| 进程 A 写事务中，进程 A 内另一 goroutine 开读事务 | bbolt 内部读写锁（mmap 读写） | 正常并发，bbolt 内部保证单写多读 |
| 不同主机通过 NFS 共享 stats.db | **未定义行为**：NFS `flock` 实现各异，可能绕过锁 | 可能出现数据库损坏，绝对不推荐 |

#### 3.4.3 掉电后 bbolt 一致性

bbolt 的 Crash-Safety 来自三个机制：

1. **写时复制（CoW B+tree）**：写事务从不修改正在使用的页，先写入新页，元数据页切换指针
2. **`fdatasync` 刷盘**：`NoSync=false` 时提交前刷脏页到磁盘，确保下一个事务开始前新页物理持久
3. **元数据页双写**：有两份 meta page，刷盘时交替写 page 0 和 page 1，避免掉电刚好写坏 meta

**掉电后果矩阵**：

| 掉电时机 | 后果 |
|---|---|
| 写事务 `fdatasync` 之前 | 本次事务所有变更丢失，db 回到上一次提交状态（安全） |
| `fdatasync` 过程中断电 | 取决于 meta page：如果新 meta 已成功写入 → 新事务生效；如果 meta 未完整写入 → 从旧 meta 恢复，仍安全 |
| `Close()` 写入过程中断电 | 当前桶写一半 → GOB 反序列化时 `Decode` 失败 → 返回 nil → 空桶补位（仅丢失这一小时） |

综上：**单个桶损坏不影响其他桶，整体数据库不会结构性损坏**（除非 NFS/VM 环境下文件系统本身丢写）。

---

## 四、DST 跨日切换与 countHours 桶数组截断边界

### 4.1 DST 为什么不影响桶 ID 计算

桶 ID 使用的是 `time.Now().Unix()`（UTC 秒数）除以 3600，**完全不涉及时区换算**：

```go
// unit.go:184-188
func newUnitID() (id uint32) {
    const secsInHour = int64(time.Hour / time.Second)
    return uint32(time.Now().Unix() / secsInHour)
}
```

这意味着：
- **夏令时开始（春天拨快 1 小时）**：本地时间从 2:00 跳到 3:00，UTC 秒数单调递增，桶 ID 仍然连续，不会出现"跳桶"或"重复桶"
- **夏令时结束（秋天拨慢 1 小时）**：本地时间从 2:00 回到 1:00，UTC 秒数仍然单调递增，桶 ID 同样连续

**DST 只影响"按天聚合"的边界计算**，不影响桶本身的存在性。

### 4.2 countHours 的真实含义与截断公式

按天聚合时需要从 `units` 数组尾部精确裁剪出能被 24 整除对齐到"今天已过小时数"的数据量：

```go
// unit.go:540-549
func countHours(curHour uint32, days int) (n int) {
    hoursInCurDay := int(curHour % 24)
    if hoursInCurDay == 0 {
        hoursInCurDay = 24
    }
    hoursInRestDays := (days - 1) * 24
    return hoursInRestDays + hoursInCurDay
}
```

参数说明：
- `curHour`：当前桶 ID = 绝对小时数。`curHour % 24` = 当前桶**在一天中的小时槽位**（0=0点，1=1点，…，23=23点）
- `days`：目标天数

**返回值 = (days-1) 个完整日 + 今天已过的小时数**

### 4.3 DST 跨日时的截断边界推导

#### 场景 1：普通日子（无 DST）

假设 `curHour = 481539`（某个周三 14:00 UTC，对应 `481539 % 24 = 14`），`days = 3`：

```
hoursInCurDay = 14
hoursInRestDays = (3-1) * 24 = 48
n = 48 + 14 = 62 小时
```

对应桶数组截断：
```
units = [桶0, 桶1, ..., 桶(总-63), ← 被截断丢弃 → | 桶(总-62), ..., 桶(总-1)]
        │← (总小时数 - 62) 个丢弃 →│← 62 个 = 2 整天 + 14 小时 →│
```

聚合后得到 3 个日槽：`[day0(前前天), day1(昨天), day2(今天 0~14点)]`

#### 场景 2：DST 切换日（本地时区有 23 或 25 小时）

由于桶 ID 基于 UTC，"天"的概念也是**UTC 自然日**（固定 24 小时），不是本地日历日。所以：

- **DST 开始日（本地 23 小时）**：`countHours` 仍按 24 小时算一整天，本地时间的"丢失小时"不影响桶数组截断
- **DST 结束日（本地 25 小时）**：`countHours` 仍按 24 小时算一整天，本地时间的"重复小时"同样不影响

**DST 唯一的用户可感知差异**：
Dashboard 的"今日"数据条在 DST 切换日看起来会和本地时钟有 1 小时偏差，因为它统计的是 **UTC 0 点到当前 UTC 小时**，而不是本地 0 点到当前本地小时。代码中没有任何时区校正逻辑（`time.Now().Unix()` 是唯一时间源）。

### 4.4 fillCollectedStatsDaily 的完整截断与聚合过程

```go
// unit.go:518-537
func (s *StatsCtx) fillCollectedStatsDaily(
    data *StatsResp, units []*unitDB, curHour uint32, days int,
) {
    // ① 计算应该取尾部多少小时（对齐到今天已过小时数）
    hours := countHours(curHour, days)           // unit.go:526
    // ② 裁剪桶数组：只保留尾部 hours 个桶，丢弃头部多余的
    units = units[len(units)-hours:]             // unit.go:527

    // ③ 每 24 个连续桶合并为 1 个日槽
    for i, u := range units {
        day := i / 24                            // unit.go:530
        data.DNSQueries[day] += u.NTotal
        data.BlockedFiltering[day] += u.NResult[RFiltered]
        data.ReplacedSafebrowsing[day] += u.NResult[RSafeBrowsing]
        data.ReplacedParental[day] += u.NResult[RParental]
    }
}
```

**裁剪边界可视化（30 天 / curHour%24 = 14）：**

```
原始 units (720 桶 = 30×24):
┌──────────────┬──────────────┬──────────────┬───────┐
│  day0 (旧)   │  day1        │  ...         │ day29 │
│  24 桶       │  24 桶       │              │ 0~13  │ (14桶，今天已过14小时)
└──────────────┴──────────────┴──────────────┴───────┘
│← 丢弃 720-710 = 10 桶 ─→│← 保留 710 桶 = (30-1)*24+14 ─→│

聚合后 data.* (30 个日槽):
[day0_sum, day1_sum, ..., day28_sum (各24桶), day29_sum (14桶)]
```

测试 `stats_internal_test.go:114-171` `TestStatsCtx_FillCollectedStats_daily` 中使用 `curID = daysCount * 24`（即 `curHour%24 = 0`），验证了恰好整除时不丢弃任何桶的边界情况。

---

## 五、Top Hosts / Top Domains 计算逻辑

### 5.1 收集阶段：写入内存桶

每次 DNS 查询通过 `unit.add(e)` 累加计数：

```go
// unit.go:318-340
func (u *unit) add(e *Entry) {
    u.nResult[e.Result]++
    if e.Result == RNotFiltered {
        u.domains[e.Domain]++          // 正常查询 → domains map
    } else {
        u.blockedDomains[e.Domain]++   // 被拦截 → blockedDomains map
    }
    u.clients[e.Client]++
    pt := uint64(e.ProcessingTime.Microseconds())
    u.timeSum += pt
    u.nTotal++

    for _, s := range e.UpstreamStats {
        if s.IsCached || s.Error != nil { continue }  // 跳过缓存和失败
        addr := s.Address
        u.upstreamsResponses[addr]++
        u.upstreamsTimeSum[addr] += uint64(s.QueryDuration.Microseconds())
    }
}
```

**分类逻辑：**

| Result 枚举值 | 含义 | 计入哪个 map |
|---|---|---|
| `RNotFiltered` | 未过滤 | `domains` |
| `RFiltered` | 黑名单/无效/服务阻断 | `blockedDomains` |
| `RSafeBrowsing` | 安全浏览拦截 | `blockedDomains` |
| `RSafeSearch` | 安全搜索替换 | `blockedDomains` |
| `RParental` | 家长控制拦截 | `blockedDomains` |

### 5.2 序列化阶段：截断 Top N

桶落盘前 `serialize()` 会将 map 转为有序 slice 并**截断到前 100 名**：

```go
// unit.go:258-274
func (u *unit) serialize() (udb *unitDB) {
    var timeAvg uint32 = 0
    if u.nTotal != 0 {
        timeAvg = uint32(u.timeSum / u.nTotal)
    }
    return &unitDB{
        NTotal:             u.nTotal,
        NResult:            append([]uint64{}, u.nResult...),
        Domains:            convertMapToSlice(u.domains, maxDomains),       // 100
        BlockedDomains:     convertMapToSlice(u.blockedDomains, maxDomains), // 100
        Clients:            convertMapToSlice(u.clients, maxClients),        // 100
        UpstreamsResponses: convertMapToSlice(u.upstreamsResponses, maxUpstreams), // 100
        UpstreamsTimeSum:   convertMapToSlice(u.upstreamsTimeSum, maxUpstreams),   // 100
        TimeAvg:            timeAvg,
    }
}
```

`convertMapToSlice` 执行：
1. map → `[]countPair`
2. 按 `Count` 降序排序（`slices.SortFunc(s, countPair.compareCount)`）
3. `s[:min(maxVal, len(s))]` 截断

> ⚠️ **精度损失点**：每小时只保留 Top 100 域名/客户端。如果某域名在多个小时分别排名 101 名，跨天汇总时该域名数据会完全丢失。这是存储空间与精度的权衡。

### 5.3 读取阶段：跨桶聚合并最终 Top N

HTTP 请求到达时，`getData()` → `dataFromUnits()` 调用 `topsCollector()`：

```go
// unit.go:379-391
func topsCollector(units []*unitDB, max int, ignored *IgnoreEngine, pg pairsGetter) []map[string]uint64 {
    m := map[string]uint64{}
    for _, u := range units {               // 遍历所有桶
        for _, cp := range pg(u) {          // 取该桶的 Top slice
            if !ignored.Has(cp.Name) {      // 过滤忽略列表
                m[cp.Name] += cp.Count      // 跨桶累加
            }
        }
    }
    a2 := convertMapToSlice(m, max)         // 再次排序 + 截断
    return convertTopSlice(a2)              // 转成前端需要的格式
}
```

**调用链：**

```
handleStats()  [http.go:60]
  └─> getData(limit)  [unit.go:412]
        └─> dataFromUnits(units, curID)  [unit.go:439]
              ├─ TopQueried  = topsCollector(units, 100, ignored, u.Domains)
              ├─ TopBlocked  = topsCollector(units, 100, ignored, u.BlockedDomains)
              ├─ TopClients  = topsCollector(units, 100, nil, topClientPairs(s))
              └─ TopUpstreams = topUpstreamsPairs(units)
```

**具体 Top 指标计算：**

| 响应字段 | pairsGetter | 最大数量 | 过滤条件 |
|---|---|---|---|
| `top_queried_domains` | `u.Domains` | 100 | 忽略域名列表 |
| `top_blocked_domains` | `u.BlockedDomains` | 100 | 忽略域名列表 |
| `top_clients` | `topClientPairs` 包装的 `u.Clients` | 100 | `shouldCountClient` 过滤 |
| `top_upstreams_responses` | `topUpstreamsPairs()` 聚合 | 100 | 无 |
| `top_upstreams_avg_time` | `topUpstreamsPairs()` 计算平均 | 100 | 无 |

---

## 六、查询来源（Client 字段）统计逻辑

### 6.1 Entry.Client 的来源构造

查询来源在 `internal/dnsforward/stats.go:143-180` 的 `updateStats()` 中构造：

```go
func (s *Server) updateStats(dctx *dnsContext, clientIP string, processingTime time.Duration) {
    pctx := dctx.proxyCtx

    var upstreamStats []*proxy.UpstreamStatistics
    qs := pctx.QueryStatistics()
    if qs != nil {
        upstreamStats = append(upstreamStats, qs.Main()...)
        upstreamStats = append(upstreamStats, qs.Fallback()...)
    }

    e := &stats.Entry{
        UpstreamStats:  upstreamStats,
        Domain:         aghnet.NormalizeDomain(pctx.Req.Question[0].Name),
        Result:         stats.RNotFiltered,
        ProcessingTime: processingTime,
    }

    // 来源优先级: ClientID > IP
    if clientID := dctx.clientID; clientID != "" {
        e.Client = clientID      // 明确指定的 ClientID (DoH/DoT 路径参数)
    } else {
        e.Client = clientIP      // 客户端 IP 地址（已匿名化处理）
    }

    switch dctx.result.Reason {
    case filtering.FilteredSafeBrowsing:    e.Result = stats.RSafeBrowsing
    case filtering.FilteredParental:        e.Result = stats.RParental
    case filtering.FilteredSafeSearch:      e.Result = stats.RSafeSearch
    case filtering.FilteredBlockList,
         filtering.FilteredInvalid,
         filtering.FilteredBlockedService:  e.Result = stats.RFiltered
    }
    s.stats.Update(e)
}
```

**Client 字段赋值规则（优先级从高到低）：**

1. **ClientID**（`dctx.clientID`）：通过 DoH/DoT/DoQ 的 URL 路径参数传递的自定义标识
   - 例如 `https://dns.example.com/dns-query/client123` 中的 `client123`
   - 在 `Top clients` 面板中以该名称优先显示

2. **匿名化 IP**（`clientIP`）：
   - 原始 IP 来自 `pctx.Addr.Addr()`
   - 经过 `s.anonymizer` 处理（IPv4 可能截断 /24，IPv6 截断 /64）
   - 代码位置：`dnsforward/stats.go:32-34`

### 6.2 过滤：ShouldCount 判断

在计入统计之前，`processQueryLogsAndStats()` 会先调用 `shouldCountStat()`：

```
processQueryLogsAndStats()  [dnsforward/stats.go:19]
  └─> shouldCountStat(host, qt, cl, ids)  [dnsforward/stats.go:92-96]
        └─> s.stats.ShouldCount(host, qt, cl, ids)  [stats.go:628-637]
              ├─ 检查 shouldCountClient(ids)  // 客户端是否被忽略
              └─ 检查 !isIgnored(host)        // 域名是否被忽略
```

`ids` 的构造（`dnsforward/stats.go:38-43`）：
- 有 ClientID：`[ClientID, IP]` — 检查时 ClientID 优先
- 无 ClientID：`[IP]`

### 6.3 Client 数据的写入与聚合

写入 `unit.clients` map：

```go
// unit.go:326
u.clients[e.Client]++
```

跨桶聚合在 `topsCollector` 中通过 `topClientPairs` 包装器执行二次过滤：

```go
// unit.go:551-563
func topClientPairs(s *StatsCtx) pairsGetter {
    return func(u *unitDB) (clients []countPair) {
        for _, c := range u.Clients {
            if c.Name != "" && !s.shouldCountClient([]string{c.Name}) {
                continue  // 运行时动态排除客户端（配置变更后即时生效）
            }
            clients = append(clients, c)
        }
        return clients
    }
}
```

> 💡 **注意**：序列化存储时保留 Top 100 客户端，但**读取时仍会再过滤一次**。这意味着如果某客户端后来被加入忽略列表，它在历史桶中的数据虽然存在，但不会出现在最终 Top 结果中。

### 6.4 TopClientsIP（特殊 API）

除了 Dashboard 用的 `TopClients`（返回 map slice），还有 `TopClientsIP()` 用于 DHCP 等场景：

```go
// stats.go:316-348
func (s *StatsCtx) TopClientsIP(maxCount uint) (ips []netip.Addr) {
    s.confMu.RLock()
    defer s.confMu.RUnlock()

    limit := uint32(s.limit.Hours())
    if !s.enabled || limit == 0 { return nil }

    units, _ := s.loadUnits(limit)
    if units == nil { return nil }

    m := map[string]uint64{}
    for _, u := range units {
        for _, it := range u.Clients {
            m[it.Name] += it.Count       // 累加
        }
    }
    a := convertMapToSlice(m, int(maxCount))
    ips = []netip.Addr{}
    for _, it := range a {
        ip, err := netip.ParseAddr(it.Name)
        if err == nil {
            ips = append(ips, ip)        // 只保留可解析为 IP 的条目
        }
    }
    return ips
}
```

该方法**只返回 IP 格式的客户端**，自定义 ClientID 会被丢弃。

---

## 七、时段分布（时间序列）聚合

### 7.1 时间单位自动切换

`fillCollectedStats()` 根据请求的小时数决定时间粒度：

```go
// unit.go:483-510
func (s *StatsCtx) fillCollectedStats(data *StatsResp, units []*unitDB, curID uint32) {
    size := len(units)
    data.TimeUnits = timeUnitsHours

    daysCount := size / 24
    if daysCount > 7 {           // 超过 7 天 → 切天粒度
        size = daysCount
        data.TimeUnits = timeUnitsDays
    }

    data.DNSQueries = make([]uint64, size)
    data.BlockedFiltering = make([]uint64, size)
    data.ReplacedSafebrowsing = make([]uint64, size)
    data.ReplacedParental = make([]uint64, size)

    if data.TimeUnits == timeUnitsDays {
        s.fillCollectedStatsDaily(data, units, curID, size)
        return
    }

    for i, u := range units {
        data.DNSQueries[i] += u.NTotal
        data.BlockedFiltering[i] += u.NResult[RFiltered]
        data.ReplacedSafebrowsing[i] += u.NResult[RSafeBrowsing]
        data.ReplacedParental[i] += u.NResult[RParental]
    }
}
```

**切换规则：**

| 回溯范围 | 时间单位 | 数据点数 |
|---|---|---|
| ≤ 168 小时（7 天） | `hours` | N 小时 |
| > 168 小时（如 30 天/90 天） | `days` | N 天 |

### 7.2 按天聚合算法

```go
// unit.go:518-537
func (s *StatsCtx) fillCollectedStatsDaily(
    data *StatsResp, units []*unitDB, curHour uint32, days int,
) {
    hours := countHours(curHour, days)       // 计算需要取尾部多少小时
    units = units[len(units)-hours:]         // 裁剪，对齐到日边界

    for i, u := range units {
        day := i / 24                        // 每 24 个桶合并为 1 天
        data.DNSQueries[day] += u.NTotal
        data.BlockedFiltering[day] += u.NResult[RFiltered]
        data.ReplacedSafebrowsing[day] += u.NResult[RSafeBrowsing]
        data.ReplacedParental[day] += u.NResult[RParental]
    }
}
```

边界对齐逻辑 `countHours()`（`unit.go:540-549`）：
- 当前小时在一天内的位置 = `curHour % 24`
- 若恰好是 0 点 → 取 24 小时
- 否则取余数作为"今天已过小时数"
- 总小时数 = `(days-1)*24 + 今天已过小时数`

---

## 八、HTTP API 暴露口与调用链

### 8.1 stats 模块注册的所有端点

`initWeb()` `http.go:300-310` 在 `Start()` 时调用，通过 `aghhttp.Registrar` 接口注册到上层 HTTP 路由：

```go
// http.go:300-310
func (s *StatsCtx) initWeb() {
    s.httpReg.Register(http.MethodGet, "/control/stats", s.handleStats)
    s.httpReg.Register(http.MethodPost, "/control/stats_reset", s.handleStatsReset)
    s.httpReg.Register(http.MethodGet, "/control/stats/config", s.handleGetStatsConfig)
    s.httpReg.Register(http.MethodPut, "/control/stats/config/update", s.handlePutStatsConfig)

    // Deprecated handlers.
    s.httpReg.Register(http.MethodGet, "/control/stats_info", s.handleStatsInfo)
    s.httpReg.Register(http.MethodPost, "/control/stats_config", s.handleStatsConfig)
}
```

| 方法 | 路径 | 处理器 | 说明 |
|---|---|---|---|
| GET | `/control/stats` | `handleStats` | 获取统计数据（Dashboard 主数据） |
| POST | `/control/stats_reset` | `handleStatsReset` | 重置（清空所有统计数据） |
| GET | `/control/stats/config` | `handleGetStatsConfig` | 获取统计配置（新 API） |
| PUT | `/control/stats/config/update` | `handlePutStatsConfig` | 更新统计配置（新 API） |
| GET | `/control/stats_info` | `handleStatsInfo` | ⚠️ 废弃，获取统计间隔 |
| POST | `/control/stats_config` | `handleStatsConfig` | ⚠️ 废弃，设置统计间隔 |

### 8.2 handleStats 完整调用链路

Dashboard 拉取数据的主路径：

```
GET /control/stats?recent=720
  │
  ▼
handleStats(w, r)  [http.go:60-97]
  ├─ 解析 recent 参数 → parseRecent()  [http.go:101-122]
  │     └─ 校验：必须是 1 小时的整数倍，且在 [1h, limit] 范围内
  ├─ confMu.RLock 读 s.limit 快照  [http.go:67-72]
  └─ s.getData(uint32(limit.Hours()))  [unit.go:412-436]
        ├─ s.loadUnits(limit)  [stats.go:572-625]
        │     ├─ currMu.RLock
        │     ├─ db.Begin(true)  // 用可写事务确保读到最新提交
        │     ├─ 循环加载 limit 个历史桶（损坏则补空桶）
        │     ├─ finishTxn(tx, false)  // 只读，回滚
        │     └─ 追加 curr.serialize() 的当前桶
        └─ s.dataFromUnits(units, curID)  [unit.go:439-480]
              ├─ topsCollector() × 3 (Queried/Blocked/Clients)
              ├─ topUpstreamsPairs()
              ├─ fillCollectedStats()  // 时段序列
              └─ 总计计数器累加
  │
  ▼
JSON 响应 (StatsResp)
```

### 8.3 配置更新调用链

```
PUT /control/stats/config/update
  │
  ▼
handlePutStatsConfig(w, r)  [http.go:227-282]
  ├─ JSON 解码 body → getConfigResp
  ├─ 构造新 IgnoreEngine
  ├─ 校验 ivl 合法性（1h ~ 1y）
  ├─ confMu.Lock
  ├─ 同步更新 s.ignored / s.limit / s.enabled
  └─ configModifier.Apply(ctx)  // 异步持久化到配置文件
```

### 8.4 关于 Prometheus / metrics

**stats 模块本身不暴露 Prometheus metrics 端点**。搜索整个代码库未发现 stats 相关的 prometheus 指标注册。AdGuard Home 的 /metrics 如果存在，也是在更上层（home 模块或全局）实现，不通过 stats 包提供。

stats 包的核心职责是：
1. 收集 DNS 查询统计数据（内存 + bbolt 持久化）
2. 通过 `/control/stats` HTTP 接口返回 Dashboard 所需的 JSON 格式数据

### 8.5 stats 端点的中间件挂载链与限流

stats 模块的 6 个 HTTP 端点**不单独配置限流或中间件**，所有中间件都是通过上层 home 模块的 `aghhttp.DefaultRegistrar` 在注册时统一注入的。

#### 8.5.1 Registrar 注入链路

整个挂载流程从 home 启动开始：

```
home.go:772-774  setupContext()
  ├─ mw := &webMw{}
  ├─ mux := http.NewServeMux()
  └─ httpReg := aghhttp.NewDefaultRegistrar(mux, mw.wrap)
            │
            ▼
  dns.go:57-73  initStats()
    ├─ statsConf.HTTPReg = httpReg  // 注入 stats.Config
    └─ stats.New(statsConf)
            │
            ▼
  stats.go:240  Start()
    └─ initWeb()  [http.go:300-310]
          └─ s.httpReg.Register(GET, "/control/stats", s.handleStats)
                    │
                    ▼
      aghhttp/registrar.go:46-48  DefaultRegistrar.Register()
        ├─ wrapped := r.wrapFn(method, h)   // 调用 mw.wrap 注入中间件
        └─ r.mux.Handle(path, wrapped)
```

#### 8.5.2 webMw.wrap 注入的中间件

`control.go:232-247` — `webMw.wrap()` 在每个 handler 注册时注入三层中间件：

```
mw.wrap(method, handler)
  └─ mw.ensureMw(method, handler)
        └─ web.postInstallHandler(
              gziphandler.GzipHandler(
                  web.ensure(method, handler)
              )
           )
```

| 中间件 | 代码位置 | 作用 |
|---|---|---|
| `ensure()` | `control.go:251-280` | 校验 HTTP method 匹配；校验 `X-Forwarded-For` 信任链 |
| `gziphandler.GzipHandler` | `control.go:236` | 启用 gzip 响应压缩 |
| `postInstallHandler` | `control.go:380-394` | 首次安装后禁止访问安装页（检查 `!a.isFirstRun()`） |

#### 8.5.3 HTTP Server 外层再加的三层中间件

在 `web.go:266-274` 创建 HTTP Server 时，在 mux 外面再包三层全局中间件：

```
http.Server.Handler =
  web.auth.middleware().Wrap(          // ① 最外层：Session Cookie 认证
      logMw.Wrap(                      // ② 访问日志
          withMiddlewares(mux,         // ③ mux 基础 + 中间件数组
              limitRequestBody         //    请求体大小限制
          )
      )
  )
```

**从外到内的完整调用链（stats 端点请求）：**

```
外部请求 → http.Server
  │
  ├─ [1] auth.middleware()  [auth.go:159-190]
  │     ├─ 跳过白名单路径（/login, /apple/*, /robots.txt, DoH/DoT 端口路径）
  │     ├─ 读取 Session Cookie / Authorization Bearer
  │     ├─ session.Valid() 校验（查 sessions bbolt DB）
  │     └─ 认证失败 → 403 Forbidden，或跳 /install.html
  │
  ├─ [2] logMw.Wrap()  [web.go:271]
  │     └─ Debug 日志记录请求 method/path
  │
  ├─ [3] limitRequestBody()  [middlewares.go:58-74]
  │     ├─ 默认 64KB body（stats 端点全部是 GET，所以其实不生效）
  │     └─ 仅 /control/access/set、/control/filtering/set_rules 放宽到 4MB
  │
  ├─ [4] http.ServeMux → 路由匹配到 "/control/stats"
  │
  ├─ [5] postInstallHandler()  [control.go:380-394]
  │     └─ 首次运行拦截（AGH 配置完成前才触发）
  │
  ├─ [6] gziphandler.GzipHandler()
  │     └─ 根据 Accept-Encoding 启用 gzip 压缩
  │
  └─ [7] web.ensure() + s.handleStats()  [stats/http.go:60]
        ├─ method 校验（GET vs 注册时的 method）
        ├─ X-Forwarded-For 校验
        └─ handleStats() 执行真正逻辑
```

#### 8.5.4 登录限流 vs stats 端点限流

**注意：loginRateLimiter 只作用于登录接口，不限制 stats 端点。**

```go
// authratelimiter.go:12-16
type loginRateLimiter interface {
    check(usrID string) (left time.Duration)
    inc(usrID string)
}
```

- 仅在 `/control/login` 处理中调用 `check()` + `inc()`，防止暴力破解
- stats 端点（GET/POST）**没有 QPS 限流或并发控制**，完全由 Session 认证作为门禁
- **唯一的"限流"**是认证本身：未登录或会话过期直接 403，无法访问任何 stats 接口

#### 8.5.5 HTTPS/TLS/HTTP3 同样的中间件链

`web.go:365-369`（HTTPS）和 `web.go:433`（HTTP/3）创建的 Server 复用完全相同的中间件链，只是多一层 TLS 握手：

```go
// web.go:369
Handler: web.auth.middleware().Wrap(
    logMw.Wrap(
        withMiddlewares(web.conf.mux, limitRequestBody)
    )
)
```

---

## 九、完整数据流总结

```
         DNS 请求到达
              │
              ▼
    ┌─────────────────────┐
    │  dnsforward 处理    │
    │  - 过滤/拦截判定    │
    │  - 提取 ClientID/IP │
    │  - 匿名化 IP        │
    └─────────┬───────────┘
              │ ShouldCount?
              ▼
    ┌─────────────────────┐
    │  stats.Update(e)    │  stats.go:278-303
    │  (confMu→currMu)    │
    │  (只写内存 curr)    │
    └─────────┬───────────┘
              │
              ▼
    ┌─────────────────────────────────────────┐
    │  curr (*unit) 内存桶                    │
    │  domains / blockedDomains / clients /   │
    │  upstreams / nResult / nTotal / timeSum │
    └─────────┬───────────────────────────────┘
              │ 每小时触发 periodicFlush (每秒轮询)
              │ confMu.Lock → currMu.Lock → bbolt Tx
              ▼
    ┌──────────────────────────────┐
    │  flushDB()                   │  stats.go:446-489
    │  ① curr = newUnit(newID)    │
    │  ② 旧桶 serialize → unitDB   │
    │  ③ flushUnitToDB → bbolt     │
    │  ④ 删除 id-limit 旧桶        │
    └─────────┬────────────────────┘
              │ bbolt 单事务原子提交
              ▼
    ┌──────────────────────────────────────────┐
    │  bbolt 数据库 (每小时 1 个 Bucket)       │
    │  Bucket[ID] → GOB(unitDB{                │
    │    Domains[100], BlockedDomains[100],    │
    │    Clients[100], Upstreams[100], ...     │
    │  })                                      │
    └─────────┬────────────────────────────────┘
              │ HTTP GET /control/stats?recent=N
              │ currMu.RLock → bbolt Tx (读)
              ▼
    ┌─────────────────────────────────────┐
    │  getData() / loadUnits()            │
    │  从 DB 加载 limit 个桶 + curr 序列化│
    └─────────┬───────────────────────────┘
              ▼
    ┌─────────────────────────────────────┐
    │  dataFromUnits()                    │
    │  ├─ topsCollector() 跨桶累加Top N   │
    │  ├─ fillCollectedStats() 时段序列   │
    │  │    ├─ ≤7天: 小时粒度直出         │
    │  │    └─ >7天: countHours 截断 +    │
    │  │           按 24 桶/日 聚合       │
    │  └─ 总计计数器累加                  │
    └─────────┬───────────────────────────┘
              ▼
         StatsResp JSON
    (Dashboard 图表渲染)
```

---

## 十、关键设计要点

1. **写入零 I/O**：实时查询只累加内存 map，不会阻塞 DNS 响应
2. **先换桶再写库**：`flushDB()` 先替换 `s.curr` 指针再写 bbolt，换桶瞬间完成；代价是写库失败时旧桶数据丢失（可用性 > 完整性）
3. **批量截断**：每小时仅保留 Top 100 各类别，控制存储膨胀
4. **滑动窗口淘汰**：切桶时原子替换 + 删除过期桶，数据量恒定
5. **双次过滤**：写入时检查忽略列表，读取时再检查，支持配置热更新
6. **双锁顺序约定**：`confMu → currMu → bbolt 事务`，代码注释明确标注，防止死锁
7. **损坏即丢弃**：GOB 反序列化失败只打 Error 日志并返回 nil，上层用空桶补位，单个桶损坏不影响整体读取
8. **空桶补位**：`loadUnits()` 中损坏/缺失的历史桶用全零 `unitDB` 填补，Dashboard 不会因为某个桶损坏而崩溃
9. **Fail-Fast 启动**：bbolt 文件整体损坏（头部 magic 不对）时 `Open()` 直接报错，stats 模块初始化失败，进程启动失败
10. **UTC 桶 ID**：使用绝对小时数（Unix÷3600）作为桶 ID，天然免疫时区和 DST 对桶连续性的干扰
11. **按天 UTC 对齐**：`countHours` 基于桶 ID 的 `mod 24` 裁剪，"今日"是 UTC 自然日而非本地日历日
12. **掉电窗口最多 1 小时**：只有整点 flush 和 Close() 会落盘，期间异常退出会丢失当前小时内存桶
13. **粒度自适应**：时段图表自动在"小时/天"间切换，平衡数据精度与展示密度
14. **Registrar 解耦**：HTTP 路由通过 `aghhttp.Registrar` 接口注入，stats 模块不直接依赖 web server，便于单元测试
15. **无 Prometheus 指标**：stats 模块只提供 JSON Dashboard API，不暴露 prometheus metrics，监控指标由上层模块负责
16. **单节点设计**：不支持跨节点统计合并，Config 无节点标识、无分布式锁、无聚合 API，集群统计必须在上层拉取各节点 API 后外部合并
17. **bbolt 排他文件锁**：使用默认 Options（Timeout=0 无限期阻塞），多进程指向同一 db 文件时第二个进程启动 Hang 死等，避免同时写导致损坏
18. **CoW 崩溃安全**：bbolt 写时复制 + meta 双写 + `fdatasync` 刷盘，掉电后要么整事务生效要么整体回退，不会出现半写入的结构性损坏
19. **双层中间件注入**：Registrar 时注入 3 层（ensure+gzip+postInstall），Server 外层再包 3 层（auth+log+bodyLimit），共 7 层调用链，stats 自身不配置限流
20. **Session 认证即门禁**：stats 端点无独立 QPS 限流，仅靠 `auth.middleware()` Session 校验控制访问，未登录直接 403

---

## 十一、测试覆盖与限流阈值常量溯源

### 11.1 stats 模块测试文件清单

| 文件 | 包 | 测试类型 | 覆盖范围 |
|---|---|---|---|
| `stats_internal_test.go` | `stats`（白盒） | 单元 + 竞态 | 并发读写竞态、按天聚合、月度 loadUnits |
| `stats_test.go` | `stats_test`（黑盒） | 集成 | 数据写入/读取/Top 统计、大量数据、ShouldCount 过滤 |
| `http_internal_test.go` | `stats`（白盒） | 单元 | handleStats 参数校验、handlePutStatsConfig 配置更新 |
| `unit_internal_test.go` | `stats`（白盒） | 单元 | unit 反序列化、TopUpstreams 排序计算 |

### 11.2 桶 ID 相关测试覆盖

#### 11.2.1 固定 ID 测试（`constUnitID`）

`stats_test.go:29` 使用 `constUnitID` 将桶 ID 固定为 0：

```go
func constUnitID() (id uint32) { return 0 }
```

- **TestStats** `stats_test.go:52-174`：用 `constUnitID` 测试单桶内的数据写入 → `handleStats` 读取 → 验证 TopQueried / TopBlocked / TopClients / TopUpstreams / DNSQueries 等全部字段
- **TestLargeNumbers** `stats_test.go:176-225`：用 `atomic.Uint32` 模拟跨小时 ID 递增，12 小时 × 1000 客户端/小时 = 12000 条 Entry，验证 `NumDNSQueries` 总计

#### 11.2.2 并发竞态测试（`TestStats_races`）

`stats_internal_test.go:47-112` 是**唯一的并发安全测试**：

```go
func TestStats_races(t *testing.T) {
    var r uint32
    idGen := func() (id uint32) { return atomic.LoadUint32(&r) }
    s := newTestStatsCtx(t, Config{UnitID: idGen, Enabled: true})
    s.Start()

    // 3 轮，每轮 10 个 writer + 5 个 reader 同时操作
    for round := range 3 {
        atomic.StoreUint32(&r, uint32(round))  // 模拟 ID 切换
        // 10 个 goroutine 调用 s.Update(e)
        // 5 个 goroutine 调用 s.getData(24)
        startWG.Wait()
        close(waitCh)  // 同时唤醒所有 goroutine
        finWG.Wait()
    }
}
```

**覆盖的路径**：`Update()` + `getData()` 并发访问 `curr`、`confMu`、`currMu`
**未覆盖的路径**：`flushDB()` 切桶时的并发冲突、`Close()` 与 `Update()` 的并发

#### 11.2.3 按天聚合测试（`TestStatsCtx_FillCollectedStats_daily`）

`stats_internal_test.go:114-171` 手工构造 10 天 × 24 小时 = 240 个 `unitDB`，使用 `curID = daysCount * 24`（即 `curHour % 24 == 0`），验证：
- `TimeUnits == "days"`
- `BlockedFiltering` / `ReplacedSafebrowsing` / `ReplacedParental` 按天正确累加
- `DNSQueries` 总计正确

**边界情况**：`curHour % 24 == 0` 时 `hoursInCurDay = 24`，不丢弃任何桶，这是最简单的整除边界。

**未覆盖**：`curHour % 24 != 0` 时的非对齐截断（实际运行中最常见的情况）。

### 11.3 HTTP 端点测试覆盖

#### 11.3.1 handleStats 参数校验（`TestStatsCtx_handleStats`）

`http_internal_test.go:164-241` 覆盖 5 种 recent 参数场景：

| 用例 | recent 值 | 期望 HTTP 状态码 | 说明 |
|---|---|---|---|
| short_interval | 4 分钟 | 400 | 小于 1 小时 |
| long_interval | 72 小时 | 400 | 超过 limit（24h） |
| interval_is_not_multiple_of_hour | 1h+1ms | 400 | 非小时整数倍 |
| no_interval | 未传 | 200 | 使用默认 limit |
| valid_interval | 1h | 200 | 只返回最近 1 小时 |

#### 11.3.2 handlePutStatsConfig 配置更新（`TestHandleStatsConfig`）

`http_internal_test.go:26-132` 覆盖：

| 用例 | 期望 | 说明 |
|---|---|---|
| set_ivl_1_minIvl | 200 | 最小合法间隔（1h） |
| small_interval | 422 | 小于 1h |
| big_interval | 422 | 大于 365 天 |
| set_ignored_ivl_1_maxIvl | 200 | 最大合法间隔 + 忽略列表 |
| enabled_is_null | 422 | enabled 不可为 null |

### 11.4 测试覆盖盲区

| 未覆盖路径 | 位置 | 影响 |
|---|---|---|
| `flushDB()` 事务回滚后内存桶状态 | `stats.go:446-489` | 回滚后旧桶数据丢失无测试验证 |
| `loadUnitFromDB()` GOB 解码失败 | `unit.go:289-293` | 反序列化失败返回 nil 仅靠代码审查，无测试模拟 |
| bbolt 文件锁冲突（双进程同 db） | `stats.go:394` | 无法在单元测试中模拟多进程 flock |
| `countHours()` 非整除边界（`curHour%24 != 0`） | `unit.go:540-549` | 最常见的运行时场景无测试 |
| `periodicFlush` 长时间运行稳定性 | `stats.go:496-502` | 整点切桶 + 并发 Update 无长时间运行测试 |
| HTTP 中间件 7 层完整调用链 | home 模块 | stats 端点测试绕过中间件，直接调 handler |
| `authRateLimiter` 对 stats 端点的效果 | home 模块 | 限流器只作用于 /login，stats 无 QPS 限制无相关测试 |

### 11.5 默认限流阈值常量溯源

所有影响 stats 端点访问控制的阈值常量都定义在 `internal/home/` 下，不在 stats 包内：

#### 11.5.1 认证限流阈值

| 常量 | 定义位置 | 默认值 | 说明 |
|---|---|---|---|
| `config.AuthAttempts` | `config.go:458` | `5` | 允许的最大登录失败次数 |
| `config.AuthBlockMin` | `config.go:459` | `15` | 登录失败后封禁分钟数 |
| `failedAuthTTL` | `authratelimiter.go:10` | `1 * time.Minute` | 失败记录在内存缓存中的 TTL |

**完整配置传递链**：

```
config.go:458-459  默认值定义
  config.AuthAttempts = 5
  config.AuthBlockMin = 15
        │
        ▼
home.go:1075-1081  初始化时读取
  if config.AuthAttempts > 0 && config.AuthBlockMin > 0 {
      blockDur := time.Duration(config.AuthBlockMin) * time.Minute
      rateLimiter = newAuthRateLimiter(blockDur, config.AuthAttempts)
  } else {
      rateLimiter = emptyRateLimiter{}   // 两者任一为 0 则禁用限流
  }
        │
        ▼
auth.go:1084-1089  注入 authConfig
  authConfig.rateLimiter = rateLimiter
        │
        ▼
auth.go:159-190  认证中间件生效
  仅在 /login 处理中调用 rateLimiter.check() + rateLimiter.inc()
```

**注意**：`AuthAttempts` 和 `AuthBlockMin` 通过 YAML 配置文件可覆盖（字段标签 `yaml:"auth_attempts"` / `yaml:"block_auth_min"`），用户可以改为 0 来禁用限流。

#### 11.5.2 请求体大小限制

| 常量 | 定义位置 | 默认值 | 说明 |
|---|---|---|---|
| `defaultReqBodySzLim` | `middlewares.go:29` | `64 * datasize.KB` (64KB) | 默认最大请求体 |
| `largerReqBodySzLim` | `middlewares.go:33` | `4 * datasize.MB` (4MB) | 放宽路径的最大请求体 |

**stats 端点影响**：stats 的 GET 端点不携带请求体，所以 `defaultReqBodySzLim` 对 stats 无实际影响；只有 `POST /control/stats_reset` 和 `PUT /control/stats/config/update` 可能受 64KB 限制，但这些请求体极小，不会触发。

**放宽路径** `middlewares.go:48-53`：只有 `/control/access/set` 和 `/control/filtering/set_rules` 使用 `largerReqBodySzLim`，stats 端点不在其中。

#### 11.5.3 Session 生命周期

| 常量/配置 | 定义位置 | 默认值 | 说明 |
|---|---|---|---|
| `sessionsDBName` | `auth.go:21` | `"sessions.db"` | Session 存储 bbolt 文件名 |
| `config.HTTPConfig.SessionTTL` | `config.go:196` | YAML 可配 | Session 过期时间，活跃会话每天自动续期 |
| `glTokenTimeout` | `authglinet.go:27` | `3600 * time.Second` (1h) | GL.iNet 设备认证 token TTL |

**stats 端点影响**：Session 过期 → `auth.middleware()` 校验失败 → 403 Forbidden。stats 端点的"限流"本质上就是 Session TTL 控制的访问窗口。

#### 11.5.4 阈值常量与 stats 端点的关联图

```
stats HTTP 端点访问控制全链路：

  浏览器 → /control/stats
    │
    ├─ [1] auth.middleware()  ← SessionTTL 控制 Session 有效期
    │     ├─ Session Cookie 有效？
    │     │   ├─ 是 → 放行
    │     │   └─ 否 → 403（需重新登录）
    │     │
    │     └─ /login 请求？
    │         └─ authRateLimiter.check()  ← AuthAttempts=5 + AuthBlockMin=15min
    │             ├─ 未封禁 → 校验密码
    │             │   ├─ 成功 → 移除 rateLimiter 记录
    │             │   └─ 失败 → rateLimiter.inc() → 达到 5 次则封禁 15 分钟
    │             └─ 已封禁 → 返回剩余封禁时间
    │
    ├─ [2] limitRequestBody  ← defaultReqBodySzLim=64KB（stats GET 请求不受影响）
    │
    └─ [3] handleStats()    ← confMu.RLock + currMu.RLock 保护
```

**结论：stats 端点没有独立的 QPS 限流，也没有请求频率控制。** 整个访问控制由 Session 认证这一个门卫完成，限流阈值（5 次失败 / 15 分钟封禁）只作用于登录接口，不影响已认证用户的 stats API 调用频率。

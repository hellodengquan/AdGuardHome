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

- ID = UNIX 时间戳 ÷ 3600（自 1970-01-01 以来的绝对小时数）
- 在 bbolt 数据库中，每个桶对应一个 Bucket，键名为 8 字节大端编码的 ID

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

## 二、Top Hosts / Top Domains 计算逻辑

### 2.1 收集阶段：写入内存桶

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
    // ... 累加 upstream、timeSum、nTotal
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

### 2.2 序列化阶段：截断 Top N

桶落盘前 `serialize()` 会将 map 转为有序 slice 并**截断到前 100 名**：

```go
// unit.go:258-274
func (u *unit) serialize() (udb *unitDB) {
    return &unitDB{
        Domains:        convertMapToSlice(u.domains, maxDomains),       // 100
        BlockedDomains: convertMapToSlice(u.blockedDomains, maxDomains), // 100
        Clients:        convertMapToSlice(u.clients, maxClients),        // 100
        // ...
    }
}
```

`convertMapToSlice` 执行：
1. map → `[]countPair`
2. 按 `Count` 降序排序
3. `s[:min(maxVal, len(s))]` 截断

> ⚠️ **精度损失点**：每小时只保留 Top 100 域名/客户端。如果某域名在多个小时分别排名 101 名，跨天汇总时该域名数据会完全丢失。这是存储空间与精度的权衡。

### 2.3 读取阶段：跨桶聚合并最终 Top N

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
              └─ ...
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

## 三、查询来源（Client 字段）统计逻辑

### 3.1 Entry.Client 的来源构造

查询来源在 `internal/dnsforward/stats.go:143-180` 的 `updateStats()` 中构造：

```go
func (s *Server) updateStats(dctx *dnsContext, clientIP string, processingTime time.Duration) {
    e := &stats.Entry{
        Domain:         NormalizeDomain(...),
        Result:         RNotFiltered,
        ProcessingTime: processingTime,
        UpstreamStats:  qs.Main() + qs.Fallback(),
    }

    // 来源优先级: ClientID > IP
    if clientID := dctx.clientID; clientID != "" {
        e.Client = clientID      // 明确指定的 ClientID (DoH/DoT 路径参数)
    } else {
        e.Client = clientIP      // 客户端 IP 地址（已匿名化处理）
    }
    // ... 根据 dctx.result.Reason 设置 Result
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

### 3.2 过滤：ShouldCount 判断

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

### 3.3 Client 数据的写入与聚合

写入 `unit.clients` map：

```go
// unit.go:326
u.clients[e.Client]++
```

跨桶聚合在 `topsCollector` 中通过 `topClientPairs` 包装器执行二次过滤：

```go
// unit.go:551-563
func topClientPairs(s *StatsCtx) pairsGetter {
    return func(u *unitDB) []countPair {
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

### 3.4 TopClientsIP（特殊 API）

除了 Dashboard 用的 `TopClients`（返回 map slice），还有 `TopClientsIP()` 用于 DHCP 等场景：

```go
// stats.go:316-348
func (s *StatsCtx) TopClientsIP(maxCount uint) []netip.Addr {
    units, _ := s.loadUnits(limit)
    m := map[string]uint64{}
    for _, u := range units {
        for _, it := range u.Clients {
            m[it.Name] += it.Count       // 累加
        }
    }
    a := convertMapToSlice(m, int(maxCount))
    // 只保留能被 netip.ParseAddr 解析的（即纯 IP，过滤 ClientID）
    for _, it := range a {
        ip, err := netip.ParseAddr(it.Name)
        if err == nil {
            ips = append(ips, ip)
        }
    }
    return ips
}
```

该方法**只返回 IP 格式的客户端**，自定义 ClientID 会被丢弃。

---

## 四、时段分布（时间序列）聚合

### 4.1 时间单位自动切换

`fillCollectedStats()` 根据请求的小时数决定时间粒度：

```go
// unit.go:483-510
func (s *StatsCtx) fillCollectedStats(data *StatsResp, units []*unitDB, curID uint32) {
    size := len(units)
    data.TimeUnits = "hours"

    daysCount := size / 24
    if daysCount > 7 {           // 超过 7 天 → 切天粒度
        size = daysCount
        data.TimeUnits = "days"
    }
    // ...
}
```

**切换规则：**

| 回溯范围 | 时间单位 | 数据点数 |
|---|---|---|
| ≤ 168 小时（7 天） | `hours` | N 小时 |
| > 168 小时（如 30 天/90 天） | `days` | N 天 |

### 4.2 按天聚合算法

```go
// unit.go:518-537
func (s *StatsCtx) fillCollectedStatsDaily(data, units, curHour, days) {
    // 对齐到"当前天已过小时数"，丢弃多余头部
    hours := countHours(curHour, days)       // 计算需要取尾部多少小时
    units = units[len(units)-hours:]         // 裁剪，对齐到日边界

    for i, u := range units {
        day := i / 24                        // 每 24 个桶合并为 1 天
        data.DNSQueries[day] += u.NTotal
        data.BlockedFiltering[day] += u.NResult[RFiltered]
        // ...
    }
}
```

边界对齐逻辑 `countHours()`（`unit.go:540-549`）：
- 当前小时在一天内的位置 = `curHour % 24`
- 若恰好是 0 点 → 取 24 小时
- 否则取余数作为"今天已过小时数"
- 总小时数 = `(days-1)*24 + 今天已过小时数`

---

## 五、完整数据流总结

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
    │  (只写内存 curr)    │
    └─────────┬───────────┘
              │
              ▼
    ┌─────────────────────────────────────────┐
    │  curr (*unit) 内存桶                    │
    │  domains / blockedDomains / clients /   │
    │  upstreams / nResult / nTotal / timeSum │
    └─────────┬───────────────────────────────┘
              │ 每小时触发 periodicFlush
              ▼
    ┌──────────────────────────────┐
    │  flushDB()                   │  stats.go:446-489
    │  ① curr = newUnit(newID)    │
    │  ② 旧桶 serialize → unitDB   │
    │  ③ flushUnitToDB → bbolt     │
    │  ④ 删除 id-limit 旧桶        │
    └─────────┬────────────────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │  bbolt 数据库 (每小时 1 个 Bucket)       │
    │  Bucket[ID] → GOB(unitDB{                │
    │    Domains[100], BlockedDomains[100],    │
    │    Clients[100], Upstreams[100], ...     │
    │  })                                      │
    └─────────┬────────────────────────────────┘
              │ HTTP GET /control/stats?recent=N
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
    │  │    └─ (小时/天粒度切换)          │
    │  └─ 总计计数器累加                  │
    └─────────┬───────────────────────────┘
              ▼
         StatsResp JSON
    (Dashboard 图表渲染)
```

---

## 六、关键设计要点

1. **写入零 I/O**：实时查询只累加内存 map，不会阻塞 DNS 响应
2. **批量截断**：每小时仅保留 Top 100 各类别，控制存储膨胀
3. **滑动窗口淘汰**：切桶时原子替换 + 删除过期桶，数据量恒定
4. **双次过滤**：写入时检查忽略列表，读取时再检查，支持配置热更新
5. **粒度自适应**：时段图表自动在"小时/天"间切换，平衡数据精度与展示密度

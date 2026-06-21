# DNS 上游多组配置的失败回退机制

AdGuard Home 的 DNS 上游服务器支持多组配置（默认上游、域名专属上游、私有 PTR 上游、回退上游），在遇到超时、SERVFAIL 或被拦截时，回退路径并不直观。本文对照代码，把**上游选择 → 健康度判定 → 失败回退**三块逻辑及其协作关系讲清楚。

---

## 1 整体调用链

一次 DNS 查询的核心调用链：

```
客户端请求
  └─ Proxy.Resolve()                       // proxy.go:695
       ├─ cacheWorks? → replyFromCache()    // 缓存命中则直接返回
       └─ replyFromUpstream()               // proxy.go:583
            ├─ selectUpstreams()            // ① 上游选择
            ├─ exchangeUpstreams()          // ② 按模式交换 + 健康度反馈
            ├─ Fallbacks 分支               // ③ 失败回退
            └─ handleExchangeResult()       // 构建 SERVFAIL / 正常响应
```

以下按序号展开。

---

## 2 上游选择：`selectUpstreams`

**代码位置**：`dnsproxy/proxy/proxy.go:549` — `Proxy.selectUpstreams()`

选择逻辑按优先级从高到低：

| 优先级 | 条件 | 使用的上游组 | 说明 |
|--------|------|-------------|------|
| 1 | `RequestedPrivateRDNS ≠ {}` 或 DNS64 PTR | `PrivateRDNSUpstreamConfig` | 私有地址的反向解析走专门的上游 |
| 2 | `CustomUpstreamConfig ≠ nil` 且域名匹配 | 客户端自定义上游 | 每个客户端可配专属上游 |
| 3 | 默认 | `UpstreamConfig`（全局默认 + 域名专属） | 通用路径 |

### 2.1 域名匹配：`getUpstreamsForDomain`

**代码位置**：`dnsproxy/proxy/upstreams.go:382` — `UpstreamConfig.getUpstreamsForDomain()`

`UpstreamConfig` 内部有三类上游映射：

- **`DomainReservedUpstreams`** — 域名专属上游（`[/host.com/]1.2.3.4` 语法）
- **`SpecifiedDomainUpstreams`** — 精确域名专属上游（非通配符）
- **`SubdomainExclusions`** — 排除子域名的域名集合（`[/maps.host.com/]#` 语法）
- **`Upstreams`** — 默认上游列表

匹配规则（从最精确到最宽泛）：

1. 若 FQDN 在 `SubdomainExclusions` 中 → 走 `lookupSubdomainExclusion()`
2. 尝试 `lookupUpstreams(fqdn)` 在 `DomainReservedUpstreams` 中精确匹配
3. 若 FQDN 只有一个标签（如 `localhost`），用 `UnqualifiedNames` 键查找
4. 逐级去掉左侧标签，在 `DomainReservedUpstreams` 中查找（`www.host.com.` → `host.com.` → `com.`）
5. 全部未命中 → 返回默认 `Upstreams`

> **关键点**：被 `#` 排除的域名，其 `DomainReservedUpstreams` 值为空切片，`lookupUpstreams` 检测到空切片时会**回退到默认 Upstreams**。

### 2.2 DS 查询的特殊处理

**代码位置**：`dnsproxy/proxy/upstreams.go:422` — `UpstreamConfig.getUpstreamsForDS()`

DS（Delegation Signer）查询会先去掉 FQDN 的第一个标签再匹配，因为 DS 记录应位于父区域。

### 2.3 AdGuard Home 如何组装上游配置

**代码位置**：`internal/dnsforward/dnsforward.go:539` — `Server.prepareUpstreamSettings()`

AdGuard Home 调用 `newUpstreamConfig()`（`internal/dnsforward/upstreams.go:60`）将用户配置的 DNS 行解析成 `proxy.UpstreamConfig`：

- 如果用户没有配置默认上游，会回退到 `defaultDNS`（`https://dns10.quad9.net/dns-query`）
- Bootstrap 解析器通过 `newBootstrap()` 创建，默认使用 `9.9.9.10` 等 Quad9 地址

---

## 3 健康度判定与上游交换：`exchangeUpstreams`

**代码位置**：`dnsproxy/proxy/exchange.go:17` — `Proxy.exchangeUpstreams()`

拿到上游列表后，根据 `UpstreamMode` 分三条路径：

### 3.1 `load_balance`（默认模式）

```go
// exchange.go:47-65
w := sampleuv.NewWeighted(p.calcWeights(ups), p.randSrc)
for i, ok := w.Take(); ok; i, ok = w.Take() {
    u = ups[i]
    resp, elapsed, err = p.exchange(u, req)
    if err == nil {
        p.updateRTT(u.Address(), elapsed)   // 成功 → 记录实际 RTT
        return resp, u, nil
    }
    errs = append(errs, err)
    p.updateRTT(u.Address(), defaultTimeout) // 失败 → 惩罚 RTT 为 10s
}
```

**健康度判定机制——加权随机 + RTT 反馈**：

1. `calcWeights()`（`exchange.go:129`）根据每个上游的历史平均 RTT 计算权重：**权重 = 1 / 平均RTT**。RTT 越低权重越高，被选中概率越大。
2. 如果上游无历史数据，权重默认为 1（`exchange.go:139`）。
3. 选中某上游后调用 `exchange()` 发起 DNS 查询并计时。
4. **成功**：用实际耗时 `elapsed` 更新 RTT → 后续请求该上游权重上升。
5. **失败**（超时/网络错误）：用 `defaultTimeout`（10s）更新 RTT → 后续请求该上游权重骤降，大概率不会再被优先选中。
6. **加权随机不放回采样**（`w.Take()`）：若选中的上游失败，从权重池中移除该上游后继续采样下一个，直到成功或全部失败。

> **没有主动健康检查**。dnsproxy 不存在后台心跳探活机制，所有健康信息纯粹来自实际请求的 RTT 统计。一个"死掉"的上游只会在被偶尔选中且再次失败后才持续被惩罚。

### 3.2 `parallel` 模式

```go
// exchange.go:23
return upstream.ExchangeParallel(ups, req)
```

**代码位置**：`dnsproxy/upstream/parallel.go:24` — `ExchangeParallel()`

- 对所有上游**同时**发起请求。
- 通过带缓冲的 channel 收集结果，**谁先成功返回谁的响应**。
- 遍历 `resCh`，遇到 `ExchangeAllResult`（成功响应）立即返回；遇到 error 则收集。
- 如果所有上游都失败，返回所有错误的 join。

> 此模式下不做 RTT 权重调整——所有上游平等竞争。但成功的响应本身隐含了"最快"的含义。

### 3.3 `fastest_addr` 模式

```go
// exchange.go:25-28
case UpstreamModeFastestAddr:
    switch req.Question[0].Qtype {
    case dns.TypeA, dns.TypeAAAA:
        return p.fastestAddr.ExchangeFastest(req, ups)
    default:
        // 非 A/AAAA 查询退化为 load_balance
    }
```

**代码位置**：`dnsproxy/fastip/fastest.go:94` — `FastestAddr.ExchangeFastest()`

流程：

1. 调用 `upstream.ExchangeAll()` 对所有上游并行查询，**收集全部成功响应**。
2. 从所有响应的 Answer 中提取 IP 地址集合。
3. 调用 `pingAll()`（`fastip/ping.go:61`）对所有 IP 发起 TCP 拨号探测：
   - 先查缓存（`schedulePings`），缓存命中且成功的 IP 直接作为候选。
   - 未命中或过期的 IP：对 80 和 443 端口并发 TCP 拨号（`pingDoTCP`）。
   - 等待 `pingWaitTimeout`（默认 1s）内第一个成功拨号的 IP，即为"最快"。
4. 用最快 IP 对应的上游响应作为最终结果，Answer 中只保留该 IP 的记录。

**健康度缓存**（`fastip/cache.go`）：

- 成功拨号：缓存 `status=0` + `latencyMsec`，TTL = 10 分钟。
- 拨号失败：缓存 `status=1`，TTL = 10 分钟。
- 下次请求同一 IP 时，缓存命中且 `status=0` 的直接使用；`status=1` 的不参与最快 IP 竞选。

> **注意**：`fastest_addr` 模式仅对 A/AAAA 查询生效，其他类型退化为 `load_balance`。

### 3.4 单上游快速路径

无论哪种模式，如果上游列表只有一个：

```go
// exchange.go:35-44
if len(ups) == 1 {
    u = ups[0]
    resp, _, err = p.exchange(u, req)
    ...
}
```

直接交换，不做权重计算。

---

## 4 失败回退：Fallbacks 分支

**代码位置**：`dnsproxy/proxy/proxy.go:609-621` — `replyFromUpstream()` 内

```go
var wrappedFallbacks []upstream.Upstream
if err != nil && !isPrivate && p.Fallbacks != nil {
    p.logger.Debug("using fallback", slogutil.KeyError, err)
    src = "fallback"
    upstreams = p.Fallbacks.getUpstreamsForDomain(req.Question[0].Name)
    wrappedFallbacks = upstreamsWithStats(upstreams)
    resp, u, err = upstream.ExchangeParallel(wrappedFallbacks, req)
}
```

**触发条件**（三个条件必须**同时**满足）：

1. `err != nil` — 主上游组全部失败（超时 / 网络错误 / SERVFAIL 未返回响应）
2. `!isPrivate` — 不是私有 PTR 请求（私有请求不走回退）
3. `p.Fallbacks != nil` — 配置了回退上游

**回退行为**：

- 从 `Fallbacks`（`UpstreamConfig` 类型）中按域名查找上游，支持和主上游一样的域名专属语法。
- 回退上游**始终使用 `ExchangeParallel`** 并行查询，不论当前 `UpstreamMode` 是什么。
- 即：回退路径不做 load_balance 权重选择，也不做 fastest_addr ping 探测。

### 4.1 AdGuard Home 如何配置 Fallbacks

**代码位置**：`internal/dnsforward/dnsforward.go:679` — `Server.setupFallbackDNS()`

```go
func (s *Server) setupFallbackDNS() (uc *proxy.UpstreamConfig, err error) {
    fallbacks := s.conf.FallbackDNS
    fallbacks = stringutil.FilterOut(fallbacks, aghnet.IsCommentOrEmpty)
    if len(fallbacks) == 0 {
        return nil, nil  // 无回退配置 → Fallbacks 为 nil，不触发回退
    }
    uc, err = proxy.ParseUpstreamsConfig(fallbacks, &upstream.Options{...})
    ...
}
```

用户在 AdGuard Home 设置的 `FallbackDNS` 字段会被解析为 `proxy.UpstreamConfig`。

---

## 5 特殊响应的处理

### 5.1 SERVFAIL 的产生

**代码位置**：`dnsproxy/proxy/proxy.go:650-654` — `handleExchangeResult()`

```go
if resp == nil {
    d.Res = p.messages.NewMsgSERVFAIL(req)
    d.hasEDNS0 = false
    return
}
```

当**所有上游（包括 Fallbacks）都失败**、`resp` 仍为 nil 时，才向客户端返回 SERVFAIL。

> **重要区分**：上游返回的 DNS 响应如果本身就带有 SERVFAIL RCODE（`resp.Rcode == RcodeServerFailure`），这种情况 `err == nil`，`resp != nil`，不会触发 Fallback 分支。只有当 `Exchange()` 返回 Go error（网络超时、连接拒绝等）时才计为"失败"。

### 5.2 BogusNXDomain

**代码位置**：`dnsproxy/proxy/proxy.go:604-607` + `dnsproxy/proxy/bogusnxdomain.go:11`

```go
} else if p.isBogusNXDomain(resp) {
    p.logger.Debug("response contains bogus-nxdomain ip")
    resp = p.messages.NewMsgNXDOMAIN(req)
}
```

如果上游返回的响应 Answer 中包含配置在 `BogusNXDomain` 子网中的 IP，响应会被**改写为 NXDOMAIN**。此改写发生在主上游交换成功之后、Fallback 判断之前，不影响回退逻辑（因为此时 `err == nil`）。

### 5.3 DNS64

**代码位置**：`dnsproxy/proxy/proxy.go:602-603`

```go
if dns64Ups := p.performDNS64(req, resp, wrapped); dns64Ups != nil {
    u = dns64Ups
}
```

如果启用了 DNS64 且响应满足转换条件，会修改上游引用。此逻辑在 BogusNXDomain 之前执行。

---

## 6 三块协作关系总图

```
                         ┌─────────────────────────┐
                         │     客户端 DNS 请求      │
                         └──────────┬──────────────┘
                                    │
                         ┌──────────▼──────────────┐
                         │    Proxy.Resolve()       │
                         │    缓存命中? → 直接返回   │
                         └──────────┬──────────────┘
                                    │ 未命中
                         ┌──────────▼──────────────┐
               ┌─────────│  selectUpstreams()       │─── ① 上游选择
               │         │  私有PTR? 客户端自定义?    │
               │         └──────────┬──────────────┘
               │                    │
               │         ┌──────────▼──────────────┐
               │         │  exchangeUpstreams()     │─── ② 交换 + 健康度
               │         │                          │
               │         │  load_balance:           │
               │         │   加权随机选上游          │
               │         │   成功→更新RTT权重↑       │
               │         │   失败→惩罚RTT权重↓       │
               │         │   继续采样下一个上游       │
               │         │                          │
               │         │  parallel:               │
               │         │   所有上游并行查询        │
               │         │   取第一个成功响应        │
               │         │                          │
               │         │  fastest_addr:            │
               │         │   并行查询+TCP ping       │
               │         │   返回最快IP的响应        │
               │         └───────┬──────┬───────────┘
               │                 │      │
               │            成功 │      │ 失败(且非私有PTR
               │                 │      │  且有Fallbacks)
               │                 │      │
               │         ┌───────▼──┐ ┌─▼──────────────────┐
               │         │ 正常响应  │ │ Fallbacks 回退      │─── ③ 失败回退
               │         │          │ │ ExchangeParallel()  │
               │         └───────┬──┘ │ 并行查询所有回退上游 │
               │                 │    └──────┬──────────────┘
               │                 │           │
               │                 │      成功 │   │ 失败
               │                 │           │   │
               │         ┌───────▼───────────▼───▼──────────┐
               │         │      handleExchangeResult()       │
               │         │  resp≠nil → 返回客户端            │
               │         │  resp==nil → 返回 SERVFAIL        │
               │         └──────────────────────────────────┘
               │
          无上游可用
               │
         ┌─────▼─────┐
         │ NXDOMAIN  │
         │ (ErrNoUp- │
         │  streams) │
         └───────────┘
```

---

## 7 关键要点总结

| 问题 | 答案 |
|------|------|
| 超时走哪条路径？ | 单次 `exchange()` 超时返回 error → load_balance 模式惩罚该上游 RTT 并继续采样；全部超时 → 触发 Fallbacks（若有）→ Fallbacks 也全部超时 → 客户端收到 SERVFAIL |
| 上游返回 SERVFAIL RCODE 走哪条路径？ | **不触发 Fallback**。SERVFAIL RCODE 是合法 DNS 响应（`err==nil, resp≠nil`），直接返回给客户端。只有网络层面的 error（超时/连接拒绝等）才触发回退 |
| 被拦截（过滤规则/Hosts 屏蔽）走哪条路径？ | AdGuard Home 的过滤发生在 `dnsFilter` 中（在 `replyFromUpstream` 之前），被拦截的请求不会走到上游交换逻辑，直接返回过滤结果 |
| BogusNXDomain 命中走哪条路径？ | 主上游返回的响应中被检测到含 Bogus IP → 响应改写为 NXDOMAIN → 直接返回客户端，**不触发 Fallback** |
| 有没有主动健康检查？ | **没有**。所有健康信息来自实际请求的 RTT 统计和（fastest_addr 模式的）TCP ping 缓存 |
| Fallbacks 使用哪种交换模式？ | **始终 `ExchangeParallel`**（并行查询所有回退上游，取第一个成功响应），不受 `UpstreamMode` 配置影响 |
| 客户端专属上游失败后走 Fallbacks 吗？ | **不走**。Fallbacks 仅在 `selectUpstreams()` 返回非私有主上游组且该组全部失败时触发。客户端专属上游由 `CustomUpstreamConfig` 管理，其失败不会级联到 Fallbacks |

---

## 8 代码索引

| 模块 | 文件 | 行号 | 函数/类型 | 说明 |
|------|------|------|----------|------|
| 上游选择 | `dnsproxy/proxy/proxy.go` | 549 | `Proxy.selectUpstreams()` | 根据请求类型选择上游组 |
| 上游选择 | `dnsproxy/proxy/upstreams.go` | 382 | `UpstreamConfig.getUpstreamsForDomain()` | 域名匹配上游 |
| 上游选择 | `dnsproxy/proxy/upstreams.go` | 451 | `UpstreamConfig.lookupUpstreams()` | 查找域名专属上游 |
| 上游选择 | `dnsproxy/proxy/upstreams.go` | 95 | `ParseUpstreamsConfig()` | 解析用户配置 |
| 上游交换 | `dnsproxy/proxy/exchange.go` | 17 | `Proxy.exchangeUpstreams()` | 按 UpstreamMode 分发 |
| 上游交换 | `dnsproxy/proxy/exchange.go` | 129 | `Proxy.calcWeights()` | 基于 RTT 计算权重 |
| 上游交换 | `dnsproxy/proxy/exchange.go` | 150 | `Proxy.updateRTT()` | 更新 RTT 统计 |
| 上游交换 | `dnsproxy/upstream/parallel.go` | 24 | `ExchangeParallel()` | 并行交换取首个成功 |
| 上游交换 | `dnsproxy/upstream/parallel.go` | 94 | `ExchangeAll()` | 并行交换收集所有响应 |
| 最快地址 | `dnsproxy/fastip/fastest.go` | 94 | `FastestAddr.ExchangeFastest()` | 并行查询+ping 选最快 |
| 最快地址 | `dnsproxy/fastip/ping.go` | 61 | `FastestAddr.pingAll()` | TCP 拨号探测 |
| 最快地址 | `dnsproxy/fastip/cache.go` | 69-106 | `cacheFind/AddSuccessful/AddFailure` | ping 结果缓存 |
| 失败回退 | `dnsproxy/proxy/proxy.go` | 609-621 | `replyFromUpstream()` 内 Fallbacks 分支 | 主上游全部失败时触发 |
| 响应处理 | `dnsproxy/proxy/proxy.go` | 643-669 | `Proxy.handleExchangeResult()` | SERVFAIL 生成 |
| 响应处理 | `dnsproxy/proxy/bogusnxdomain.go` | 11 | `Proxy.isBogusNXDomain()` | Bogus IP 检测 |
| AH 配置 | `internal/dnsforward/upstreams.go` | 60 | `newUpstreamConfig()` | 组装主上游配置 |
| AH 配置 | `internal/dnsforward/dnsforward.go` | 679 | `Server.setupFallbackDNS()` | 组装回退上游配置 |
| AH 配置 | `internal/dnsforward/upstreams.go` | 143 | `setProxyUpstreamMode()` | 设置上游交换模式 |

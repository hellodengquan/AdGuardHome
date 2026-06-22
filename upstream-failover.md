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

## 8 补充细节一：上游切换时的连接清理与连接池复用

不同协议的上游对连接池的处理方式不同，直接影响上游切换（失败换下一上游 / Fallback 换上游）时的性能表现。以下按协议拆解。

### 8.1 Plain DNS（UDP/TCP）：无连接池，每次新建

**代码位置**：`dnsproxy/upstream/plain.go:89-131` — `plainDNS.dialExchange()`

```go
func (p *plainDNS) dialExchange(
    network network,
    dial bootstrap.DialHandler,
    req *dns.Msg,
) (resp *dns.Msg, err error) {
    client := &dns.Client{Timeout: p.timeout}
    conn := &dns.Conn{}

    conn.Conn, err = dial(ctx, network, "")
    if err != nil {
        return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
    }
    defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

    resp, _, err = client.ExchangeWithConn(upstreamReq, conn)
    // ...
}
```

- **每次 Exchange 都新建连接**，`defer c.Close()` 保证用完立即关闭。
- UDP 无连接的语义下开销可接受，TCP 每次建连的三次握手在高并发下成本较高。
- 切换上游时不存在旧连接残留问题——每个请求独立。

### 8.2 DNS-over-TLS（DoT）：自维护 FILO 连接池

**代码位置**：`dnsproxy/upstream/dot.go:26-52`

```go
type dnsOverTLS struct {
    connsMu *sync.Mutex
    conns   []net.Conn  // 可复用连接池，FILO 顺序
    // ...
}
```

**取连接**（`dot.go:154-185` — `conn()`）：

```go
func (p *dnsOverTLS) conn(h bootstrap.DialHandler) (conn net.Conn, err error) {
    defer func() {
        if conn == nil {
            conn, err = tlsDial(h, p.tlsConf.Clone())  // 池空则新建 TLS 连接
        }
    }()

    p.connsMu.Lock()
    defer p.connsMu.Unlock()

    l := len(p.conns)
    if l == 0 {
        return nil, nil
    }

    p.conns, conn = p.conns[:l-1], p.conns[l-1]  // FILO，取最后一个

    err = conn.SetDeadline(time.Now().Add(dialTimeout))
    if err != nil {
        // SetDeadline 失败 → 连接已被服务端关闭，放弃并新建
        return nil, nil
    }
    return conn, nil
}
```

**还连接**（`dot.go:187-192` — `putBack()`）：

```go
func (p *dnsOverTLS) putBack(conn net.Conn) {
    p.connsMu.Lock()
    defer p.connsMu.Unlock()
    p.conns = append(p.conns, conn)
}
```

**失败时的连接处理**（`dot.go:92-132` — `Exchange()`）：

```go
reply, err = p.exchangeWithConn(conn, req)
if err != nil {
    // 池中的坏连接：立即关闭，不还回池
    err = errors.WithDeferred(err, conn.Close())
    // 重新 dial 一条新连接再试一次
    conn, err = tlsDial(h, p.tlsConf.Clone())
    reply, err = p.exchangeWithConn(conn, req)
    if err != nil {
        return reply, errors.WithDeferred(err, conn.Close())
    }
}
p.putBack(conn)  // 成功 → 连接放回池中复用
```

> **关键行为**：连接池是**每个上游独立**的。当上游 A 失败切换到上游 B 时，A 的连接池中的连接不会被清理（仍保留在 A 的池里）。只有对该上游的后续请求才会遇到坏连接并触发"SetDeadline 失败 → 建新连接"的自愈逻辑。关闭整个 `dnsOverTLS` 时（`Close()`），才会遍历 `conns` 全量关闭。

### 8.3 DNS-over-HTTPS（DoH）：Go http.Client 的 Transport 连接池

**代码位置**：`dnsproxy/upstream/doh.go:50-88`

```go
type dnsOverHTTPS struct {
    client    *http.Client    // 内部持 http.Transport，自带连接池
    clientMu  *sync.Mutex
    // ...
}
```

**连接池配置**（`doh.go:469-493` — `createTransport()`）：

```go
transport := &http.Transport{
    TLSClientConfig:    tlsConf,
    IdleConnTimeout:    transportDefaultIdleConnTimeout,   // 5 分钟
    MaxConnsPerHost:    dohMaxConnsPerHost,                // 每个 host 最多 2 条
    MaxIdleConns:       dohMaxIdleConns,                   // 最多 2 条空闲
    ForceAttemptHTTP2:  true,
}
```

**失败时的连接重置**（`doh.go:154-202` — `Exchange()`）：

```go
resp, err = p.exchangeHTTPS(client, req)

// 如果是缓存的 client 出现超时 / QUIC 重试错误 → 最多重置 client 两次
for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
    client, err = p.resetClient(err)  // 关闭旧 client，重建
    resp, err = p.exchangeHTTPS(client, req)
}

if err != nil {
    _, resErr := p.resetClient(err)   // 最终失败也确保 client 被重置
    return nil, errors.WithDeferred(err, resErr)
}
```

`resetClient()`（`doh.go:350-371`）会关闭旧 client 的底层 transport：

```go
func (p *dnsOverHTTPS) resetClient(resetErr error) (client *http.Client, err error) {
    if errors.Is(resetErr, quic.Err0RTTRejected) {
        p.resetQUICConfig()  // 清除 0-RTT TokenStore
    }
    oldClient := p.client
    if oldClient != nil {
        closeErr := p.closeClient(oldClient)  // HTTP/3 直接 Close，HTTP/2 关闭空闲连接
    }
    p.client, err = p.createClient()
    return p.client, err
}
```

> **上游切换与连接池的关系**：每个 DoH 上游有自己独立的 `http.Client`。上游 A 失败 → 其 client 可能被 reset（连池被清空重建）→ 切换到上游 B 时使用 B 自己的 client（连接池独立）。两上游之间互不干扰。

### 8.4 DNS-over-QUIC（DoQ）：单连接缓存 + 流复用

**代码位置**：`dnsproxy/upstream/doq.go:60-99`

```go
type dnsOverQUIC struct {
    conn    *quic.Conn       // 单条 QUIC 连接缓存
    connMu  *sync.Mutex
    // ...
}
```

**连接使用**（`doq.go:170-223` — `Exchange()`）：

```go
conn, cached, err := p.getConnection()  // 有缓存 conn 则复用

resp, err = p.exchangeQUIC(req, conn)   // 复用 conn，在上面开新 stream

if cached && err != nil {
    // 缓存的 conn 坏了 → 关闭并重建
    p.closeConnWithError(conn, err)
    conn, _, err = p.getConnection()    // 会走 openConnection() 新建
    resp, err = p.exchangeQUIC(req, conn)
}

if err != nil {
    p.closeConnWithError(conn, err)     // 最终失败也关闭
}
```

`getConnection()`（`doq.go:301-318`）只缓存一条 conn：

```go
func (p *dnsOverQUIC) getConnection() (conn *quic.Conn, cached bool, err error) {
    p.connMu.Lock()
    defer p.connMu.Unlock()

    conn = p.conn
    if conn != nil {
        return conn, true, nil
    }
    conn, err = p.openConnection()
    p.conn = conn
    return conn, false, nil
}
```

`closeConnWithError()`（`doq.go:394-417`）重置缓存：

```go
func (p *dnsOverQUIC) closeConnWithError(conn *quic.Conn, err error) {
    p.connMu.Lock()
    defer p.connMu.Unlock()

    if p.conn == conn {
        p.conn = nil  // 只在关闭缓存 conn 时才清空
    }
    _ = conn.CloseWithError(code, "")
}
```

> **关键区别**：DoQ 是**单连接 + 多 Stream 复用**模型。同一上游的所有并发查询共享一条 QUIC 连接，通过 Stream 隔离。连接失效时所有并发请求都会失败并触发重建。上游切换时（A→B），A 的 QUIC 连接不会被主动关闭，只是不再被后续请求选中。

### 8.5 小结：四种协议的连接模型对比

| 协议 | 连接池模型 | 切换上游时旧连接处理 | 坏连接自愈 |
|------|-----------|---------------------|-----------|
| Plain UDP/TCP | 无，每次新建 | N/A | 每次都新建，无"坏连接"概念 |
| DoT | 每个上游独立 FILO 切片池 | 不处理，保留在原上游池里 | SetDeadline 失败时放弃旧连接，建新连接 |
| DoH | `http.Transport` 内部 LRU 池 | 不处理，各上游 client 独立 | 超时/QUIC 错误时 resetClient，重建整个 client |
| DoQ | 每个上游单条 QUIC 连接 | 不主动关闭，缓存保留 | 失败时 closeConnWithError 置 nil，下次请求新建 |

---

## 9 补充细节二：DNSSEC 验证失败与上游回退优先级判断

dnsproxy 本身**不做 DNSSEC 签名验证**，它的角色是**透明转发 DO/AD/CD 位**，并在缓存和响应过滤层面处理 DNSSEC 相关记录。理解这一点很关键——"DNSSEC 验证失败"在 dnsproxy 的语义里不等于"上游查询失败"。

### 9.1 DO 位与 DNSSEC 请求

**代码位置**：`dnsproxy/proxy/proxy.go:671-688` — `Proxy.addDO()`

```go
func (p *Proxy) addDO(msg *dns.Msg) {
    if !p.DNSSECEnabled {
        return  // DNSSEC 全局开关关闭 → 什么也不做
    }
    if o := msg.IsEdns0(); o != nil {
        if !o.Do() {
            o.SetDo()  // 已有 EDNS0 OPT → 设置 DO 位为 1
        }
        return
    }
    msg.SetEdns0(defaultUDPBufSize, true)  // 无 OPT → 新增，DO=1
}
```

在 `Proxy.Resolve()`（`proxy.go:695-755`）中，`addDO` 的调用时机：

```go
// proxy.go:702-731
cacheWorks := p.cacheWorks(dctx)
if cacheWorks {
    p.addDO(dctx.Req)  // 缓存启用时，向所有上游请求追加 DO=1，以便缓存 DNSSEC RR
    // ...
}
```

> **规则**：如果 `DNSSECEnabled=true` 且缓存启用，所有上游查询都会被强制加上 DO 位（DNSSEC OK），这样上游会把 RRSIG/DNSKEY/NSEC 等 DNSSEC 资源记录一并返回，便于后续缓存。

### 9.2 AD 位的透传与过滤

**代码位置**：`dnsproxy/proxy/cache.go:641-658` — `filterMsg()`

```go
func filterMsg(dst, m *dns.Msg, ad, do bool, ttl uint32) {
    // RFC 6840：只有请求中 DO=1 或 AD=1 时，响应才保留 AD=1
    dst.AuthenticatedData = dst.AuthenticatedData && (ad || do)

    // DO=0 时，过滤掉所有 DNSSEC RR（NSEC/NSEC3/DS/RRSIG/DNSKEY 等）
    dst.Answer = filterRRSlice(m.Answer, do, ttl, m.Question[0].Qtype)
    dst.Ns     = filterRRSlice(m.Ns, do, ttl, dns.TypeNone)
    dst.Extra  = filterRRSlice(m.Extra, do, ttl, dns.TypeNone)
}
```

`filterRRSlice()`（`cache.go:617-639`）的过滤逻辑：

```go
for _, r := range rrs {
    if (!do && isDNSSEC(r) && r.Header().Rrtype != except) || r.Header().Rrtype == dns.TypeOPT {
        continue  // DO=0 时丢弃 DNSSEC 记录，OPT 始终丢弃
    }
    // ...
}
```

在 `Resolve()` 末尾（`proxy.go:748-750` 和 `cache.go:147-158`），无论响应来自缓存还是上游，都会调用 `filterMsg`：

```go
// proxy.go:748-750
if dctx.Res != nil {
    filterMsg(dctx.Res, dctx.Res, dctx.adBit, dctx.doBit, 0)
}
```

其中：
- `dctx.adBit` = 客户端原始请求的 AD 位
- `dctx.doBit` = 客户端原始请求的 DO 位（来自 EDNS0 OPT）

### 9.3 CD 位（Checking Disabled）：跳过上游回退判断的关键

**代码位置**：`dnsproxy/proxy/proxy.go:741-744` — 缓存写入条件

```go
if cacheWorks && ok && !dctx.Res.CheckingDisabled {
    // 仅当响应没有 CD 位时才缓存
    p.cacheResp(dctx)
}
```

以及缓存读取条件（`proxy.go:805-816` — `cacheWorks()`）：

```go
case dctx.Req.CheckingDisabled:
    // 客户端请求带 CD=1 → 不查缓存
    reason = "dnssec check disabled"
```

> **含义**：`CheckingDisabled` 是 DNS 头部的 CD 位，表示"客户端希望上游不要做 DNSSEC 验证"。当客户端请求 CD=1 时，dnsproxy 直接跳过缓存，每次都查上游；且响应的 CD 位为 1 时也不会被写入缓存。CD 位本身不影响上游选择和回退逻辑。

### 9.4 DNSSEC"验证失败"在上游回退中的真实表现

dnsproxy 不做签名验证，那么什么情况下会出现"DNSSEC 相关的失败"？

| 场景 | dnsproxy 看到的结果 | 是否触发回退 |
|------|---------------------|-------------|
| 上游返回 `SERVFAIL` 且原因是 DNSSEC 验证失败 | `resp != nil, err == nil, resp.Rcode = SERVFAIL` | **不触发** |
| 上游网络超时（真实的超时，不是 DNSSEC SERVFAIL） | `resp == nil, err != nil` | **触发**，按普通网络错误处理 |
| BogusNXDomain 命中含伪答案 IP 的响应 | 主上游成功 → BogusNXDomain 改写为 NXDOMAIN | **不触发** |
| 上游返回合法响应但 AD=0（未验证或验证失败） | `resp != nil, err == nil`，按 `filterMsg` 规则处理 | **不触发** |
| 上游返回 RRSIG 但签名已过期 | dnsproxy 不检查，原样返回给客户端 | **不触发** |

> **关键结论**：dnsproxy 不具备判断"DNSSEC 验证失败"的能力——它既不验证签名，也不解析 SERVFAIL 的子原因码（EDNS Extended RCODE）。因此**DNSSEC 验证失败永远不会触发上游回退**。唯一的例外是当 DNSSEC 验证逻辑导致上游本身网络超时或崩溃时，这会被当作普通网络错误处理，但 dnsproxy 并不知道这与 DNSSEC 有关。

### 9.5 DNSSEC 相关决策与回退优先级的顺序

把所有逻辑按 `Resolve()` 内的执行顺序排列：

```
Proxy.Resolve(dctx)
  │
  ├─ ① processECS              // 添加 ECS（如有）
  ├─ ② calcFlagsAndSize        // 提取 adBit / doBit / hasEDNS0
  │
  ├─ ③ cacheWorks() 判断
  │     ├─ DNSSECEnabled=true  → 后续 addDO 会生效
  │     ├─ Req.CheckingDisabled → cacheWorks=false（跳过缓存）
  │     └─ ...
  │
  ├─ 缓存命中?
  │     ├─ 是 → filterMsg(adBit, doBit) 过滤 DNSSEC RR + AD 位 → 返回
  │     └─ 否 → addDO(dctx.Req)         // 若 DNSSECEnabled，请求上游时强制 DO=1
  │
  ├─ ④ replyFromUpstream()      // ← 正常的上游选择/回退逻辑
  │     │                          这里不感知 DNSSEC，只看 err 是否为 nil
  │     ├─ selectUpstreams()
  │     ├─ exchangeUpstreams()
  │     ├─ Fallbacks（仅当 err != nil）
  │     └─ handleExchangeResult()
  │
  ├─ ⑤ cacheResp() 条件
  │     └─ !Res.CheckingDisabled → 才写入缓存
  │
  └─ ⑥ filterMsg(adBit, doBit)  // 最终响应：根据客户端 DO/AD 决定是否保留 DNSSEC RR
```

DNSSEC 在整个链路中只影响**三件事**：
1. 是否在上游请求中加 DO 位（影响上游返回什么 RR）
2. 响应/请求的 CD 位是否跳缓存
3. 返回给客户端时是否过滤掉 DNSSEC RR 和 AD 位

**DNSSEC 不参与上游回退判断**。上游回退的唯一条件是 `err != nil`（Go 层面的网络错误），这与 DNS 响应内容（包括 SERVFAIL RCODE、AD 位、是否包含有效 RRSIG）完全正交。

---

## 10 补充细节三：私有反向 DNS 请求路径与上游回退的关系

私有反向 DNS（Private RDNS）请求是 dnsproxy 中一类特殊处理的请求，它从请求入口就走上完全独立的路径，并且**永远不会触发 Fallback**。理解这条路径需要追踪从 `handleDNSRequest` 到 `replyFromUpstream` 的完整调用链。

### 10.1 入口识别：`isForbiddenARPA`

**代码位置**：`dnsproxy/proxy/server.go:123-150` — `DNSContext.isForbiddenARPA()`

```go
func (dctx *DNSContext) isForbiddenARPA(
    privateNets netutil.SubnetSet,
    l *slog.Logger,
) (ok bool) {
    q := dctx.Req.Question[0]
    switch q.Qtype {
    case dns.TypePTR, dns.TypeSOA, dns.TypeNS:
        // 只处理 PTR / SOA / NS 三种类型
    default:
        return false
    }

    // 从 ARPA 域名中提取反向地址前缀
    requestedPref, err := netutil.ExtractReversedAddr(q.Name)
    if err != nil {
        return false
    }

    // 反向地址在私有网段内 → 标记为私有 RDNS 请求
    if privateNets.Contains(requestedPref.Addr()) {
        dctx.RequestedPrivateRDNS = requestedPref  // 关键标记！
        return !dctx.IsPrivateClient  // 公网客户端请求私有 ARPA → 直接拒绝
    }

    return false
}
```

这个函数在 `validateRequest`（`proxy.go:760-788`）中被调用，位置在 `Resolve()` 之前：

```go
// proxy.go:760-784
func (p *Proxy) validateRequest(d *DNSContext) (resp *dns.Msg) {
    switch {
    // ...
    case d.isForbiddenARPA(p.privateNets, p.logger):
        p.logger.Debug("private arpa domain is requested", ...)
        return p.messages.NewMsgNXDOMAIN(d.Req)  // 公网客户端 → 直接 NXDOMAIN
    // ...
    }
}
```

**两层过滤**：
1. **公网客户端请求私有 ARPA** → 直接返回 NXDOMAIN，根本走不到 `Resolve()`
2. **内网客户端请求私有 ARPA** → 通过校验，设置 `RequestedPrivateRDNS` 标记，进入 `Resolve()`

### 10.2 `selectUpstreams` 中的分支

**代码位置**：`dnsproxy/proxy/proxy.go:549-562`

```go
func (p *Proxy) selectUpstreams(
    d *DNSContext,
) (upstreams []upstream.Upstream, isPrivate bool) {
    // ── 第一优先级分支 ──────────────────────────────────────
    if d.RequestedPrivateRDNS != (netip.Prefix{}) || p.shouldStripDNS64(d.Req) {
        private := p.PrivateRDNSUpstreamConfig
        if p.UsePrivateRDNS && d.IsPrivateClient && private != nil {
            upstreams = private.getUpstreamsForDomain(host)
        }
        return upstreams, true  // ② isPrivate = true！
    }
    // ────────────────────────────────────────────────────────

    // 后续分支（自定义上游、默认上游）永远不会走到
    // ...
}
```

**关键点**：
- `RequestedPrivateRDNS` 非空时，直接进入私有 RDNS 分支
- 返回的第二个值 `isPrivate = true`，这个标记决定了后续的回退行为
- 私有上游组来自 `PrivateRDNSUpstreamConfig`，与主上游 `UpstreamConfig` 完全独立

### 10.3 为何不走 Fallback：`replyFromUpstream` 中的判断

**代码位置**：`dnsproxy/proxy/proxy.go:581-621`

```go
func (p *Proxy) replyFromUpstream(d *DNSContext) (ok bool, err error) {
    req := d.Req

    upstreams, isPrivate := p.selectUpstreams(d)
    if len(upstreams) == 0 {
        d.Res = p.messages.NewMsgNXDOMAIN(req)
        return false, fmt.Errorf("selecting upstream: %w", upstream.ErrNoUpstreams)
    }

    if isPrivate {
        p.recDetector.add(d.Req)  // 加入递归检测，防止 PTR → A → PTR 循环
    }

    // ① 查询私有上游
    resp, u, err := p.exchangeUpstreams(req, wrapped)

    // ── Fallback 触发条件 ──────────────────────────────────
    //     err != nil       → 主上游全部失败
    // && !isPrivate       → 不是私有请求  ← 关键条件！
    // && p.Fallbacks != nil → 配置了 fallback
    // ──────────────────────────────────────────────────────
    if err != nil && !isPrivate && p.Fallbacks != nil {
        resp, u, err = upstream.ExchangeParallel(wrappedFallbacks, req)
    }
    // ...
}
```

**`!isPrivate` 这个条件直接锁死了私有 RDNS 的 Fallback 路径**。即使 `PrivateRDNSUpstreamConfig` 中的所有上游都失败，`err != nil`，只要 `isPrivate == true`，Fallback 分支就不会执行。

### 10.4 设计意图与安全考虑

为什么私有 RDNS 故意不走 Fallback？从代码和 RFC 规范中可以找到三个理由：

1. **隐私保护（RFC 6761 § 6.1）**：私有地址的反向解析（如 `1.168.192.in-addr.arpa`）属于内网信息，不应泄漏到公网 DNS。如果内网 DNS 失败，直接返回 SERVFAIL 比发给 Quad9/Cloudflare 等公网 Fallback 更安全。

2. **避免无效流量**：公网 DNS 不可能知道 `10.0.0.1` 对应的主机名，查询注定失败，徒增延迟。

3. **防止 DNS 泄漏**：企业内网的命名方案（如 `server1.dc1.corp.local`）通过 PTR 查询可能泄漏内部网络结构，这在安全上是敏感信息。

### 10.5 完整路径对比

| 路径 | 普通公网 DNS 请求 | 私有 RDNS 请求（内网客户端） |
|------|------------------|----------------------------|
| 入口识别 | 无特殊标记 | `isForbiddenARPA` 设置 `RequestedPrivateRDNS` |
| 上游选择 | 自定义 → 默认上游 | 直接走 `PrivateRDNSUpstreamConfig` |
| `isPrivate` 标记 | `false` | `true` |
| Fallback 触发 | 满足条件时触发 | **永远不触发** |
| 缓存 | 支持（除非 CD 位） | **不缓存**（`cacheWorks()` 中 `RequestedPrivateRDNS != {}` 直接返回 false） |
| 全部失败时 | SERVFAIL（经过 Fallback 后） | SERVFAIL（直接） |

---

## 11 补充细节四：DoT/DoH 加密上游与传统 UDP 上游混合配置的健康度判定差异

当用户在 AdGuard Home 中混合配置多种协议的上游时（如同时配置 `udp://1.1.1.1` 和 `tls://1.1.1.1` 和 `https://1.1.1.1/dns-query`），健康度判定机制在表面上使用同一套 RTT 统计逻辑，但实际上由于 **地址标识差异**、**连接开销差异** 和 **失败重试机制差异**，三种上游的"健康度"表现差异巨大。

### 11.1 地址标识：同一 IP，不同协议 = 不同的 RTT 统计键

健康度统计的核心是 `p.upstreamRTTStats` map，其 key 是上游的 `Address()` 返回值。不同协议的 `Address()` 实现不同，导致即使是同一个 IP，不同协议的 RTT 统计**完全独立**。

**代码位置**：各协议的 `Address()` 方法

```go
// Plain UDP（plain.go:76-85）
func (p *plainDNS) Address() string {
    switch p.net {
    case networkUDP:
        return p.addr.Host  // → "1.1.1.1"（只有 IP，无 scheme）
    case networkTCP:
        return p.addr.String()  // → "tcp://1.1.1.1:53"
    }
}

// DoT（dot.go:89）
func (p *dnsOverTLS) Address() string {
    return p.addr.String()  // → "tls://1.1.1.1:853"
}

// DoH（doh.go:151）
func (p *dnsOverHTTPS) Address() string {
    return p.addrRedacted  // → "https://1.1.1.1/dns-query"（密码脱敏）
}

// DoQ（doq.go:167）
func (p *dnsOverQUIC) Address() string {
    return p.addr.String()  // → "quic://1.1.1.1:853"
}
```

**结果**：对于同一个服务器 1.1.1.1，四种协议在 `upstreamRTTStats` map 中是四个**独立的 key**，各自维护独立的 RTT 统计：

```
p.upstreamRTTStats = {
    "1.1.1.1":                      {rttSum: X, reqNum: Y},    // UDP
    "tcp://1.1.1.1:53":             {rttSum: X, reqNum: Y},    // TCP
    "tls://1.1.1.1:853":            {rttSum: X, reqNum: Y},    // DoT
    "https://1.1.1.1/dns-query":    {rttSum: X, reqNum: Y},    // DoH
}
```

`calcWeights()`（`exchange.go:129`）按 index 遍历时，每个上游查各自的统计：

```go
func (p *Proxy) calcWeights(ups []upstream.Upstream) (weights []float64) {
    for _, u := range ups {
        stat := p.upstreamRTTStats[u.Address()]  // 按协议独立的 key 查找
        // ...
    }
}
```

### 11.2 RTT 基线差异：加密协议的握手开销

`exchange()` 方法中计时的 `dur` 包含了从调用 `u.Exchange(req)` 到返回的**全部时间**：

**代码位置**：`dnsproxy/proxy/exchange.go:75-105`

```go
func (p *Proxy) exchange(
    u upstream.Upstream,
    req *dns.Msg,
) (resp *dns.Msg, dur time.Duration, err error) {
    startTime := p.time.Now()
    resp, err = u.Exchange(req)       // 这里包含了所有协议开销
    dur = p.time.Now().Sub(startTime)  // 总耗时
    // ...
    if err == nil {
        p.updateRTT(u.Address(), dur)  // 成功 → 用总耗时更新
    } else {
        p.updateRTT(u.Address(), defaultTimeout)  // 失败 → 10s 惩罚
    }
}
```

**三种协议的 RTT 构成差异**：

| 协议 | 首次请求 RTT 构成 | 后续请求 RTT 构成 | 典型基线 |
|------|-----------------|-----------------|----------|
| **UDP** | UDP 传输 + DNS 处理（~10-50ms） | 同首次（每次新建） | ~20ms |
| **TCP** | TCP 三次握手（~RTT×1.5） + DNS 处理 | 同首次（每次新建） | ~30ms |
| **DoT** | TCP 握手 + TLS 握手（~RTT×3-4） + DNS 处理 | 连接复用（仅 DNS 处理） | 首次 ~80ms，复用后 ~20ms |
| **DoH** | TCP + TLS + HTTP/2 握手（~RTT×4） + DNS 处理 | 连接复用（HTTP/2 流复用） | 首次 ~100ms，复用后 ~25ms |
| **DoQ** | QUIC 握手（~RTT×1-2，支持 0-RTT） + DNS 处理 | 连接复用（QUIC 流复用） | 首次 ~40ms，复用后 ~20ms |

**对权重的影响**：
- **冷启动阶段**：UDP 权重最高（平均 RTT 最小）→ 被优先选中 → UDP 的统计样本越来越多 → 权重差距拉大
- **热运行阶段**：加密协议连接建立后，后续请求的 RTT 与 UDP 接近 → 权重逐渐追平 → 开始竞争
- **失败惩罚**：所有协议失败时统一用 `defaultTimeout`（10s）惩罚，对原本 RTT 小的 UDP 权重打击更大（从 1/20ms 降到 1/10000ms，权重下降 500 倍）

### 11.3 失败重试机制差异：加密协议的"内部重试"

加密协议（DoT/DoH/DoQ）在 `Exchange()` 内部有自己的重试逻辑，**这些重试的耗时会计入总 RTT**，但对上层 `exchangeUpstreams` 来说是透明的。

**DoT 内部重试**（`dot.go:92-132`）：

```go
func (p *dnsOverTLS) Exchange(req *dns.Msg) (reply *dns.Msg, err error) {
    conn, err := p.conn(h)  // 从池取连接
    reply, err = p.exchangeWithConn(conn, req)
    if err != nil {
        // 池中的坏连接 → 关闭并新建重试
        err = errors.WithDeferred(err, conn.Close())
        conn, err = tlsDial(h, p.tlsConf.Clone())  // 新建连接（含握手）
        reply, err = p.exchangeWithConn(conn, req)
    }
    p.putBack(conn)
    return reply, nil
}
```

**DoH 内部重试**（`doh.go:154-202`）：

```go
func (p *dnsOverHTTPS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
    client, isCached, err := p.getClient()
    resp, err = p.exchangeHTTPS(client, req)

    // 缓存 client 出现超时 / QUIC 错误 → 最多重置 client 并重试 2 次
    for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
        client, err = p.resetClient(err)  // 关闭旧 client，重建（含握手）
        resp, err = p.exchangeHTTPS(client, req)
    }
    // ...
}
```

**DoQ 内部重试**（`doq.go:170-223`）：

```go
func (p *dnsOverQUIC) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
    conn, cached, err := p.getConnection()  // 复用缓存连接
    resp, err = p.exchangeQUIC(req, conn)

    if cached && err != nil {
        // 缓存连接坏了 → 关闭并重建
        p.closeConnWithError(conn, err)
        conn, _, err = p.getConnection()  // 新建 QUIC 连接（含握手）
        resp, err = p.exchangeQUIC(req, conn)
    }
    // ...
}
```

**对健康度判定的影响**：
1. **RTT 膨胀**：加密协议的内部重试会计入 `dur`，导致其平均 RTT 高于实际 DNS 查询时间。UDP 失败时直接返回 error，不会内部重试。
2. **成功率高估**：加密协议通过内部重试"消化"了部分失败，上层 `exchangeUpstreams` 看到的 `err == nil` 比例更高 → 更少触发 10s 惩罚。
3. **UDP 的"脆弱性"**：UDP 没有内部重试，一次网络丢包就直接失败 → 立即触发 10s 惩罚 → 权重骤降。

### 11.4 连接池对"平均 RTT"的影响

第 8 章详细介绍了各协议的连接池模型，这些模型直接影响 RTT 统计的分布：

| 协议 | 连接池模型 | 对 RTT 统计的影响 |
|------|-----------|------------------|
| **UDP** | 无连接池，每次新建 | RTT 分布稳定，波动小 |
| **DoT** | FILO 池，最多保留 N 条连接 | 池命中时 RTT 低（~20ms），池空/坏连接时 RTT 高（~80ms）→ **双峰分布** |
| **DoH** | `http.Transport` LRU 池，`MaxConnsPerHost=2` | 同 DoT，HTTP/2 流复用进一步降低后续请求开销 |
| **DoQ** | 单连接 + 多 Stream 复用 | 连接建立后 RTT 极低且稳定，连接失效时所有并发请求同时失败 → **全有或全无** |

**权重计算的公平性问题**：`calcWeights()` 用**算术平均** RTT，对双峰分布不友好。DoT/DoH 偶尔出现的 80ms（建连）会拉高平均值，而 UDP 稳定的 20ms 平均值更优。这导致在冷启动或网络抖动时，UDP 始终获得更高权重，加密协议即使 99% 的请求很快，只要有 1% 的建连开销，平均权重就被拉低。

### 11.5 混合配置时的实际行为示例

假设用户配置：

```yaml
upstream_dns:
  - udp://1.1.1.1:53
  - tls://1.1.1.1:853
  - https://1.1.1.1/dns-query
```

**冷启动阶段（前 10 个请求）**：

| 请求 # | 选中上游 | 原因 | 实际 RTT | 更新后平均 RTT |
|--------|---------|------|----------|---------------|
| 1 | 随机（权重都是 1） | 无历史数据 | 假设选中 UDP，20ms | UDP: 20ms, DoT: -, DoH: - |
| 2 | UDP（权重 1/20=0.05，其余 1） | UDP 有数据，权重略低 | UDP，20ms | UDP: 20ms |
| 3 | 随机（DoT/DoH 权重 1 高于 UDP 0.05） | 新上游权重默认 1 | 假设选中 DoT，首次建连 80ms | DoT: 80ms，权重 1/80=0.0125 |
| 4 | UDP（0.05 最高） | UDP 权重最高 | UDP，20ms | UDP: 20ms |
| 5 | DoH（权重 1） | DoH 还没数据 | DoH，首次建连 100ms | DoH: 100ms，权重 0.01 |

**结果**：冷启动阶段 UDP 占据绝对优势，因为加密协议的首次建连开销拉低了权重。

**热运行阶段（100+ 请求后，连接池稳定）**：

| 上游 | 成功请求占比 | 平均 RTT | 权重 |
|------|------------|----------|------|
| UDP | 100%（无内部重试） | 20ms | 0.05 |
| DoT | 99%（1% 内部重试消化） | 25ms（含偶发建连） | 0.04 |
| DoH | 99% | 30ms（HTTP/2 开销） | 0.033 |

**结果**：UDP 权重仍然最高，但差距缩小。一旦 UDP 出现一次超时（网络波动），立即被惩罚到 10000ms 平均 RTT，权重骤降到 0.0001，此时 DoT/DoH 会接管所有请求，直到 UDP 的平均 RTT 被后续成功请求逐渐拉低。

---

## 12 代码索引

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
| 连接池-Plain | `dnsproxy/upstream/plain.go` | 89-131 | `plainDNS.dialExchange()` | 每次新建连接，用完即关 |
| 连接池-DoT | `dnsproxy/upstream/dot.go` | 26-52 | `dnsOverTLS` 结构体 | FILO 连接池定义 |
| 连接池-DoT | `dnsproxy/upstream/dot.go` | 154-185 | `dnsOverTLS.conn()` | 从池取连接，SetDeadline 自检坏连接 |
| 连接池-DoT | `dnsproxy/upstream/dot.go` | 92-132 | `dnsOverTLS.Exchange()` | 失败时关闭坏连接并新建重试 |
| 连接池-DoH | `dnsproxy/upstream/doh.go` | 469-493 | `dnsOverHTTPS.createTransport()` | `http.Transport` 连接池参数 |
| 连接池-DoH | `dnsproxy/upstream/doh.go` | 350-371 | `dnsOverHTTPS.resetClient()` | 失败时关闭旧 client 并重建 |
| 连接池-DoQ | `dnsproxy/upstream/doq.go` | 60-99 | `dnsOverQUIC` 结构体 | 单连接缓存 + Stream 复用 |
| 连接池-DoQ | `dnsproxy/upstream/doq.go` | 170-223 | `dnsOverQUIC.Exchange()` | 复用连接，失败时重建 |
| 连接池-DoQ | `dnsproxy/upstream/doq.go` | 394-417 | `dnsOverQUIC.closeConnWithError()` | 关闭连接并清空缓存 |
| DNSSEC | `dnsproxy/proxy/proxy.go` | 671-688 | `Proxy.addDO()` | 请求上游时设置 DO 位 |
| DNSSEC | `dnsproxy/proxy/cache.go` | 641-658 | `filterMsg()` | 根据客户端 DO/AD 过滤 DNSSEC RR 和 AD 位 |
| DNSSEC | `dnsproxy/proxy/cache.go` | 617-639 | `filterRRSlice()` | 具体的 RR 过滤逻辑 |
| DNSSEC | `dnsproxy/proxy/cache.go` | 536-552 | `msgToKey()` | 缓存 key 包含 DO 位 |
| DNSSEC | `dnsproxy/proxy/proxy.go` | 741-744 | `Resolve()` 内缓存写入条件 | CD 位为 1 时不写缓存 |
| DNSSEC | `dnsproxy/proxy/proxy.go` | 805-816 | `cacheWorks()` | CD 位为 1 时不读缓存 |
| 私有 RDNS | `dnsproxy/proxy/server.go` | 123-150 | `DNSContext.isForbiddenARPA()` | 入口识别私有 ARPA 请求，设置 `RequestedPrivateRDNS` |
| 私有 RDNS | `dnsproxy/proxy/proxy.go` | 760-784 | `Proxy.validateRequest()` | 公网客户端请求私有 ARPA 直接返回 NXDOMAIN |
| 私有 RDNS | `dnsproxy/proxy/proxy.go` | 549-562 | `Proxy.selectUpstreams()` | 私有 RDNS 分支，返回 `isPrivate=true` |
| 私有 RDNS | `dnsproxy/proxy/proxy.go` | 581-621 | `Proxy.replyFromUpstream()` | `!isPrivate` 条件锁死 fallback 路径 |
| 私有 RDNS | `dnsproxy/proxy/proxy.go` | 805-808 | `cacheWorks()` | 私有 RDNS 请求不缓存 |
| 混合健康度 | `dnsproxy/upstream/plain.go` | 76-85 | `plainDNS.Address()` | UDP 返回 `Host`（"1.1.1.1"），TCP 返回完整 URL |
| 混合健康度 | `dnsproxy/upstream/dot.go` | 89 | `dnsOverTLS.Address()` | 返回 `tls://host:853` |
| 混合健康度 | `dnsproxy/upstream/doh.go` | 151 | `dnsOverHTTPS.Address()` | 返回脱敏后的 `https://...` URL |
| 混合健康度 | `dnsproxy/upstream/doq.go` | 167 | `dnsOverQUIC.Address()` | 返回 `quic://host:853` |
| 混合健康度 | `dnsproxy/proxy/exchange.go` | 75-105 | `Proxy.exchange()` | 计时包含全部协议开销，更新 RTT |
| 混合健康度 | `dnsproxy/proxy/exchange.go` | 127-146 | `Proxy.calcWeights()` | 用算术平均 RTT 计算权重 |
| 混合健康度 | `dnsproxy/upstream/dot.go` | 92-132 | `dnsOverTLS.Exchange()` | 内部重试逻辑，失败后重建连接 |
| 混合健康度 | `dnsproxy/upstream/doh.go` | 154-202 | `dnsOverHTTPS.Exchange()` | 内部重试，最多 resetClient 两次 |
| 混合健康度 | `dnsproxy/upstream/doq.go` | 170-223 | `dnsOverQUIC.Exchange()` | 内部重试，缓存连接坏了重建 |

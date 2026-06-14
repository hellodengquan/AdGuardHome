# DNS 上游分配（Upstream Dispatch）代码路径详解

本文档按代码执行顺序，详细解析 AdGuard Home 中 DNS 请求如何按策略分配到不同上游服务器的完整路径。

---

## 整体架构概览

DNS 上游分配涉及两个主要层级：

1. **dnsforward 层**（AdGuard Home 内部）- 负责请求处理流水线、客户端识别、自定义上游注入
2. **dnsproxy 层**（外部库 `github.com/AdguardTeam/dnsproxy`）- 负责核心的上游选择、域名匹配、负载均衡/并行查询

---

## 第一层：dnsforward 包 - 请求进入与预处理

### 1.1 入口：`Server.ServeDNS`

**文件**：`internal/dnsforward/requesthandler.go:18`

DNS 请求进入 AdGuard Home 的第一站。实现了 `proxy.Handler` 接口，被 dnsproxy 在接收到 DNS 请求后回调。

```go
func (s *Server) ServeDNS(ctx context.Context, _ *proxy.Proxy, pctx *proxy.DNSContext) (err error)
```

请求经过一个模块化处理链（mods），按顺序执行：

| 序号 | 处理模块 | 作用 |
|------|----------|------|
| 1 | `processInitial` | 初始处理：客户端 IP、ClientID、过滤设置 |
| 2 | `processDDRQuery` | DDR（Discovery of Designated Resolvers）查询 |
| 3 | `processDHCPHosts` | DHCP 主机名本地解析 |
| 4 | `processDHCPAddrs` | DHCP 地址 PTR 本地解析 |
| 5 | `processFilteringBeforeRequest` | 请求前过滤（广告、恶意域名等） |
| 6 | **`processUpstream`** | **上游转发（核心分配逻辑入口）** |
| 7 | `processFilteringAfterResponse` | 响应后过滤 |
| 8 | `ipset.process` | ipset 处理 |
| 9 | `processQueryLogsAndStats` | 查询日志与统计 |

每个模块返回 `resultCode`：
- `resultCodeSuccess` → 继续下一个模块
- `resultCodeFinish` → 终止处理，直接返回
- `resultCodeError` → 终止处理，返回错误

---

### 1.2 核心入口：`processUpstream`

**文件**：`internal/dnsforward/process.go:441`

进入上游转发阶段的入口函数，按以下顺序进行分支判断：

```
processUpstream
├─ 分支1：响应已存在？
│   └─ 是 → 直接跳过，返回 resultCodeSuccess
│
├─ 分支2：是 DHCP 主机名查询？
│   └─ 是 → 返回 NXDOMAIN，终止处理
│
├─ 步骤3：设置自定义上游（setCustomUpstream）
│
└─ 步骤4：调用 prx.Resolve(ctx, pctx) → 进入 dnsproxy 层
```

**分支1 - 响应已存在**：
如果前面的模块（如过滤、DHCP）已经生成了响应，直接跳过上游查询。

**分支2 - DHCP 主机名**：
如果是本地域名查询（如 `*.lan`）且没有匹配到 DHCP 记录，直接返回 NXDOMAIN，不转发到上游。

---

### 1.3 自定义上游注入：`setCustomUpstream`

**文件**：`internal/dnsforward/process.go:516`

为特定客户端注入自定义上游配置：

```
setCustomUpstream
├─ 检查：客户端地址有效？ClientsContainer 存在？
│   └─ 否 → 直接返回
│
├─ 查找客户端（优先 ClientID，其次 IP）
│   └─ 调用 s.conf.ClientsContainer.CustomUpstreamConfig(clientID, cliAddr)
│
└─ 找到自定义配置？
    └─ 是 → 设置 pctx.CustomUpstreamConfig = upsConf
```

查找逻辑在 `internal/client/storage.go:730`：
1. 先按 `ClientID` 在持久化客户端索引中查找
2. 没找到则按 IP 地址查找
3. 找到后通过 `upstreamManager.customUpstreamConfig(c.UID, c.Name)` 获取或懒加载自定义上游配置

自定义上游配置包含：
- 独立的上游列表（支持域名特定上游）
- 可选的独立缓存
- 独立的 EDNS Client Subnet 配置

---

## 第二层：dnsproxy 包 - 核心上游分配

### 2.1 解析入口：`Proxy.Resolve`

**文件**：`dnsproxy/proxy/proxy.go:695`

dnsproxy 的核心解析方法，完整流程：

```
Resolve
├─ 步骤1：处理 EDNS Client Subnet（如果启用）
│
├─ 步骤2：计算标志和 UDP 大小
│
├─ 步骤3：缓存检查（如果缓存启用）
│   ├─ 检查是否命中缓存
│   └─ 命中 → 直接返回缓存结果
│
├─ 步骤4：从上游获取响应（replyFromUpstream）⭐
│
├─ 步骤5：缓存响应（如果缓存启用且成功）
│
├─ 步骤6：过滤 DNSSEC 标志等
│
└─ 步骤7：整理响应（scrub）
```

---

### 2.2 上游交换总控：`replyFromUpstream`

**文件**：`dnsproxy/proxy/proxy.go:583`

控制整个上游交换和回退流程：

```
replyFromUpstream
├─ 步骤1：选择上游列表（selectUpstreams）⭐⭐
│
├─ 分支1：上游列表为空？
│   └─ 是 → 返回 NXDOMAIN + ErrNoUpstreams 错误
│
├─ 分支2：是私有上游？
│   └─ 是 → 添加递归检测
│
├─ 步骤3：主上游交换（exchangeUpstreams）⭐
│
├─ 步骤4：DNS64 合成处理（如果启用且需要）
│
├─ 步骤5：Bogus NXDOMAIN 检查
│   └─ 响应 IP 在 Bogus 列表 → 替换为 NXDOMAIN
│
├─ 分支6：主上游失败 且 有 Fallback 且 不是私有查询？
│   └─ 是 → Fallback 回退：
│       ├─ 从 Fallbacks 配置按域名选择上游
│       └─ 并行查询所有 fallback 上游
│
└─ 步骤7：处理交换结果（handleExchangeResult）
```

**Fallback 回退机制**：
- 仅主上游全部失败时触发
- 私有 PTR 查询不使用 Fallback
- Fallback 上游同样支持域名特定配置
- Fallback 使用并行查询策略（`upstream.ExchangeParallel`）

---

### 2.3 核心策略：`selectUpstreams` ⭐⭐⭐

**文件**：`dnsproxy/proxy/proxy.go:549`

**这是上游分配策略的核心决策函数**，按优先级从高到低选择上游配置：

```
selectUpstreams
│
├─ 分支1：私有 PTR / DNS64 请求？
│   │
│   ├─ 条件：d.RequestedPrivateRDNS != 空 或 p.shouldStripDNS64(req)
│   │
│   ├─ 子条件：UsePrivateRDNS && IsPrivateClient && 私有配置 != nil
│   │   └─ 是 → 使用 PrivateRDNSUpstreamConfig.getUpstreamsForDomain(host)
│   │
│   └─ 返回：isPrivate = true
│
├─ 前置：确定域名匹配方法
│   ├─ DS 查询类型 → 使用 getUpstreamsForDS（去掉首标签匹配）
│   └─ 其他 → 使用 getUpstreamsForDomain
│
├─ 分支2：有自定义上游配置？
│   │
│   ├─ 条件：d.CustomUpstreamConfig != nil
│   │
│   ├─ 从自定义配置按域名查找上游
│   │
│   └─ 找到非空列表 → 直接返回自定义上游
│
└─ 分支3：使用默认上游配置
    └─ p.UpstreamConfig.getUpstreamsForDomain(host)
```

#### 分支1 - 私有上游

**触发条件**：
- `RequestedPrivateRDNS` 非空：即请求是针对私有 IP 的 PTR/SOA/NS 查询（ARPA 域名）
- 或 DNS64 需要剥离前缀的查询

**额外条件**：
- `UsePrivateRDNS` 配置已启用
- 客户端是私有客户端（`IsPrivateClient`）
- `PrivateRDNSUpstreamConfig` 不为 nil

用途：本地 PTR 解析、内网 DNS 解析。

#### 分支2 - 自定义上游

优先级高于全局默认上游。每个客户端可以有自己独立的上游配置，同样支持域名特定上游。

如果自定义配置中找不到匹配的上游，会**降级**到全局默认上游。

#### 分支3 - 默认上游

使用全局配置的 `UpstreamConfig`，这是最常用的路径。

---

### 2.4 域名匹配策略：`getUpstreamsForDomain` ⭐⭐

**文件**：`dnsproxy/proxy/upstreams.go:382`

根据域名从上游配置中选择对应的上游列表。支持精确匹配、通配符子域匹配、逐级向上匹配。

```
getUpstreamsForDomain(fqdn)
│
├─ 快速路径：DomainReservedUpstreams 为空？
│   └─ 是 → 直接返回默认 Upstreams
│
├─ 步骤1：子域排除检查
│   │
│   ├─ fqdn 在 SubdomainExclusions 中？
│   │   └─ 是 → 调用 lookupSubdomainExclusion(fqdn)
│   │       ├─ 先查 SpecifiedDomainUpstreams[fqdn] 精确匹配
│   │       ├─ 没找到 → 查上一级 DomainReservedUpstreams
│   │       └─ 都没有 → 返回默认 Upstreams
│   │
│   └─ 命中 → 直接返回结果
│
├─ 步骤2：精确匹配查找
│   │
│   ├─ lookupUpstreams(fqdn)
│   │   ├─ 在 DomainReservedUpstreams 中查找
│   │   ├─ 找到且列表非空 → 返回该列表
│   │   └─ 找到但列表为空（被排除）→ 返回默认 Upstreams
│   │
│   └─ 命中 → 直接返回结果
│
├─ 步骤3：逐级向上匹配（循环）
│   │
│   ├─ 去掉第一个标签（最左边的）
│   ├─ 如果只剩单标签（非标准域名）→ 使用 UnqualifiedNames 作为键
│   ├─ 调用 lookupUpstreams 尝试匹配
│   ├─ 命中 → 返回结果
│   └─ 继续去掉下一个标签，直到 fqdn 为空
│
└─ 步骤4：都没找到 → 返回默认 Upstreams
```

#### 匹配优先级（从高到低）

1. **精确域名匹配**（SpecifiedDomainUpstreams）- 如 `www.example.com.`
2. **子域通配排除**（SubdomainExclusions + 上级保留）- 如 `[/*.example.com/]` 只匹配子域
3. **域名保留匹配**（DomainReservedUpstreams）- 如 `example.com.` 匹配自身及所有子域
4. **逐级向上匹配** - 找不到时往父域找
5. **默认上游**（Upstreams）- 兜底

#### 配置语法示例

```
# 默认上游
1.1.1.1
8.8.8.8

# 保留域：所有 example.com 及其子域走这个上游
[/example.com/]2.2.2.2

# 指定域：只有 www.example.com 走这个上游
[/www.example.com/]3.3.3.3

# 仅子域：*.example.com 走这个，但 example.com 本身不走
[/*.example.com/]4.4.4.4

# 排除域：maps.example.com 走默认上游
[/maps.example.com/]#

# 单标签域名（不合格域名）走专用上游
[/ /]5.5.5.5
```

---

### 2.5 DS 查询特殊处理：`getUpstreamsForDS`

**文件**：`dnsproxy/proxy/upstreams.go:422`

对于 DS（Delegation Signer）记录查询，匹配时去掉第一个标签。

原因：DS 记录出现在父域，用于验证子域的 DNSKEY。例如查询 `sub.example.com` 的 DS 记录，应该在 `example.com` 的上游查询。

---

### 2.6 上游交换模式：`exchangeUpstreams` ⭐

**文件**：`dnsproxy/proxy/exchange.go:17`

选好上游列表后，根据配置的上游模式执行实际的 DNS 查询。

```
exchangeUpstreams(req, ups)
│
├─ 模式1：并行模式（UpstreamModeParallel）
│   └─ upstream.ExchangeParallel(ups, req)
│      所有上游同时发送请求，返回第一个成功的响应
│
├─ 模式2：最快地址模式（UpstreamModeFastestAddr）
│   ├─ 仅 A / AAAA 查询类型生效
│   ├─ p.fastestAddr.ExchangeFastest(req, ups)
│   │   （所有上游查询，然后对返回的 IP 进行 ping/TCP 测速，选最快的）
│   └─ 非 A/AAAA 查询 → 降级到负载均衡模式
│
└─ 模式3：负载均衡模式（UpstreamModeLoadBalance）- 默认
    │
    ├─ 只有 1 个上游 → 直接使用
    │
    └─ 多个上游 → 加权随机选择
        ├─ 基于历史 RTT 计算权重：weight = 1 / avgRTT
        ├─ 使用 sampleuv.NewWeighted 加权随机采样
        ├─ 按权重顺序依次尝试
        ├─ 成功 → 更新该上游的 RTT 统计，返回结果
        └─ 失败 → 尝试下一个，直到全部失败
```

#### 三种上游模式对比

| 模式 | 行为 | 适用场景 |
|------|------|----------|
| **负载均衡**（默认） | 按 RTT 加权随机，逐个尝试 | 稳定性优先，兼顾速度 |
| **并行查询** | 所有上游同时查，取最快响应 | 速度优先，上游数量不宜过多 |
| **最快地址** | A/AAAA 查询额外对 IP 测速 | 对响应速度要求极高的场景 |

---

### 2.7 上游配置结构：`UpstreamConfig`

**文件**：`dnsproxy/proxy/upstreams.go:26`

```go
type UpstreamConfig struct {
    // 保留域上游：域名本身及所有子域使用这些上游
    DomainReservedUpstreams map[string][]upstream.Upstream
    
    // 指定域上游：精确匹配该域名才使用
    SpecifiedDomainUpstreams map[string][]upstream.Upstream
    
    // 子域排除集合：这些域名仅子域匹配，自身不匹配
    SubdomainExclusions *container.MapSet[string]
    
    // 默认上游：兜底使用
    Upstreams []upstream.Upstream
}
```

---

## 完整调用链总结

```
DNS 请求到达
    │
    ▼
[dnsproxy] 接收请求（UDP/TLS/HTTPS/QUIC/DNSCrypt）
    │
    ▼
[dnsforward] Server.ServeDNS  ← 实现 proxy.Handler 接口
    │
    ├─ processInitial          ← 客户端识别、过滤设置
    ├─ processDDRQuery         ← DDR 查询
    ├─ processDHCPHosts        ← DHCP 主机名本地解析
    ├─ processDHCPAddrs        ← DHCP 地址 PTR 本地解析
    ├─ processFilteringBeforeRequest  ← 广告/恶意域名过滤
    │
    └─ processUpstream         ← 进入上游转发
         │
         ├─ setCustomUpstream  ← 客户端自定义上游注入（按 ClientID/IP）
         │
         └─ prx.Resolve()      ← 回到 dnsproxy 层
              │
              ├─ 缓存检查（可选）
              │
              └─ replyFromUpstream
                   │
                   ├─ selectUpstreams  ⭐⭐⭐ 上游选择决策
                   │    ├─ 私有 PTR/DNS64？→ PrivateRDNSUpstreamConfig
                   │    ├─ 有自定义上游？  → CustomUpstreamConfig
                   │    └─ 否则           → UpstreamConfig（默认）
                   │         │
                   │         └─ getUpstreamsForDomain  ⭐⭐ 域名匹配
                   │              ├─ 精确匹配
                   │              ├─ 子域排除
                   │              ├─ 逐级向上匹配
                   │              └─ 默认上游兜底
                   │
                   ├─ exchangeUpstreams  ⭐ 上游交换模式
                   │    ├─ 并行模式
                   │    ├─ 最快地址模式
                   │    └─ 负载均衡模式（默认，加权随机）
                   │
                   ├─ DNS64 合成（可选）
                   ├─ Bogus NXDOMAIN 检查
                   │
                   └─ 失败？→ Fallback 回退（并行查询）
                        └─ 同样按域名匹配 Fallback 上游
              │
              ├─ 缓存响应（可选）
              └─ 返回结果
    │
    ├─ processFilteringAfterResponse  ← 响应后过滤
    ├─ ipset.process            ← ipset 处理
    └─ processQueryLogsAndStats ← 日志统计
```

---

## 关键文件索引

### AdGuard Home 内部

| 文件 | 作用 |
|------|------|
| `internal/dnsforward/requesthandler.go` | 请求入口 `ServeDNS`、处理链 |
| `internal/dnsforward/process.go` | 各处理模块实现，含 `processUpstream`、`setCustomUpstream` |
| `internal/dnsforward/upstreams.go` | 上游配置创建、bootstrap、私有配置 |
| `internal/dnsforward/config.go` | 代理配置构建 `newProxyConfig` |
| `internal/dnsforward/clientscontainer.go` | 客户端容器接口 |
| `internal/client/storage.go` | 客户端存储，`CustomUpstreamConfig` 实现 |
| `internal/client/upstreammanager.go` | 客户端上游管理器 |

### dnsproxy 外部库

| 文件 | 作用 |
|------|------|
| `proxy/proxy.go` | `Resolve`、`replyFromUpstream`、`selectUpstreams` |
| `proxy/upstreams.go` | `UpstreamConfig`、`ParseUpstreamsConfig`、`getUpstreamsForDomain` |
| `proxy/exchange.go` | `exchangeUpstreams`、负载均衡权重计算 |
| `proxy/upstreammode.go` | 上游模式枚举定义 |
| `proxy/dnscontext.go` | `DNSContext`、`CustomUpstreamConfig` |

---

## 附录 A：上游失败回退策略详解

### A.1 回退决策流程

**文件**：`dnsproxy/proxy/proxy.go:583` (`replyFromUpstream`)

当所有主上游同时失败时，系统按以下流程进行回退决策：

```
主上游交换失败
    │
    ▼
┌─ 分支判断 ─────────────────────────────────────┐
│                                               │
│  1. 是私有查询（isPrivate == true）？          │
│     └─ 是 → 不回退，直接失败                   │
│                                               │
│  2. Fallbacks 配置为空（p.Fallbacks == nil）？ │
│     └─ 是 → 不回退，直接失败                   │
│                                               │
└─ 否 → 进入 Fallback 回退流程 ──────────────────┘
    │
    ▼
┌─ Fallback 回退流程 ────────────────────────────┐
│                                               │
│  步骤1：按域名匹配 Fallback 上游               │
│         p.Fallbacks.getUpstreamsForDomain(...) │
│         （与主上游使用完全相同的域名匹配规则） │
│                                               │
│  步骤2：并行查询所有 Fallback 上游             │
│         upstream.ExchangeParallel(...)         │
│         所有上游同时发送，返回第一个成功响应   │
│                                               │
└─ 成功？────────────────────────────────────────┘
    │
    ├─ 是 → 返回 Fallback 响应
    │
    └─ 否 → 所有 Fallback 也失败
         │
         ▼
      生成 SERVFAIL 响应
```

### A.2 最终响应码：SERVFAIL vs NXDOMAIN

**文件**：`dnsproxy/proxy/proxy.go:643` (`handleExchangeResult`)

| 场景 | 响应码 | 触发条件 |
|------|--------|----------|
| **上游列表为空** | NXDOMAIN | `selectUpstreams` 返回空列表（如私有上游配置错误） |
| **所有上游（含 Fallback）失败** | **SERVFAIL** | 主上游全失败 + Fallback 全失败 |
| **Bogus NXDOMAIN** | NXDOMAIN | 响应 IP 在 Bogus NXDOMAIN 列表中 |

**关键代码**：
```go
func (p *Proxy) handleExchangeResult(...) {
    if resp == nil {
        // 所有上游都失败时，生成 SERVFAIL
        d.Res = p.messages.NewMsgSERVFAIL(req)
        d.hasEDNS0 = false
        return
    }
    // ...
}
```

**运营结论**：
- ✅ 配置了 Fallback DNS 时，**优先切换到 Fallback**
- ❌ Fallback 也失败时，**返回 SERVFAIL**，而非 NXDOMAIN
- ⚠️ 私有 PTR 查询不触发 Fallback，直接失败

### A.3 错误聚合与日志

**文件**：`dnsproxy/proxy/exchange.go:67`

当多个上游失败时，错误信息会被聚合：
```go
err = fmt.Errorf("all upstreams failed to exchange request: %w",
    errors.Join(errs...))
```

每个失败的上游都会记录错误日志（Error 级别）：
```
exchange failed  upstream=1.1.1.1:53  question=example.com. A
  duration=2.001s  error="dial udp 1.1.1.1:53: i/o timeout"
```

---

## 附录 B：加密协议（DoH/DoT/DoQ）分流路径分析

### B.1 入站侧：协议监听层

所有协议的监听层虽然实现不同，但最终都会汇聚到同一套处理流程。

#### UDP / TCP（明文）

| 协议 | 监听入口 | 处理函数 | 汇聚点 |
|------|----------|----------|--------|
| UDP | `udpPacketLoop` | `udpHandlePacket` | `handleDNSRequest` |
| TCP | `tcpPacketLoop(proto=ProtoTCP)` | `handleTCPConnection` | `handleDNSRequest` |

#### DoT（DNS-over-TLS）

**文件**：`dnsproxy/proxy/servertcp.go:66` (`initTLSListeners`)

DoT 复用 TCP 的处理框架，仅在监听时包装 TLS：
```go
l := tls.NewListener(tcpListen, p.TLSConfig)  // TLS 包装
tcpPacketLoop(proto=ProtoTLS)                // 复用 TCP 循环
handleTCPConnection(proto=ProtoTLS)          // 复用 TCP 连接处理
```

#### DoH（DNS-over-HTTPS）

**文件**：`dnsproxy/proxy/serverhttps.go:187` (`ServeHTTP`)

DoH 有独立的 HTTP 服务器，但最终同样汇聚：
```
HTTP 请求到达
    │
    ▼
ServeHTTP
    ├─ 基础认证检查（可选）
    ├─ 解析 DNS 请求（GET/POST 两种方式）
    ├─ 提取真实客户端 IP（X-Forwarded-For 等）
    ├─ newDNSContext(ProtoHTTPS)
    └─ handleDNSRequest  ← 同一汇聚点
```

支持的 HTTP 版本：HTTP/1.1、HTTP/2、HTTP/3（h3:// 前缀）

#### DoQ（DNS-over-QUIC）

**文件**：`dnsproxy/proxy/serverquic.go:123` (`quicPacketLoop`)

DoQ 使用 QUIC 协议，有独立的连接和流处理：
```
QUIC 连接到达
    │
    ▼
handleQUICConnection
    ├─ 接受 QUIC 流（每个查询一个流）
    ├─ 解析 DNS 请求（带 2 字节长度前缀）
    ├─ newDNSContext(ProtoQUIC)
    └─ handleDNSRequest  ← 同一汇聚点
```

### B.2 汇聚点：`handleDNSRequest`

**文件**：`dnsproxy/proxy/requesthandler.go:13`

所有协议经过各自的监听层解析后，都会调用：
```go
func (p *Proxy) handleDNSRequest(ctx context.Context, d *DNSContext) (err error)
```

`handleDNSRequest` 的处理流程：
1. 检查请求有效性
2. 检查是否是递归查询（Recursion Desired）
3. 调用 `p.RequestHandler.ServeDNS(ctx, p, d)`
   - **这会回调到 AdGuard Home 的 `dnsforward.Server.ServeDNS`**
4. 调用 `respondUDP/TCP/HTTPS/QUIC` 按原协议发送响应

### B.3 分流路径一致性验证

**结论：所有入站协议共享完全相同的上游分流逻辑**

```
[UDP]  ──┐
[TCP]  ──┤
[DoT]  ──┤
[DoH]  ──┼─► handleDNSRequest ──► ServeDNS (dnsforward) ──► 同一套分流
[DoQ]  ──┤                            │
[DNSCrypt] ─┘                      ▼
                             处理链 + prx.Resolve
                                  │
                                  ▼
                             selectUpstreams
                             getUpstreamsForDomain
                             exchangeUpstreams
                                  │
                                  ▼
                             上游协议（UDP/TCP/DoT/DoH/DoQ）
```

### B.4 出站侧：上游协议多样性

虽然入站分流逻辑统一，但出站上游可以是任意协议类型：

| 上游协议 | URL 前缀 | 实现文件 |
|----------|----------|----------|
| 明文 UDP | `udp://` 或无 | `upstream/plain.go` |
| 明文 TCP | `tcp://` | `upstream/plain.go` |
| DoT | `tls://` | `upstream/dot.go` |
| DoH | `https://` | `upstream/doh.go` |
| DoQ | `quic://` | `upstream/doq.go` |
| DNSCrypt | `sdns://` | `upstream/dnscrypt.go` |

所有上游类型都实现了相同的 `Upstream` 接口：
```go
type Upstream interface {
    Exchange(req *dns.Msg) (resp *dns.Msg, err error)
    Address() string
    Close() error
}
```

因此分流逻辑（按域名选择哪个上游列表）与上游实际使用的协议完全解耦。

### B.5 协议特有的行为差异

虽然分流路径统一，但不同协议在交换时有一些差异：

| 特性 | UDP | TCP | DoT | DoH | DoQ |
|------|-----|-----|-----|-----|-----|
| 连接复用 | ❌ | ✅ | ✅ | ✅ | ✅ |
| 自动重试 | ✅（TCP 回退） | ❌ | ❌ | ❌ | ❌ |
| 超时控制 | 独立 | 独立 | 独立 | 独立 | 独立 |
| EDNS0 支持 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 管道化请求 | ❌ | ✅ | ✅ | ✅ | ✅ |

**注意**：明文 UDP 上游在响应被截断（TC=1）时，会自动回退到 TCP 重试。

---

## 附录 C：健康检查与负载均衡实现细节

### C.1 健康检查机制

**重要结论：AdGuard Home 没有主动健康检查**

系统采用**被动故障检测**机制，而非主动探活。

#### 被动故障检测原理

1. **正常请求作为探测**：每个发往上有的 DNS 查询同时也是一次健康检测
2. **失败即标记**：如果查询超时或失败，该上游被视为"不健康"
3. **RTT 加权降级**：失败的上游会被记录一个较大的 RTT（默认超时时间），从而降低其被选中的概率

**文件**：`dnsproxy/proxy/exchange.go:53-64`

```go
resp, elapsed, err = p.exchange(u, req)
if err == nil {
    // 成功：更新实际 RTT
    p.updateRTT(u.Address(), elapsed)
    return resp, u, nil
}

// 失败：用默认超时时间更新 RTT，降低权重
p.updateRTT(u.Address(), defaultTimeout)
```

`defaultTimeout` 为 10 秒（硬编码），远大于正常 RTT，因此失败的上游权重会急剧下降。

#### 无主动探活的影响

| 优点 | 缺点 |
|------|------|
| 无需额外带宽 | 故障检测依赖实际请求，可能导致用户请求失败 |
| 实现简单 | 静默故障（上游不响应但连接正常）检测慢 |
| 反映真实用户体验 | 无流量时无法检测故障 |

### C.2 负载均衡算法详解

#### 负载均衡模式（默认）

**文件**：`dnsproxy/proxy/exchange.go:47`

算法核心：**基于历史 RTT 的加权随机采样**

```go
w := sampleuv.NewWeighted(p.calcWeights(ups), p.randSrc)
for i, ok := w.Take(); ok; i, ok = w.Take() {
    // 按权重从高到低依次尝试
}
```

#### 权重计算公式

**文件**：`dnsproxy/proxy/exchange.go:129` (`calcWeights`)

```
对于每个上游 u：
    如果没有历史统计（rttSum == 0 或 reqNum == 0）：
        weight = 1.0  // 默认权重
    否则：
        avgRTT = rttSum / reqNum           // 平均响应时间（微秒）
        weight = 1.0 / avgRTT              // 权重与平均 RTT 成反比
```

**示例**：
- 上游 A：平均 RTT = 10ms → 权重 = 1/10000 = 0.0001
- 上游 B：平均 RTT = 50ms → 权重 = 1/50000 = 0.00002
- 上游 C：刚失败 → RTT = 10000ms → 权重 = 1/10000000 = 0.0000001

归一化后的选择概率：
- A: 0.0001 / 0.0001201 ≈ **83.3%**
- B: 0.00002 / 0.0001201 ≈ **16.6%**
- C: 0.0000001 / 0.0001201 ≈ **0.1%**

#### RTT 统计结构

**文件**：`dnsproxy/proxy/exchange.go:107`

```go
type upstreamRTTStats struct {
    rttSum float64  // 所有 RTT 之和（微秒）
    reqNum float64  // 请求次数
}
```

统计是**累积式**的，没有滑动窗口或过期机制。随着时间推移，新的 RTT 样本会逐渐稀释旧样本的影响。

#### 故障转移行为

在负载均衡模式下，故障转移是**自动且渐进**的：

```
上游 A 故障（超时）
    │
    ▼
updateRTT(A, 10000ms)  ← 权重急剧下降
    │
    ▼
下一次请求：
    calcWeights() → A 的权重远低于其他上游
    w.Take() → 大概率选择其他上游
    │
    ├─ 其他上游成功 → 正常响应
    │
    └─ 所有上游都失败 → 按权重顺序逐个尝试
        │
        ├─ 尝试 1：权重最高的上游（最可能成功）
        ├─ 尝试 2：次高权重的上游
        └─ ... 直到全部失败
```

#### 并行查询模式

**文件**：`dnsproxy/upstream/parallel.go:24` (`ExchangeParallel`)

```go
func ExchangeParallel(ups []Upstream, req *dns.Msg) (...) {
    resCh := make(chan any, upsNum)
    for _, f := range ups {
        go exchangeAsync(f, copyReq, resCh)  // 所有上游同时发送
    }

    for range ups {
        r, err := receiveAsyncResult(resCh)
        if err == nil {
            return r.Resp, r.Upstream, nil  // 返回第一个成功的
        }
    }
    // 全部失败
}
```

**行为特点**：
- ✅ 延迟最低：取第一个成功响应
- ❌ 带宽消耗大：N 个上游就有 N 倍流量
- ⚠️ 失败检测慢：需要等待所有上游都失败才返回错误
- ✅ 无故障转移延迟：同时发送，无需等待超时

#### 最快地址模式

仅适用于 A/AAAA 查询，在负载均衡模式的基础上额外增加 IP 连通性检测：

```
1. 并行查询所有上游，获取所有 IP 结果
2. 对每个返回的 IP 地址进行 TCP ping（80 端口）
3. 选择 RTT 最低的 IP 对应的响应
4. 非 A/AAAA 查询降级到负载均衡模式
```

### C.3 故障恢复机制

由于是被动检测，故障恢复同样是**渐进式**的：

```
上游 A 恢复正常
    │
    ▼
某次请求（低概率）选中了 A
    │
    ▼
查询成功，elapsed = 15ms
    │
    ▼
updateRTT(A, 15ms)  ← 权重开始回升
    │
    ▼
后续请求中 A 的权重逐渐恢复到正常水平
```

**恢复速度**取决于该上游被选中的频率，通常需要几次成功查询才能完全恢复权重。

### C.4 运营建议

| 场景 | 建议配置 | 原因 |
|------|----------|------|
| 上游可靠性高 | 负载均衡模式（默认） | 兼顾稳定性和带宽 |
| 上游可靠性差 | 并行查询模式 + 少量上游（2-3个） | 降低故障影响 |
| 对延迟极度敏感 | 最快地址模式（仅 A/AAAA） | 额外 IP 测速开销 |
| 上游数量 ≥ 4 | 负载均衡模式 | 并行模式带宽开销过大 |
| 关键业务 | 配置 Fallback 上游 | 主上游全挂时兜底 |
| 不同上游质量差异大 | 负载均衡模式 | RTT 加权自动优选 |

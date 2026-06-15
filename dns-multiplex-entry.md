# DNS 多协议整合：统一查询入口架构分析

## 1. 概述

AdGuardHome 通过 **"监听层多路复用 + 处理层统一入口"** 的架构设计，将多种 DNS 协议（UDP、TCP、TLS、HTTPS、QUIC、DNSCrypt）整合为统一的查询处理链路。其核心思想是：

- **监听层**：由 `dnsproxy/proxy` 库负责不同协议的网络监听器实现，将各种协议的数据帧统一解析为标准的 `*proxy.DNSContext` 对象
- **处理层**：由 `dnsforward.Server` 实现统一的 `ServeDNS()` 入口，通过中间件链和模块化处理管道完成所有 DNS 查询处理

```
┌───────────────────────────────────────────────────────────────────┐
│                        客户端请求                                 │
│  (UDP/TCP/DoT/DoH/DoQ/DNSCrypt)                                   │
└──────────────────────┬────────────────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────────────────┐
│                     监听层 (dnsproxy/proxy)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │UDP Listener│TCP Listener│TLS Listener│HTTPS Listener│QUIC/DNSCrypt││
│  └─────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬────┘ └────┬────┘  │
│        └────────────┴────────────┴──────────────┴───────────┘       │
│                              │                                       │
│                        统一封装为 *proxy.DNSContext                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────────┐
│                   中间件层 (Middleware Chain)                       │
│  Ratelimit → Logging → ClientID/Access → 核心 Handler              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────────┐
│                  统一处理入口 ServeDNS()                            │
│     模块化处理管道 (Processing Pipeline)                            │
└───────────────────────────────────────────────────────────────────┘
```

---

## 2. 监听层：多协议监听器的实现与配置

### 2.1 核心依赖：dnsproxy/proxy 库

AdGuardHome 自身不直接实现各协议的底层监听，而是委托给 `github.com/AdguardTeam/dnsproxy/proxy` 库。该库提供了统一的代理抽象，支持以下 6 种 DNS 协议：

| 协议 | 常量标识 | 传输层 | 默认端口 |
|------|---------|--------|---------|
| Plain DNS over UDP | `proxy.ProtoUDP` | UDP | 53 |
| Plain DNS over TCP | `proxy.ProtoTCP` | TCP | 53 |
| DNS-over-TLS (DoT) | `proxy.ProtoTLS` | TCP+TLS | 853 |
| DNS-over-HTTPS (DoH) | `proxy.ProtoHTTPS` | HTTP/1.1 or HTTP/2 | 443 |
| DNS-over-QUIC (DoQ) | `proxy.ProtoQUIC` | QUIC (UDP) | 853 |
| DNSCrypt | `proxy.ProtoDNSCrypt` | UDP/TCP + NaCl | 配置指定 |

### 2.2 监听器配置入口：`newProxyConfig()`

所有监听地址在 `internal/dnsforward/config.go:331` 的 `newProxyConfig()` 函数中统一组装到 `proxy.Config` 结构体：

```go
func (s *Server) newProxyConfig(ctx context.Context) (conf *proxy.Config, err error) {
    // ... 创建 proxy.Config 基础配置

    // 步骤1: 配置 TLS 加密协议监听器 (DoT, DoQ, DNSCrypt)
    err = s.prepareTLS(ctx, conf)

    // 步骤2: 配置 Plain DNS 监听器 (UDP, TCP)
    err = s.preparePlain(ctx, conf)

    // 步骤3: DoH 通过 HTTPConfig 配置
    httpConf := &proxy.HTTPConfig{
        ServerHeader:    aghhttp.UserAgent(),
        InsecureEnabled: s.conf.TLSAllowUnencryptedDoH,
    }
    conf.HTTPConfig = httpConf
}
```

### 2.3 各协议监听地址的配置流程

#### 2.3.1 Plain DNS (UDP/TCP)

在 `internal/dnsforward/config.go:812` 的 `preparePlain()` 方法中配置：

```go
func (s *Server) preparePlain(ctx context.Context, proxyConf *proxy.Config) (err error) {
    if s.conf.ServePlainDNS {
        // 从 ServerConfig 中提取 UDP/TCP 监听地址
        proxyConf.UDPListenAddr = s.conf.UDPListenAddrs  // []*net.UDPAddr
        proxyConf.TCPListenAddr = s.conf.TCPListenAddrs  // []*net.TCPAddr
        return nil
    }
    // 若禁用明文 DNS，必须至少启用一种加密协议
}
```

**配置来源**：`internal/home/dns.go:283` 中由用户配置的 `bind_hosts` + `port` 转换而来：

```go
newConf = &dnsforward.ServerConfig{
    UDPListenAddrs: ipsToUDPAddrs(hosts, dnsConf.Port),  // hosts: 绑定IP列表
    TCPListenAddrs: ipsToTCPAddrs(hosts, dnsConf.Port),  // Port: 默认53
    // ...
}
```

#### 2.3.2 TLS 加密协议 (DoT / DoQ)

在 `internal/dnsforward/config.go:710` 的 `prepareTLS()` 方法中配置：

```go
func (s *Server) prepareTLS(ctx context.Context, proxyConf *proxy.Config) (err error) {
    // 首先配置 DNSCrypt
    s.prepareDNSCrypt(proxyConf)

    if s.conf.TLSConf.Cert == nil { return nil }

    // 提取 DoT (TCP+TLS) 监听地址
    proxyConf.TLSListenAddr = s.conf.TLSConf.TLSListenAddrs   // []*net.TCPAddr

    // 提取 DoQ (QUIC over UDP) 监听地址
    proxyConf.QUICListenAddr = s.conf.TLSConf.QUICListenAddrs  // []*net.UDPAddr

    // TLS 配置：证书、SNI 严格检查等
    proxyConf.TLSConfig = &tls.Config{
        GetCertificate: s.onGetCertificate,  // SNI 验证回调
        CipherSuites:   s.conf.TLSCiphers,
        MinVersion:     tls.VersionTLS12,
    }
}
```

#### 2.3.3 DNSCrypt

在 `internal/dnsforward/config.go:697` 的 `prepareDNSCrypt()` 方法中配置：

```go
func (s *Server) prepareDNSCrypt(proxyConf *proxy.Config) {
    dnsCryptConf := s.conf.TLSConf.DNSCryptConf
    if dnsCryptConf == nil { return }

    proxyConf.DNSCryptUDPListenAddr = dnsCryptConf.UDPListenAddrs
    proxyConf.DNSCryptTCPListenAddr = dnsCryptConf.TCPListenAddrs
    proxyConf.DNSCryptProviderName   = dnsCryptConf.ProviderName
    proxyConf.DNSCryptResolverCert   = dnsCryptConf.ResolverCert
}
```

#### 2.3.4 DNS-over-HTTPS (DoH)

DoH 有两种接入方式，使用不同的路径：

**方式一：独立 HTTPS 服务器（由 dnsproxy 管理）**
- 通过 `proxy.HTTPConfig.ListenAddresses` 配置独立监听端口
- 由 dnsproxy 库内部创建独立的 HTTP server

**方式二：挂载到 AdGuardHome 主 Web 服务器（推荐）**
- 通过 `registerDoHHandlers()` 将 `dnsServer`（实现了 `http.Handler`）挂载到主路由
- 代码在 `internal/home/dns.go:598`：

```go
func registerDoHHandlers(routes []string) {
    for _, route := range routes {
        // 全局 Web mux 将 /dns-query 等路径交给 dnsServer 处理
        globalContext.web.conf.mux.Handle(route, globalContext.dnsServer)
    }
}
```

- `dnsforward.Server.ServeHTTP()` 方法实现了 `http.Handler` 接口，在 `internal/dnsforward/dnsforward.go:888`：

```go
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if !s.IsRunning() { /* 错误响应 */ return }

    if prx := s.proxy(); prx != nil {
        // 委托给 dnsproxy 的 HTTP 处理器，内部会解析 DNS 请求
        // 然后同样调用 RequestHandler.ServeDNS()
        prx.ServeHTTP(w, r)
    }
}
```

### 2.4 监听器启动

配置完成后，调用 `proxy.New(proxyConfig)` 创建代理实例，然后通过 `Start()` 启动所有监听器：

```go
// internal/dnsforward/dnsforward.go:472
func (s *Server) startLocked(ctx context.Context) error {
    // dnsproxy 内部会为每种协议启动独立的 goroutine + Listener
    err := s.dnsProxy.Start(ctx)
    if err == nil { s.isRunning = true }
    return err
}
```

---

## 3. 统一入口：从多协议到单处理器

### 3.1 `proxy.DNSContext`：协议无关的数据载体

dnsproxy 库的核心设计是将所有协议接收到的数据统一封装为 `*proxy.DNSContext`。该结构体内包含：

| 字段 | 说明 |
|------|------|
| `Proto` | 请求来源协议（`ProtoUDP` / `ProtoTCP` / `ProtoTLS` 等） |
| `Addr` | 客户端地址（netip.AddrPort） |
| `Req` | 解析后的标准 DNS 请求消息（`*dns.Msg`，来自 miekg/dns 库） |
| `Res` | 响应消息（由处理器填充） |
| `CustomUpstreamConfig` | 自定义上游配置（按客户端设置） |

**统一流程**：无论哪种协议，监听器接收到原始字节数据后：
1. 解析为标准 DNS 消息（`miekg/dns.Msg`）
2. 构造 `proxy.DNSContext`，填入 `Proto` 和 `Addr`
3. 调用 `RequestHandler.ServeDNS(ctx, proxy, dnsContext)`

### 3.2 RequestHandler 注册点

在 `newProxyConfig()` 中通过 `proxy.Config.RequestHandler` 注册统一处理器：

```go
// internal/dnsforward/config.go:358
conf = &proxy.Config{
    // ...
    // 三层中间件包装 → 最终调用 s.ServeDNS()
    RequestHandler: ratelimitMw.Wrap(        // 外层: 速率限制
                      logMw.Wrap(             // 中层: 日志+上下文
                        s.Wrap(s)             // 内层: ClientID提取+访问控制
                      )
                    ),
    // ...
}
```

---

## 4. 中间件链：跨协议的横切关注点

中间件采用 **装饰器模式**，通过 `proxy.Middleware` 接口的 `Wrap(Handler) Handler` 方法层层包装，形成洋葱模型。

### 4.1 中间件接口定义

```go
type Middleware interface {
    Wrap(next Handler) Handler  // 返回一个包装了 next 的新 Handler
}

type Handler interface {
    ServeDNS(ctx context.Context, p *Proxy, d *DNSContext) error
}
```

### 4.2 三层中间件详解

#### 第一层：Rate Limit 中间件（最外层）

由 `newRatelimitMw()` 创建，位于 `internal/dnsforward/config.go:414`：

```go
func newRatelimitMw(l *slog.Logger, conf ServerConfig) (mw proxy.Middleware, err error) {
    if conf.Ratelimit == 0 {
        // 无速率限制时使用直通中间件
        return proxy.MiddlewareFunc(proxy.PassThrough), nil
    }
    // 基于客户端 IP 子网的速率限制
    rlConf := &ratelimit.Config{
        Ratelimit:     uint(conf.Ratelimit),         // 每秒请求数上限
        SubnetLenIPv4: conf.RatelimitSubnetLenIPv4,  // IPv4子网掩码
        SubnetLenIPv6: conf.RatelimitSubnetLenIPv6,  // IPv6子网掩码
    }
    return ratelimit.NewMiddleware(rlConf), nil
}
```

#### 第二层：Log 中间件

由 `newLogMiddleware()` 创建，位于 `internal/dnsforward/middleware.go:155`：

```go
func (m *logMiddleware) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
    f := func(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
        startTime := time.Now()

        // 1. 注入结构化日志属性（请求ID、Q类型、查询域名）
        attrs := []slog.Attr{
            slog.Uint64("id", uint64(dctx.Req.Id)),
            slog.String("qtype", dns.Type(q.Qtype).String()),
            slog.String("target", q.Name),
        }
        logHdlr := m.logger.Handler().WithAttrs(attrs)
        ctx = slogutil.ContextWithLogger(ctx, slog.New(logHdlr))

        // 2. 记录开始日志
        l.Log(ctx, m.lvl, "started")
        defer m.logFinished(ctx, l, startTime)  // 记录结束日志（耗时）

        // 3. 调用下一层
        return h.ServeDNS(ctx, p, dctx)
    }
    return proxy.HandlerFunc(f)
}
```

#### 第三层：Server.Wrap() 中间件（最内层、核心业务前置处理）

位于 `internal/dnsforward/middleware.go:24`，执行四项关键检查：

```go
func (s *Server) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
    f := func(ctx context.Context, p *proxy.Proxy, pctx *proxy.DNSContext) (err error) {
        // 步骤1: 从协议中提取 ClientID
        //   - DoH: 从 URL Path 提取 /dns-query/{client-id}/...
        //   - DoT/DoQ: 从 SNI (Server Name Indication) 子域名前缀提取
        //   - UDP/TCP: 不支持 ClientID (返回空)
        clientID, err := s.clientIDFromDNSContext(ctx, l, pctx)

        // 步骤2: 访问控制 - IP/ClientID 黑白名单检查
        blocked, _ := s.IsBlockedClient(pctx.Addr.Addr(), clientID)
        if blocked { return s.serveBlockedResponse(pctx) }

        // 步骤3: Host 黑名单检查（如 version.bind 等探测域名）
        blocked = s.isBlockedHost(ctx, l, pctx.Req.Question)
        if blocked { return s.serveBlockedResponse(pctx) }

        // 步骤4: 将 ClientID 注入到 context 供后续管道使用
        if clientID != "" { ctx = contextWithClientID(ctx, clientID) }

        // 进入核心处理
        return h.ServeDNS(ctx, p, pctx)
    }
    return proxy.HandlerFunc(f)
}
```

**注意**：`s.Wrap(s)` 这种写法中，被包装的 `h` 就是 `s` 本身，即最终调用 `(*Server).ServeDNS()` 方法。

---

## 5. 核心处理管道：`ServeDNS()` 统一入口

### 5.1 方法定义

位于 `internal/dnsforward/requesthandler.go:18`，是所有协议 DNS 查询的最终统一入口：

```go
func (s *Server) ServeDNS(ctx context.Context, _ *proxy.Proxy, pctx *proxy.DNSContext) (err error) {
    // 构造 dnsforward 内部的扩展上下文
    dctx := &dnsContext{
        proxyCtx:  pctx,       // dnsproxy 上下文
        result:    &filtering.Result{},
        startTime: time.Now(), // 处理开始时间
    }

    // 定义处理模块管道 - 按顺序依次执行
    mods := []modProcessFunc{
        s.processInitial,                 // 1. 初始化处理
        s.processDDRQuery,                // 2. DDR (Discovery of Designated Resolvers)
        s.processDHCPHosts,               // 3. DHCP 主机名 -> IP 解析
        s.processDHCPAddrs,               // 4. DHCP IP -> 主机名 反向解析
        s.processFilteringBeforeRequest,  // 5. 请求前过滤 (广告/恶意域名等)
        s.processUpstream,                // 6. 转发到上游 DNS 服务器
        s.processFilteringAfterResponse,  // 7. 响应后过滤 (CNAME/IP 黑名单等)
        s.ipset.process,                  // 8. ipset 处理 (Linux 防火墙联动)
        s.processQueryLogsAndStats,       // 9. 查询日志与统计
    }

    // 顺序执行管道，按需短路
    for _, process := range mods {
        r := process(ctx, l, dctx)
        switch r {
        case resultCodeSuccess: continue           // 继续下一个模块
        case resultCodeFinish:  return nil         // 提前结束
        case resultCodeError:   return dctx.err    // 出错终止
        }
    }

    if pctx.Res != nil {
        pctx.Res.Compress = true   // 启用 DNS 消息压缩
    }
    return nil
}
```

### 5.2 处理管道各模块详解

#### 模块 1: `processInitial()` - 初始化

位于 `internal/dnsforward/process.go:104`：

- **AAAA 请求丢弃**：若配置了 `AAAA Disabled`，直接返回 NODATA
- **Firefox Canary 域拦截**：`use-application-dns.net` 返回 NXDOMAIN 禁用浏览器内置 DoH
- **健康检查域**：`healthcheck.adguardhome.test` 返回空响应
- **获取 ClientID**：从 context 中取出（已由 Wrap 中间件注入）
- **获取过滤设置**：为当前客户端加载对应的过滤规则配置

#### 模块 2: `processDDRQuery()` - 自动发现加密解析器

位于 `internal/dnsforward/process.go:172`：

- 响应 `_dns.resolver.arpa.` 的 SVCB 类型查询
- 动态告知客户端服务器支持哪些加密协议（DoH/DoT/DoQ）及其端口
- 推动客户端自动升级到加密 DNS 连接

#### 模块 3: `processDHCPHosts()` - DHCP 主机名正向解析

位于 `internal/dnsforward/process.go:275`：

- 查询本地 DHCP 分配的主机名（如 `my-pc.lan`）
- 如果在 DHCP 租约中找到匹配主机名，直接返回其 IP，不转发上游
- 支持 DNS64 映射（IPv4 地址 → IPv6 映射地址）

#### 模块 4: `processDHCPAddrs()` - DHCP 地址反向解析

位于 `internal/dnsforward/process.go:345`：

- 处理私有 IP 的 PTR 反向查询
- 如果 IP 地址在 DHCP 租约中，直接返回对应的主机名

#### 模块 5: `processFilteringBeforeRequest()` - 请求前置过滤

位于 `internal/dnsforward/process.go:395`，调用 `filterDNSRequest()` 执行：

- 域名黑名单匹配
- 白名单规则检查
- SafeSearch 强制安全搜索
- CNAME/DNS 重写规则
- 家长控制/服务过滤规则

如果过滤命中且需要阻断，直接构造阻断响应（NXDOMAIN / REFUSED / 自定义 IP），跳过上游转发。

#### 模块 6: `processUpstream()` - 上游转发

位于 `internal/dnsforward/process.go:441`：

```go
func (s *Server) processUpstream(
    ctx context.Context, l *slog.Logger, dctx *dnsContext,
) (rc resultCode) {
    pctx := dctx.proxyCtx

    if pctx.Res != nil {
        // 已有响应（本地缓存、DHCP、过滤等已生成）→ 跳过
        return resultCodeSuccess
    } else if dctx.isDHCPHost {
        // DHCP 主机名未命中 → 返回 NXDOMAIN
        pctx.Res = s.NewMsgNXDOMAIN(req)
        return resultCodeFinish
    }

    // 步骤 A: 按客户端注入自定义上游配置
    s.setCustomUpstream(ctx, l, pctx, dctx.clientID)

    // 步骤 B: 委托 dnsproxy 完成实际转发（含上游选择、fallback）
    prx := s.proxy()
    if dctx.err = prx.Resolve(ctx, pctx); dctx.err != nil {
        return resultCodeError
    }

    dctx.responseFromUpstream = true
    return resultCodeSuccess
}
```

上游转发的 **四层策略决策** 过程如下：

```
客户端请求
   │
   ▼
┌────────────────────────────────────────────────────┐
│  第1层：客户端专属上游 (CustomUpstreamConfig)       │
│  调用 s.setCustomUpstream()                        │
│  从 ClientsContainer 按 clientID / IP 查询         │
│  命中 → 写入 pctx.CustomUpstreamConfig             │
└───────────────┬────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────┐
│  第2层：按 hostname 域名分流 (在 dnsproxy 内部)     │
│  proxy.UpstreamConfig 两大分发表：                  │
│   • SpecifiedDomainUpstreams: 精确匹配域名          │
│     (如: [/example.com/]1.1.1.1)                   │
│   • DomainReservedUpstreams: 子域名通配匹配         │
│     (如: [/google.com/]8.8.8.8)                    │
│  命中 → 使用匹配的上游组                            │
└───────────────┬────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────┐
│  第3层：默认上游组 + 上游模式 (UpstreamMode)        │
│  proxy.Config.UpstreamMode 决定策略：               │
│   • UpstreamModeLoadBalance: 轮询负载均衡 (默认)   │
│   • UpstreamModeParallel:    并发取最快             │
│   • UpstreamModeFastestAddr: 探测 IP 响应时延       │
└───────────────┬────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────┐
│  第4层：Fallback 兜底 (所有主上游均失败)             │
│  proxy.Config.Fallbacks                            │
│  主上游全部 Timeout / SERVFAIL → 切换 Fallback      │
└────────────────────────────────────────────────────┘
```

支持的上游模式：
  - `load_balance`：负载均衡（默认）
  - `parallel`：并行查询所有上游，取最快响应
  - `fastest_addr`：探测上游 IP 连通速度，选择最快

#### 模块 7: `processFilteringAfterResponse()` - 响应后置过滤

位于 `internal/dnsforward/process.go:542`：

- DNS 重写规则中的 CNAME 链补全
- 响应 IP 地址黑名单检查（Bogus NXDOMAIN）
- 安全浏览结果检查

#### 模块 8: `ipset.process()` - 防火墙联动

位于 `internal/dnsforward/ipset.go`：

- 将解析出的特定域名 IP 自动加入 Linux ipset 列表
- 用于与 iptables/nftables 防火墙规则联动实现流量管控

#### 模块 9: `processQueryLogsAndStats()` - 日志与统计

位于 `internal/dnsforward/stats.go:19`：

根据协议类型进行分类记录：

```go
// stats.go 中按 Proto 转换为 querylog 内部协议标识
switch pctx.Proto {
case proxy.ProtoHTTPS:
    p.ClientProto = querylog.ClientProtoDoH
case proxy.ProtoQUIC:
    p.ClientProto = querylog.ClientProtoDoQ
case proxy.ProtoTLS:
    p.ClientProto = querylog.ClientProtoDoT
case proxy.ProtoDNSCrypt:
    p.ClientProto = querylog.ClientProtoDNSCrypt
default:  // UDP / TCP
    p.ClientProto = querylog.ClientProtoPlain
}
```

1. **查询日志（Query Log）**：记录每次请求的完整上下文（客户端、域名、类型、结果、耗时、来源协议）
2. **统计（Stats）**：按域名、客户端、阻止类型聚合统计，用于 Dashboard 展示

---

## 6. 特殊协议的差异化处理

### 6.1 协议差异化的阻断响应

在 `serveBlockedResponse()` 中（`middleware.go:59`）对不同协议采用不同的阻断策略：

```go
func (s *Server) serveBlockedResponse(pctx *proxy.DNSContext) (err error) {
    // UDP 和 DNSCrypt: 返回 nil 触发 ErrDrop → 直接丢弃数据包
    // 目的：防止 DNS 放大攻击 (不向伪造源发送响应)
    if pctx.Proto == proxy.ProtoUDP || pctx.Proto == proxy.ProtoDNSCrypt {
        return proxy.ErrDrop
    }

    // TCP / TLS / QUIC / HTTPS: 有连接保证，正常返回 REFUSED 响应
    pctx.Res = s.makeResponseREFUSED(pctx.Req)
    return nil
}
```

### 6.2 ClientID 的协议特定提取

在 `clientIDFromDNSContext()` 中（`middleware.go:99`）：

```go
func (s *Server) clientIDFromDNSContext(...) (clientID string, err error) {
    switch proto {
    case proxy.ProtoHTTPS:
        // 从 URL 路径提取: /dns-query/{clientID} 或 /{clientID}/dns-query
        clientID, err = clientIDFromDNSContextHTTPS(pctx)
        fallthrough  // 同时继续检查 SNI
    case proxy.ProtoTLS, proxy.ProtoQUIC:
        // 从 TLS SNI 的子域名前缀提取: {client-id}.dns.example.com
        cliSrvName, _ := clientServerName(ctx, l, pctx, proto)
        clientID, err = clientIDFromClientServerName(
            s.conf.TLSConf.ServerName, cliSrvName, ...)
    default:
        // UDP / TCP (明文 DNS) 无法携带 ClientID
        return "", nil
    }
}
```

---

## 7. 多上游 Fallback 机制

### 7.1 Fallback DNS 的配置与装配

Fallback DNS 是当所有主上游服务器都失败（超时、SERVFAIL、网络错误等）时使用的兜底解析器。其装配流程位于 `internal/dnsforward/dnsforward.go` 的 `Prepare()` 方法中：

```go
// internal/dnsforward/dnsforward.go:483
func (s *Server) Prepare(ctx context.Context, conf *ServerConfig) (err error) {
    // ... 前面步骤: proxyConfig 已构建好主上游 (UpstreamConfig) ...

    proxyConfig, err := s.newProxyConfig(ctx)
    // ...

    // Fallback 在主 proxyConfig 构建之后单独注入
    proxyConfig.Fallbacks, err = s.setupFallbackDNS()
    if err != nil {
        return fmt.Errorf("setting up fallback dns servers: %w", err)
    }

    dnsProxy, err := proxy.New(proxyConfig)
    // ...
}
```

### 7.2 `setupFallbackDNS()` 实现细节

位于 `internal/dnsforward/dnsforward.go:679`：

```go
func (s *Server) setupFallbackDNS() (uc *proxy.UpstreamConfig, err error) {
    // 从配置读取 fallback_dns 列表，过滤掉空行和注释 (# 开头)
    fallbacks := s.conf.FallbackDNS
    fallbacks = stringutil.FilterOut(fallbacks, aghnet.IsCommentOrEmpty)
    if len(fallbacks) == 0 {
        return nil, nil  // 未配置 fallback → 不启用
    }

    // 与主上游相同，通过 proxy.ParseUpstreamsConfig 解析为 UpstreamConfig
    // 注意: Fallback 暂不使用 Bootstrap 解析器（见 TODO 注释）
    uc, err = proxy.ParseUpstreamsConfig(fallbacks, &upstream.Options{
        Logger:       aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeFallback),
        Timeout:      s.conf.UpstreamTimeout,  // 复用主上游的超时
        PreferIPv6:   s.conf.BootstrapPreferIPv6,
    })
    return uc, err
}
```

### 7.3 Fallback 触发时机（在 dnsproxy 内部）

Fallback 的实际使用由 dnsproxy 库的 `Resolve()` 逻辑控制。触发条件是：**所有匹配的主上游全部失败**（超时、连接失败、返回 SERVFAIL/REFUSED/SERVFAIL 等错误响应码）。当主上游耗尽后，dnsproxy 才尝试 `proxy.Config.Fallbacks` 中的上游，同样遵循域名分流与上游模式规则。

---

## 8. 按 Hostname 拆分上游（域名分流）

### 8.1 Upstream 配置字符串语法

AdGuardHome 支持类似 Dnsmasq 的上游域名匹配语法，由 `proxy.ParseUpstreamsConfig()` 解析（位于 dnsproxy 库内部）：

| 语法 | 含义 | 对应字段 |
|------|------|---------|
| `8.8.8.8:53` | 无域名前缀，默认上游 | `UpstreamConfig.Upstreams` |
| `[/example.com/]1.1.1.1` | 精确匹配域名及子域 | `UpstreamConfig.SpecifiedDomainUpstreams` |
| `[/*.google.com/]8.8.8.8` | 通配子域名（不含根域） | `UpstreamConfig.DomainReservedUpstreams` |

**解析过程**：用户在 YAML 中配置的 `upstream_dns` 是一个字符串数组：

```yaml
upstream_dns:
  - https://dns.google/dns-query
  - [/example.com/]1.1.1.1
  - [/*.corp.local/]192.168.1.1
```

加载路径：`loadUpstreams()` (`config.go:530`) 从配置或文件读取原始字符串 → 过滤注释和空行 → `proxy.ParseUpstreamsConfig()` 将其解析为三部分数据结构。

### 8.2 `proxy.UpstreamConfig` 三部分结构

```go
type UpstreamConfig struct {
    // 1. 无域名匹配的默认上游（兜底使用）
    Upstreams []upstream.Upstream

    // 2. 指定域名上游（精确匹配: [/a.b/]x → 仅 a.b 和 *.a.b）
    //    Key: 规范化域名 (如 "example.com.")
    SpecifiedDomainUpstreams map[string][]upstream.Upstream

    // 3. 域名通配保留上游（通配匹配: [/*.x/]y → 仅 *.x）
    //    Key: 规范化域名 (如 "google.com.")
    DomainReservedUpstreams map[string][]upstream.Upstream
}
```

### 8.3 匹配优先级（在 dnsproxy `Resolve()` 内）

对于一个查询 `www.example.com`，匹配算法依次尝试：

1. **精确域名匹配**：查找 `SpecifiedDomainUpstreams["www.example.com."]`
   - 若命中 → 使用该组上游
   - 否则向上递归父域 `example.com.` → `com.`
2. **通配保留匹配**：查找 `DomainReservedUpstreams["www.example.com."]`
   - 同样向上递归父域
3. **默认上游**：使用 `Upstreams` 数组

### 8.4 客户端专属上游的覆盖

位于 `internal/dnsforward/process.go:516` 的 `setCustomUpstream()`：

```go
func (s *Server) setCustomUpstream(
    ctx context.Context, l *slog.Logger,
    pctx *proxy.DNSContext, clientID string,
) {
    if !pctx.Addr.IsValid() || s.conf.ClientsContainer == nil { return }

    cliAddr := pctx.Addr.Addr()
    // 按优先级查询: ClientID → IP 地址
    upsConf := s.conf.ClientsContainer.CustomUpstreamConfig(clientID, cliAddr)
    if upsConf != nil {
        // 写入 DNSContext，dnsproxy Resolve() 将优先使用此配置
        // 完全覆盖主 UpstreamConfig（含域名分流）
        pctx.CustomUpstreamConfig = upsConf
    }
}
```

`ClientsContainer.CustomUpstreamConfig()` 的实现位于 `internal/client/upstreammanager.go:122`，它：
- 按 `client UID` 查找缓存的 `customUpstreamConfig`
- 若配置有变动（`isChanged` 标记），调用 `newCustomUpstreamConfig()` 重新构建
- 内部同样调用 `proxy.ParseUpstreamsConfig()`，支持与全局上游相同的域名分流语法

**完整上游优先级链**：

```
请求进入
   │
   ▼
pctx.CustomUpstreamConfig 存在? ──是──► 使用客户端专属配置 (含分流)
   │否
   ▼
SpecifiedDomainUpstreams 精确匹配命中? ──是──► 使用该组上游
   │否
   ▼
DomainReservedUpstreams 通配匹配命中? ──是──► 使用该组上游
   │否
   ▼
默认 Upstreams 组 (按 UpstreamMode 执行负载均衡/并行/探测)
   │
   ▼
全部失败? ──是──► 使用 proxyConfig.Fallbacks
```

---

## 9. DoH 双入口复用机制

DoH（DNS-over-HTTPS）是 AdGuardHome 中最特殊的协议，因为它建立在 HTTP 之上，而 AdGuardHome 自身已经有一个用于 Web 管理界面的 HTTP 服务器。于是形成了 **两种 DoH 接入路径并存** 的复用架构。

### 9.1 路径 A：dnsproxy 独立 HTTPS 监听器

**配置方式**：通过 `proxy.Config.HTTPConfig.ListenAddresses` 配置独立的 `host:port`。

**代码入口**：dnsproxy 库在 `proxy.Start()` 时，若检测到 `HTTPConfig.ListenAddresses` 非空，就会创建独立的 `net.Listener` + `http.Server`，由 dnsproxy 自身管理生命周期。这条路径与其他协议（DoT/DoQ/UDP）完全一致，适用于需要 DoH 监听在独立端口（如 443）的场景。

请求流程：
```
客户端 → https://doh.example.com:443/dns-query
            │
            ▼
      dnsproxy 独立 HTTPS Listener
            │
            ▼
      dnsproxy 内部解析 HTTP 请求体/URL 参数
            │
            ▼
      组装 *proxy.DNSContext (Proto=ProtoHTTPS)
            │
            ▼
      RequestHandler (中间件链) → ServeDNS()
```

### 9.2 路径 B：挂载到 AdGuardHome 主 Web 服务器（默认推荐）

**代码装配链路**：

#### 第 1 步：`initDNS()` 注册路由

位于 `internal/home/dns.go:46`：

```go
func initDNS(ctx context.Context, baseLogger *slog.Logger, ...) (err error) {
    // ... 初始化 stats、queryLog、filters、dnsServer ...

    err = initDNSServer(ctx, ...)   // 创建并 Prepare dnsServer
    if err != nil { return err }

    // ⭐ DNS Server 准备好后，将其以 http.Handler 身份注册到主 Web mux
    registerDoHHandlers(config.HTTPConfig.DoH.Routes)

    return nil
}
```

#### 第 2 步：默认 DoH 路由配置

位于 `internal/home/config.go:469`，默认路由为：

```yaml
http_config:
  doh:
    routes:
      - "GET /dns-query"
      - "POST /dns-query"
      - "GET /dns-query/{ClientID}"
      - "POST /dns-query/{ClientID}"
```

#### 第 3 步：`registerDoHHandlers()` 注册

位于 `internal/home/dns.go:598`：

```go
func registerDoHHandlers(routes []string) {
    for _, route := range routes {
        // 关键: 将 dnsServer 直接作为 http.Handler 挂到全局 mux
        // dnsServer 类型是 *dnsforward.Server，它实现了 ServeHTTP()
        globalContext.web.conf.mux.Handle(route, globalContext.dnsServer)
    }
}
```

#### 第 4 步：鉴权中间件豁免 DoH 路由

位于 `internal/home/authhttp.go:326`：

```go
func (mw *authMiddlewareDefault) isDoHRoute(r *http.Request) (ok bool) {
    _, pattern := mw.mux.Handler(r)  // 查出匹配到的 route pattern
    if pattern == "" { return false }
    return slices.Contains(mw.doHRoutes, pattern)  // 在白名单中则跳过鉴权
}
```

DoH 路由被标记为公开资源，鉴权中间件在 `handlePublicAccess()` 中对其放行，避免 DoH 客户端因缺少登录 cookie 被 401 拒绝。

#### 第 5 步：`dnsforward.Server.ServeHTTP()` 转交 dnsproxy

位于 `internal/dnsforward/dnsforward.go:888`：

```go
// dnsforward.Server 实现了 net/http.Handler 接口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if !s.IsRunning() {
        http.Error(w, "DNS server is not running", http.StatusInternalServerError)
        return
    }
    if prx := s.proxy(); prx != nil {
        // ⭐ 委托给 dnsproxy 的 HTTP 处理器
        // prx.ServeHTTP() 会:
        //   1. 从请求中解析出 DNS 请求 (GET 的 dns 参数或 POST 二进制 body)
        //   2. 组装 proxy.DNSContext (Proto=ProtoHTTPS)
        //   3. 调用与其他协议完全相同的 RequestHandler → ServeDNS() 流程
        prx.ServeHTTP(w, r)
    }
}
```

### 9.3 双路径汇合点

两条路径虽然 HTTP 服务器来源不同，但最终都汇聚到同一个 `proxy.Proxy` 实例的内部 DoH 处理器，再调用完全相同的 `RequestHandler`（中间件链 + `ServeDNS()`）。因此从 DNS 处理逻辑看，两者 **100% 等价**。

```
  ┌───────────────────────┐     ┌───────────────────────┐
  │ dnsproxy 独立 HTTPS    │     │ AdGuardHome 主 Web     │
  │ 服务器 (独立端口)      │     │ 服务器 (共享端口)      │
  └───────────┬───────────┘     └───────────┬───────────┘
              │  HTTP 请求                     │  HTTP 请求
              ▼                               ▼
  ┌─────────────────────────────────────────────────────┐
  │        proxy.Proxy.ServeHTTP() (dnsproxy 内部)       │
  │   解析 DoH 请求 → 构造 DNSContext(Proto=ProtoHTTPS) │
  └───────────────────────┬─────────────────────────────┘
                          │
                          ▼
  ┌─────────────────────────────────────────────────────┐
  │   RequestHandler (中间件链: Rate → Log → Wrap)        │
  │                 → Server.ServeDNS()                   │
  └─────────────────────────────────────────────────────┘
```

### 9.4 两种模式对比

| 维度 | 路径 A：独立 HTTPS 监听器 | 路径 B：主 Web 挂载（默认） |
|------|--------------------------|---------------------------|
| 端口 | 独立端口，可对外 443 | 复用 Web 管理端口（默认 3000） |
| HTTP Server 归属 | dnsproxy 库管理 | `home.web` 全局 Web API 管理 |
| 鉴权 | 不经过鉴权中间件（直接进入 DNS 处理） | 鉴权中间件按 doh.routes 白名单放行 |
| TLS 证书 | dnsproxy 单独配置 | 复用主 Web 服务器证书 |
| HTTP/3 支持 | 由 `ServeHTTP3` 配置控制 | 取决于主 Web 服务器 |
| 适用场景 | 专用 DoH 服务端口 | 端口资源紧张、统一证书管理 |

---

## 10. ClientID 客户端识别完整链路

ClientID 是 AdGuardHome 对客户端进行精细化管理（自定义上游、独立过滤、统计归属）的核心标识。它仅在三种加密协议中携带，其推导与使用贯穿请求生命周期的多个环节。

### 10.1 各协议 ClientID 提取路径

#### DoH (DNS-over-HTTPS): 从 URL 路径提取

位于 `internal/dnsforward/clientid.go:63` 的 `clientIDFromDNSContextHTTPS()`：

```go
func clientIDFromDNSContextHTTPS(pctx *proxy.DNSContext) (clientID string, err error) {
    r := pctx.HTTPRequest  // 由 dnsproxy 从网络请求还原的 http.Request

    // 关键：依赖 Go 1.22+ 的路由模式匹配。
    // 当路由为 "/dns-query/{ClientID}" 时，Pattern 中包含 "{ClientID}" 占位符
    if !strings.Contains(r.Pattern, "{ClientID}") {
        return "", nil   // 路由没有 ClientID 占位符 → 跳过
    }

    // 从匹配到的 URL 段中读取参数值，例如 /dns-query/john → "john"
    clientID = r.PathValue("ClientID")
    err = client.ValidateClientID(clientID)  // 校验字符集和长度
    if err != nil { return "", fmt.Errorf("clientid check: %w", err) }

    return strings.ToLower(clientID), nil   // 规范化: 统一小写
}
```

**DoH 路由模式配置**（`internal/home/config.go:469`）：
```go
// 默认路由已预留 ClientID 占位符
DoH: doHConfig{
    Routes: []string{
        "GET /dns-query",
        "POST /dns-query",
        "GET /dns-query/{ClientID}",    // ✅ 带 ClientID
        "POST /dns-query/{ClientID}",   // ✅ 带 ClientID
    },
},
```

#### DoT / DoQ: 从 SNI 子域名前缀提取

##### 第 1 步：按协议获取 SNI

位于 `internal/dnsforward/clientid.go:91` 的 `clientServerName()`：

```go
func clientServerName(...) (srvName string, err error) {
    switch proto {
    case proxy.ProtoHTTPS:
        // HTTPS 时若 TLS SNI 未取到则 fallback 到 HTTP Host 头
        srvName, fromHost, err = clientServerNameFromHTTP(pctx.HTTPRequest)
        //   r.TLS != nil   → r.TLS.ServerName (TLS 握手 SNI)
        //   否则            → 解析 r.Host 去除端口部分
    case proxy.ProtoQUIC:
        // QUIC 连接从 TransportParameters 中获取 TLS SNI
        srvName = pctx.QUICConnection.ConnectionState().TLS.ServerName
    case proxy.ProtoTLS:
        // 标准 TLS 连接，直接从 *tls.Conn 的 ConnectionState() 读取
        tc := pctx.Conn.(tlsConn)
        srvName = tc.ConnectionState().ServerName
    }
    return srvName, nil
}
```

##### 第 2 步：将 SNI 与服务域名对比，提取子域前缀

位于 `internal/dnsforward/clientid.go:20` 的 `clientIDFromClientServerName()`：

```go
func clientIDFromClientServerName(
    hostSrvName string, // 配置中的服务域名: "dns.example.com"
    cliSrvName  string, // 客户端 SNI:       "john.dns.example.com"
    strict      bool,   // 是否严格拒绝非匹配 SNI
) (clientID string, err error) {
    if hostSrvName == cliSrvName {
        return "", nil   // 完全一致 → 没有 ClientID 前缀
    }

    // 检查: cliSrvName 是否为 hostSrvName 的**直接子域**
    //   "john.dns.example.com" 是 "dns.example.com" 的直接子域 ✓
    //   "a.b.dns.example.com" 不是  → 拒绝（严格模式）
    if !netutil.IsImmediateSubdomain(cliSrvName, hostSrvName) {
        if !strict { return "", nil }
        return "", fmt.Errorf("client server name %q doesn't match", cliSrvName)
    }

    // 截断: "john.dns.example.com"[:len("dns.example.com")+1] → "john"
    clientID = cliSrvName[:len(cliSrvName)-len(hostSrvName)-1]
    if err = client.ValidateClientID(clientID); err != nil {
        return "", err
    }
    return strings.ToLower(clientID), nil
}
```

### 10.2 ClientID 总调度：`clientIDFromDNSContext()`

位于 `internal/dnsforward/middleware.go:99`，处理 DoH 与 SNI 的优先级组合：

```go
func (s *Server) clientIDFromDNSContext(
    ctx context.Context, l *slog.Logger, pctx *proxy.DNSContext,
) (clientID string, err error) {
    proto := pctx.Proto

    if proto == proxy.ProtoHTTPS {
        // ⭐ 优先级 1: 先从 URL 路径提取 (/dns-query/{ClientID})
        clientID, err = clientIDFromDNSContextHTTPS(pctx)
        if err != nil { return "", err }
        if clientID != "" {
            return clientID, nil   // 命中 URL 路径 → 直接返回，跳过 SNI
        }
        // URL 路径没有 ClientID → fallthrough，继续尝试 SNI
    } else if proto != proxy.ProtoTLS && proto != proxy.ProtoQUIC {
        return "", nil   // UDP / TCP / DNSCrypt 明文协议 → 不支持
    }

    // ⭐ 优先级 2: 从 SNI / Host 头提取 ({clientid}.server.example.com)
    cliSrvName, err := clientServerName(ctx, l, pctx, proto)
    // ...
    return clientIDFromClientServerName(
        s.conf.TLSConf.ServerName,  // 服务域名
        cliSrvName,                  // 客户端 SNI
        s.conf.TLSConf.StrictSNICheck,  // 严格模式开关
    )
}
```

**协议支持矩阵**：

| 协议 | URL 路径提取 | SNI 子域提取 | 两者结合（DoH 双通道） |
|------|:-----------:|:-----------:|:---------------------:|
| UDP/TCP (Plain) | ❌ | ❌ | ❌ |
| DNSCrypt | ❌ | ❌ | ❌ |
| DoT (TLS) | ❌ | ✅ | - |
| DoQ (QUIC) | ❌ | ✅ | - |
| DoH (HTTPS) | ✅ (最高优先级) | ✅ (fallback) | ✅ URL → SNI |

### 10.3 ClientID 的使用：三处注入点

ClientID 在 Wrap 中间件中推导成功后，流向三处使用：

```
clientIDFromDNSContext() → 拿到 clientID = "john"
   │
   ├──► 使用点 1: IsBlockedClient(ip, clientID)
   │        在 accessManager 中进行 allowlist/blocklist 检查
   │
   ├──► 使用点 2: contextWithClientID(ctx, clientID)
   │        写入 context，下游 dnsContext 中读取用于日志、过滤
   │        dctx.clientID = clientIDFromContext(ctx)
   │
   └──► 使用点 3: setCustomUpstream(ctx, l, pctx, clientID)
            在 processUpstream 中通过 ClientsContainer 查询该 ID 的专属上游：
            pctx.CustomUpstreamConfig = ClientsContainer.CustomUpstreamConfig(clientID, ip)
```

---

## 11. Access Control 访问控制完整链路

访问控制发生在 **Wrap 中间件**（所有处理之前），包含三重独立检查，全部通过才允许请求进入管道。

### 11.1 `accessManager`：统一的访问控制引擎

位于 `internal/dnsforward/dnsforward.go:128` 的 `Server.access` 字段，由 `newAccessCtx()` 从配置构建：

```go
// internal/dnsforward/access.go:22
type accessManager struct {
    // IP 白/黑名单：精确地址 + CIDR 网段
    allowedIPs    *container.MapSet[netip.Addr]
    blockedIPs    *container.MapSet[netip.Addr]
    allowedNets   []netip.Prefix
    blockedNets   []netip.Prefix

    // ClientID 白/黑名单（加密协议才携带）
    allowedClientIDs *container.MapSet[string]
    blockedClientIDs *container.MapSet[string]

    // 域名黑名单：基于 urlfilter 规则引擎
    blockedHostsEng *urlfilter.DNSEngine  // 支持通配符、正则等
}
```

配置载入逻辑在 `newAccessCtx()` (`access.go:66`)：
```go
func newAccessCtx(allowed, blocked, blockedHosts []string) (a *accessManager, err error) {
    // 1. IP 与 ClientID 自动解析：
    //    "192.168.1.0/24" → IP CIDR 网段
    //    "10.0.0.5"      → 精确 IP
    //    其他字符串       → 视为 ClientID（调用 ValidateClientID 校验）
    processAccessClients(allowed, a.allowedIPs, &a.allowedNets, a.allowedClientIDs)
    processAccessClients(blocked, a.blockedIPs, &a.blockedNets, a.blockedClientIDs)

    // 2. 域名黑名单通过 urlfilter RuleStorage 加载
    //    每个域名一行，写入 blockedHostsEng 供高效匹配
    a.blockedHostsEng = urlfilter.NewDNSEngine(rulesStrg)
}
```

### 11.2 白名单模式切换

`accessManager` 通过 `allowlistMode()` 自动切换：**只要配置了任何一条 allow 规则，就进入白名单模式**：

```go
// access.go:108
func (a *accessManager) allowlistMode() (ok bool) {
    return a.allowedIPs.Len() != 0 ||
           a.allowedClientIDs.Len() != 0 ||
           len(a.allowedNets) != 0
}
```

白名单模式下的语义：
| 字段 | 白名单模式 | 黑名单模式（默认） |
|------|:---------:|:----------------:|
| IP | 未在 allowlist 内 → 拒绝 | 在 blocklist 内 → 拒绝 |
| ClientID | 未在 allowlist 内（含空 ClientID） → 拒绝 | 在 blocklist 内 → 拒绝 |

### 11.3 三重检查在 Wrap 中间件的执行顺序

位于 `internal/dnsforward/middleware.go:24` 的 `Wrap()`：

```go
func (s *Server) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
    f := func(ctx context.Context, p *proxy.Proxy, pctx *proxy.DNSContext) (err error) {
        l := slogutil.MustLoggerFromContext(ctx)

        // ====== 第 1 步：推导 ClientID（仅加密协议可拿到）======
        clientID, err := s.clientIDFromDNSContext(ctx, l, pctx)
        if err != nil {
            pctx.Res = s.NewMsgSERVFAIL(pctx.Req)   // 提取失败返回 SERVFAIL
            return nil
        }

        // ====== 第 2 步：客户端身份检查（IP + ClientID 同时判定）======
        blocked, _ := s.IsBlockedClient(pctx.Addr.Addr(), clientID)
        if blocked {
            // 按协议返回对应阻断：UDP/DNSCrypt→丢包，TCP/HTTPS→REFUSED
            return s.serveBlockedResponse(pctx)
        }

        // ====== 第 3 步：请求域名黑名单检查（如 version.bind）======
        blocked = s.isBlockedHost(ctx, l, pctx.Req.Question)
        if blocked {
            return s.serveBlockedResponse(pctx)
        }

        // ====== 全部通过：注入 ClientID 到 context，进入主流程 ======
        if clientID != "" { ctx = contextWithClientID(ctx, clientID) }

        return h.ServeDNS(ctx, p, pctx)
    }
    return proxy.HandlerFunc(f)
}
```

### 11.4 客户端身份判定：`IsBlockedClient()`

```go
// 实际调用：Server.access 两个方法组合判断
func (s *Server) IsBlockedClient(ip netip.Addr, clientID string) (blocked bool) {
    // a. ClientID 维度
    if s.access.isBlockedClientID(clientID) { return true }

    // b. IP 维度（精确 IP + 网段）
    blocked, _ = s.access.isBlockedIP(ip)
    return blocked
}
```

**ClientID 判定** (`isBlockedClientID()`, access.go:113)：
```go
func (a *accessManager) isBlockedClientID(id string) (ok bool) {
    if id == "" { return a.allowlistMode() }
    //   白名单模式：allowlist 内不拦截 → !Has(id) 为 true → 拦截
    //   黑名单模式：blocklist 内 → Has(id) 为 true → 拦截
    if a.allowlistMode() { return !a.allowedClientIDs.Has(id) }
    return a.blockedClientIDs.Has(id)
}
```

**IP 判定** (`isBlockedIP()`, access.go:141)：
```go
func (a *accessManager) isBlockedIP(ip netip.Addr) (blocked bool, rule string) {
    blocked = true          // 默认值，白名单模式下反转
    ips := a.blockedIPs
    ipnets := a.blockedNets

    if a.allowlistMode() {
        blocked = false
        ips = a.allowedIPs
        ipnets = a.allowedNets
    }

    if ips.Has(ip) { return blocked, ip.String() }
    for _, ipnet := range ipnets {
        if ipnet.Contains(ip) { return blocked, ipnet.String() }
    }

    return !blocked, ""   // 未命中列表：白名单→拒绝, 黑名单→通过
}
```

### 11.5 域名黑名单检查：`isBlockedHost()`

`access.go:129` 中通过 urlfilter 的 DNSEngine 匹配：

```go
func (a *accessManager) isBlockedHost(host string, qt rules.RRType) (ok bool) {
    _, ok = a.blockedHostsEng.MatchRequest(&urlfilter.DNSRequest{
        Hostname: aghnet.NormalizeDomain(host),  // 去末尾. + 小写
        DNSType:  qt,                            // A/AAAA/CNAME 等类型
    })
    return ok
}
```

默认配置的内置拦截（`dnsforward.go:51`）：
```go
var defaultBlockedHosts = []string{"version.bind", "id.server", "hostname.bind"}
```
这三个是 DNS 服务器探测域名，避免信息泄露。

---

## 12. DHCP 与 DNS 的双向解析协同

AdGuardHome 内置 DHCP 服务器，通过 **"DNS 依赖 DHCP 查询接口"** 的解耦模式，实现前向（主机名→IP）和后向（IP→主机名）的本地解析联动。

### 12.1 解耦接口：`DHCP` interface

位于 `internal/dnsforward/dnsforward.go:64`，DNS 模块只依赖此接口，不直接耦合 DHCP 实现：

```go
type DHCP interface {
    // 正向：主机名 → IP（由 DHCP 租约表内部实现哈希查找）
    IPByHost(host string) (ip netip.Addr)

    // 反向：IP → 主机名（由 DHCP 租约表内部实现哈希查找）
    HostByIP(ip netip.Addr) (host string)

    // 启用开关：关闭时直接跳过 DHCP 解析
    Enabled() (ok bool)
}
```

Server 持有该接口引用（`dnsforward.go:108`）：
```go
type Server struct {
    dhcpServer DHCP   // 由外部注入（home/dns.go 在创建 Server 时传入）
    // ...
}
```

### 12.2 前向解析：主机名 → IP (`processDHCPHosts`)

位于 `internal/dnsforward/process.go:275`，是处理管道的第 3 模块（在 DDR 之后，过滤之前）：

```go
func (s *Server) processDHCPHosts(...) (rc resultCode) {
    pctx := dctx.proxyCtx
    req := pctx.Req
    q := &req.Question[0]

    // 条件 1: 判断查询名是否匹配本地 DHCP 域模式
    dhcpHost := s.dhcpHostFromRequest(q)
    if dctx.isDHCPHost = dhcpHost != ""; !dctx.isDHCPHost {
        return resultCodeSuccess   // 不是 DHCP 主机查询 → 跳过
    }

    // 条件 2: 客户端必须来自私有网络（防止外部探测内部主机名）
    if !pctx.IsPrivateClient {
        pctx.Res = s.NewMsgNXDOMAIN(req)   // 外部客户端 → NXDOMAIN，甚至不记日志
        return resultCodeFinish            // 管道提前结束
    }

    // 条件 3: 通过 DHCP 接口查询租约表
    ip := s.dhcpServer.IPByHost(dhcpHost)   // O(1) 哈希查找
    if ip == (netip.Addr{}) {
        return resultCodeSuccess   // 没命中 → 继续走过滤+上游（可能 DNS 重写匹配）
    }

    // 命中 → 组装响应（不经过上游）
    resp := s.replyCompressed(req)
    switch q.Qtype {
    case dns.TypeA:
        // A 记录 → 直接写入 IPv4 地址
        resp.Answer = append(resp.Answer, &dns.A{Hdr: s.hdr(req, dns.TypeA), A: ip.AsSlice()})
    case dns.TypeAAAA:
        // AAAA + DNS64：IPv4 主机被 DNS64 前缀合成 IPv6
        if s.dns64Pref != (netip.Prefix{}) {
            resp.Answer = append(resp.Answer, &dns.AAAA{
                Hdr:  s.hdr(req, dns.TypeAAAA),
                AAAA: s.mapDNS64(ip),   // 64:ff9b:: + IPv4 合成 AAAA
            })
        }
    }

    dctx.proxyCtx.Res = resp     // 写入响应
    return resultCodeSuccess     // 继续下游管道（过滤/日志等仍会执行）
}
```

**DHCP 主机名匹配规则**：`dhcpHostFromRequest()` (`process.go:494`)

```go
func (s *Server) dhcpHostFromRequest(q *dns.Question) (reqHost string) {
    if !s.dhcpServer.Enabled() { return "" }         // DHCP 未开启
    if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA { return "" }  // 仅 A/AAAA

    reqHost = strings.ToLower(q.Name[:len(q.Name)-1])          // 去末尾点
    if !netutil.IsSubdomain(reqHost, s.localDomainSuffix) {    // 是否 *.lan ?
        return ""
    }

    // "my-pc.lan"[:len("my-pc.lan") - len("lan") - 1]  →  "my-pc"
    return reqHost[:len(reqHost)-len(s.localDomainSuffix)-1]
}
```

**查询示例**（`localDomainSuffix = "lan"`）：

| 查询 | 匹配结果 | 行为 |
|-----|:-------:|-----|
| `my-pc.lan.` IN A | ✅ → `dhcpHost="my-pc"` | 查租约，返回 IP 或 NXDOMAIN |
| `server.corp.lan.` IN A | ✅ → `dhcpHost="server.corp"` | 查租约 |
| `google.com.` IN A | ❌ → 不匹配 `.lan` 域 | 跳过 DHCP，转上游 |
| `my-pc.lan.` IN MX | ❌ → 非 A/AAAA | 跳过 DHCP |

### 12.3 后向解析：IP → 主机名 (`processDHCPAddrs`)

位于 `internal/dnsforward/process.go:345`，是处理管道的第 4 模块：

```go
func (s *Server) processDHCPAddrs(...) (rc resultCode) {
    pctx := dctx.proxyCtx
    if pctx.Res != nil { return resultCodeSuccess }   // 已有响应（如前向已命中）→ 跳过

    req := pctx.Req
    q := req.Question[0]
    pref := pctx.RequestedPrivateRDNS   // dnsproxy 识别的私有 PTR 前缀
    //    请求: "1.168.192.in-addr.arpa."  →  pref = 192.168.1.1/32
    //    dnsproxy 解析: 非私有网段不设置此字段 → 值为零值

    if pref == (netip.Prefix{}) || q.Qtype != dns.TypePTR {
        return resultCodeSuccess   // 非私有 PTR 或非 PTR 查询 → 跳过
    }

    addr := pref.Addr()
    host := s.dhcpServer.HostByIP(addr)  // 从租约表反向查找 O(1)
    if host == "" { return resultCodeSuccess }  // 没找到 → 交给上游/PTR

    // 命中 → 组装 PTR 响应
    resp := s.replyCompressed(req)
    resp.Answer = append(resp.Answer, &dns.PTR{
        Hdr: dns.RR_Header{
            Name:   q.Name,
            Rrtype: dns.TypePTR,
            Ttl:    s.dnsFilter.BlockedResponseTTL(),
            Class:  dns.ClassINET,
        },
        // "my-pc" + "lan"  →  "my-pc.lan."
        Ptr: dns.Fqdn(strings.Join([]string{host, s.localDomainSuffix}, ".")),
    })
    pctx.Res = resp
    return resultCodeSuccess
}
```

### 12.4 关键前置条件：dnsproxy 注入的两个字段

DHCP 协同依赖 dnsproxy 在 `DNSContext` 中预先填充的两个字段：

| 字段 | 设置者 | 含义 | 如何设置 |
|------|:------:|------|---------|
| `IsPrivateClient` | dnsproxy | 请求源 IP 是否属于 `proxy.PrivateNets` 配置的私有网段（10.0.0.0/8、192.168.0.0/16 等） | 每次请求时检查 `DNSContext.Addr` 是否匹配 |
| `RequestedPrivateRDNS` | dnsproxy | PTR 查询目标 IP 若属于私有网段，则解析出前缀 | 反解 `*.in-addr.arpa` 或 `*.ip6.arpa`，再判断是否为私有 IP |

AdGuardHome 在 `newProxyConfig()` 中将自身的私有网段集合传给 dnsproxy：
```go
// internal/dnsforward/config.go:359
conf = &proxy.Config{
    PrivateNets:    s.conf.PrivateNets,   // 透传给 dnsproxy
    RequestHandler: /* ... */,
}
```

这两个字段是 DHCP 模块安全开关的核心：
- `IsPrivateClient=false` → 前向解析直接 NXDOMAIN（**防止外部请求内部主机名**）
- `RequestedPrivateRDNS=零值` → 反向解析直接跳过（**公共 IP 的 PTR 交给上游**）

### 12.5 DHCP 协同的完整数据流

```
DNS 请求进入管道
   │
   ▼
┌───────────────────────────────────────────────────────┐
│ processInitial 模块                                    │
│   注入 dctx.isPrivateClient (来自 pctx.IsPrivateClient)│
└───────────────────────┬───────────────────────────────┘
                        │
   ┌────────────────────┴────────────────────┐
   │                                         │
   ▼                                         ▼
 processDHCPHosts (前向)               processDHCPAddrs (反向)
   │                                         │
   ├─ dhcpHostFromRequest() 判断域           ├─ q.Qtype==PTR?
   ├─ pctx.IsPrivateClient?                 ├─ RequestedPrivateRDNS != 零值?
   ├─ dhcpServer.IPByHost() 查询租约        ├─ dhcpServer.HostByIP() 查询租约
   │                                         │
   ▼                                         ▼
 命中 → 构造 A/AAAA (可能 DNS64)         命中 → 构造 PTR (host.localDomainSuffix)
   │                                         │
   └────────────────────┬────────────────────┘
                        │
                        ▼
           processFilteringBeforeRequest (过滤)
                        │
                        ▼
                继续下游管道 ...
```

---

## 13. 架构演进：`next/dnssvc` 新架构

位于 `internal/next/dnssvc/dnssvc.go`，展现了未来更简洁的设计方向（目前仅用于内部子系统）：

```go
func New(c *Config) (svc *Service, err error) {
    // 更清晰的分层：地址转换 → 上游构建 → Proxy 创建
    upstreams, resolvers, err := addressesToUpstreams(...)

    svc.proxy, err = proxy.New(&proxy.Config{
        // 直接传入监听地址
        UDPListenAddr:  udpAddrs(c.Addresses),
        TCPListenAddr:  tcpAddrs(c.Addresses),
        // 中间件链更简洁
        RequestHandler: rlMw.Wrap(proxy.DefaultHandler{}),
        // ...
    })
}
```

### 13.1 新旧架构对比

| 特性 | 旧架构 (`dnsforward`) | 新架构 (`next/dnssvc`) |
|------|----------------------|-----------------------|
| 功能完整度 | 完整（过滤、统计、日志、DHCP 联动等） | 精简版（仅代理转发） |
| 处理管道 | 9 个处理模块 | 依赖 `proxy.DefaultHandler` |
| 配置耦合度 | 高（与全局 Context 深度耦合） | 低（纯函数式创建） |
| 中间件 | 3 层（Rate + Log + Wrap） | 1 层（Rate） |

---

## 14. 关键文件索引

| 功能模块 | 文件路径 | 关键行号/函数 |
|---------|---------|-------------|
| DNS 服务器主体 & DHCP 接口 | `internal/dnsforward/dnsforward.go` | `DHCP` interface (L64), `Server` 结构体 (L99), `Start()` (L463), `ServeHTTP()` (L888), `setupFallbackDNS()` (L679) |
| 监听器配置 | `internal/dnsforward/config.go` | `newProxyConfig()` (L331), `prepareTLS()` (L710), `preparePlain()` (L812), `loadUpstreams()` (L530), `filterOutAddrs()` (L630) |
| 统一入口 | `internal/dnsforward/requesthandler.go` | `ServeDNS()` (L18) |
| 中间件 & 访问控制 & ClientID 入口 | `internal/dnsforward/middleware.go` | `Wrap()` (L24), `serveBlockedResponse()` (L59), `isBlockedHost()` (L73), `clientIDFromDNSContext()` (L99), `logMiddleware.Wrap()` (L169) |
| ClientID 提取实现 | `internal/dnsforward/clientid.go` | `clientIDFromClientServerName()` (L20), `clientIDFromDNSContextHTTPS()` (L63), `clientServerName()` (L91), `clientServerNameFromHTTP()` (L130) |
| 访问控制引擎 | `internal/dnsforward/access.go` | `accessManager` (L22), `processAccessClients()` (L39), `newAccessCtx()` (L66), `allowlistMode()` (L108), `isBlockedClientID()` (L113), `isBlockedIP()` (L141) |
| 处理管道 & 上游转发 & DHCP 解析 | `internal/dnsforward/process.go` | `processDHCPHosts()` (L275), `processDHCPAddrs()` (L345), `processUpstream()` (L441), `setCustomUpstream()` (L516), `dhcpHostFromRequest()` (L494) |
| 上游配置构造 | `internal/dnsforward/upstreams.go` | `newBootstrap()` (L27), `newUpstreamConfig()` (L60), `newPrivateConfig()` (L97), `setProxyUpstreamMode()` (L143) |
| 客户端专属上游 | `internal/client/upstreammanager.go` | `customUpstreamConfig()` (L122), `newCustomUpstreamConfig()` (L209) |
| DoH 主路由注册 | `internal/home/dns.go` | `initDNS()` (L46), `newServerConfig()` (L263), `registerDoHHandlers()` (L598) |
| DoH 鉴权豁免 | `internal/home/authhttp.go` | `isDoHRoute()` (L327), `authMiddlewareDefault.Wrap()` (L404) |
| DoH 路由默认配置 | `internal/home/config.go` | `doHConfig` 结构体 (L209), 默认 routes (L469) |
| 日志统计 | `internal/dnsforward/stats.go` | `processQueryLogsAndStats()` (L19) |
| 新架构实现 | `internal/next/dnssvc/dnssvc.go` | `New()` (L62) |
| DoH API 配置 | `internal/dnsforward/http.go` | `registerHandlers()` (L823), HTTP 控制接口 |

---

## 15. 总结

AdGuardHome 的 DNS 多协议统一架构，通过四层核心设计、三个关键扩展机制、两组业务协同链路，实现了协议透明性与业务可扩展性的平衡：

### 核心四层设计

1. **协议抽象层**（dnsproxy 库提供）：6 种协议监听器 → 统一 `DNSContext`，对上层完全屏蔽协议差异，同时注入 `IsPrivateClient` / `RequestedPrivateRDNS` 供上层使用
2. **中间件装饰层**（3 层洋葱模型）：速率限制 → 日志注入 → ClientID 提取 + 访问控制，在进入主处理管道之前完成横切关注点
3. **统一入口层**：`ServeDNS()` 方法，所有 DNS 查询必经的单点入口
4. **模块化管道层**：9 个独立处理模块依次执行，按需提前短路返回

### 三个关键扩展机制

5. **上游分流层**（五层优先级链）：客户端专属 → 精确域名匹配 → 通配域名匹配 → 默认上游组 → Fallback 兜底，每一层都支持独立的域名分流语法与上游模式
6. **DoH 双入口复用**：dnsproxy 独立 HTTPS 监听器 + 主 Web 路由挂载，两条路径最终汇聚到同一个 `proxy.Proxy.ServeHTTP()` → `RequestHandler` → `ServeDNS()`，实现 DNS 处理逻辑的 100% 复用
7. **ClientID 跨协议识别**：DoH 优先从 URL 路径 `{ClientID}` 占位符提取 → DoH/DoT/DoQ 回退从 SNI 直接子域前缀提取 → 注入 context 供访问控制、自定义上游、日志统计使用

### 两组业务协同链路

8. **访问控制双维度检查**（Wrap 中间件）：IP 白/黑名单（精确 + CIDR） + ClientID 白/黑名单 + 域名黑名单，白名单模式自动切换，支持协议差异化阻断
9. **DHCP ↔ DNS 双向解析联动**：DNS 通过 `DHCP` interface 解耦依赖 DHCP，前向 `*.lan` A/AAAA 查询经 `IPByHost()` 查租约返回，反向私有网段 PTR 查询经 `HostByIP()` 查租约返回，安全开关依赖 dnsproxy 注入的私有网段标识

### 整体优势

- **可扩展性**：新增协议只需在 dnsproxy 中实现 Listener，上层逻辑零改动
- **一致性**：所有协议使用相同的过滤、统计、日志逻辑，行为一致
- **可测试性**：各模块独立可测，不依赖具体协议
- **演进能力**：通过 Wrap 模式可无限扩展横切关注点（如 tracing、鉴权等）
- **灵活性**：上游分流支持按客户端、域名多级精细化调度，Fallback 保障解析可靠性
- **部署弹性**：DoH 双入口模式可在独立专用端口与共享 Web 端口之间自由选择
- **安全性**：私有网段 DHCP 解析对外部客户端屏蔽，UDP 阻断采用丢包避免放大攻击
- **解耦性**：DNS 与 DHCP 通过 interface 解耦，支持独立替换与测试

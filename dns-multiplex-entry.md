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

## 13. DNS 过滤规则引擎完整匹配链路

AdGuardHome 过滤系统采用 **"前置拦截 + 后置补漏"** 的双阶段模型，围绕 `filtering.DNSFilter` 核心引擎展开。

### 13.1 过滤引擎核心：`DNSFilter` 与 hostChecker 链

`filtering/filtering.go:252` 的 `DNSFilter` 是过滤子系统的门面：

```go
type DNSFilter struct {
    // 核心匹配引擎（基于 urlfilter 库）
    rulesStorage        *filterlist.RuleStorage   // 黑名单规则存储
    filteringEngine     *urlfilter.DNSEngine      // 黑名单 DNS 匹配引擎
    rulesStorageAllow   *filterlist.RuleStorage   // 白名单规则存储
    filteringEngineAllow *urlfilter.DNSEngine     // 白名单 DNS 匹配引擎

    // 六大 hostChecker，按顺序执行
    hostCheckers []hostChecker   // 见下文
    // ...
}

// hostChecker 是过滤管道的最小单元接口
type hostChecker struct {
    check func(host string, qtype uint16, setts *Settings) (Result, error)
    name  string
}
```

六大 `hostChecker` 在 `filtering.go:994`（DNSFilter 创建时）按以下顺序注册：

| 序号 | 检查器 | 名称 | 功能 |
|:---:|--------|------|------|
| 1 | `matchSysHosts` | hosts container | 系统 /etc/hosts 与用户自定义 DNS 重写（A/AAAA 记录） |
| 2 | `matchHost` | filtering | 主过滤引擎：黑名单/白名单规则（基于 urlfilter） |
| 3 | `matchBlockedServicesRules` | blocked services | 被屏蔽服务（如 Facebook、Twitter）的规则匹配 |
| 4 | `checkSafeBrowsing` | safe browsing | 安全浏览哈希前缀检查（远程恶意域名库） |
| 5 | `checkParental` | parental | 家长控制：成人内容过滤 |
| 6 | `checkSafeSearch` | safe search | 搜索引擎强制安全搜索（Google、Bing、YouTube 等） |

**匹配短路规则**：`CheckHost()` 按顺序调用每个 checker，只要返回 `Result.Reason.Matched() == true` 就立即返回，不再执行后续 checker。

### 13.2 前置过滤：`processFilteringBeforeRequest()`

位于 `internal/dnsforward/process.go:395`，执行在 **上游转发之前**，能拦截的请求绝不转发到公网。

```
请求进入
   │
   ├── 私有 PTR 查询 → 关闭 SafeBrowsing/Parental/SafeSearch（优化）
   │
   ├── pctx.Res 已被前序模块设置（DHCP/DDR等） → 跳过
   │
   ▼
filterDNSRequest(ctx, l, dctx)
   │
   ├── 第 1 阶段：DNSFilter.CheckHost(host, qtype, setts)
   │     │
   │     ├── processRewrites() → 检查 Legacy DNS Rewrites
   │     │     (仅命中 Rewritten 类型，有 CanonName/IPList 就立即返回)
   │     │
   │     └── 六大 hostChecker 依次执行（短路返回）
   │           │
   │           ├─ matchSysHosts → 用户 hosts 条目 / etc/hosts
   │           ├─ matchHost → urlfilter 黑白名单
   │           ├─ matchBlockedServicesRules → 服务屏蔽规则
   │           ├─ checkSafeBrowsing → 安全浏览
   │           ├─ checkParental → 家长控制
   │           └─ checkSafeSearch → 强制安全搜索
   │
   ├── 第 2 阶段：按 Result.Reason 生成响应或改写请求
   │
   ├── 分支 A: isRewrittenCNAME() → CNAME 重写无 IP
   │     ├─ 保存原 Question 到 dctx.origQuestion
   │     └─ 将 Req.Question[0].Name 改为 CanonName，继续上游解析此新域名
   │
   ├── 分支 B: res.IsFiltered → 明确拦截
   │     └─ genDNSFilterMessage() 按 BlockingMode 生成响应
   │         (Default/NXDOMAIN/REFUSED/自定义 IP / 空响应)
   │
   └── 分支 C: 其他 Matched Reason
         ├─ FilteredSafeSearch / Rewritten
         │   └─ getCNAMEWithIPs() → CNAME + IP 联合响应
         └─ RewrittenAutoHosts / RewrittenRule
             └─ filterDNSRewrite() → 应用 DNS 重写规则
```

关键代码位于 `internal/dnsforward/filter.go:28` 的 `filterDNSRequest()`：

```go
func (s *Server) filterDNSRequest(...) (res *filtering.Result, err error) {
    resVal, err := s.dnsFilter.CheckHost(host, q.Qtype, dctx.setts)
    res = &resVal

    // CNAME-only 重写（无 IP）：修改请求域名交给上游
    if isRewrittenCNAME(res) {
        dctx.origQuestion = q                    // 保存原问题
        req.Question[0].Name = dns.Fqdn(res.CanonName)  // 替换查询域
        checkReason = false
    } else if res.IsFiltered {
        pctx.Res = s.genDNSFilterMessage(ctx, l, pctx, res)  // 直接生成阻断响应
        checkReason = false
    }

    // 其他命中类型：SafeSearch / Rewritten / AutoHosts / Rule
    switch res.Reason {
    case FilteredSafeSearch, Rewritten:
        pctx.Res = s.getCNAMEWithIPs(ctx, req, res.IPList, res.CanonName)
    case RewrittenAutoHosts, RewrittenRule:
        err = s.filterDNSRewrite(ctx, req, res, pctx)
    }
    return res, err
}
```

### 13.3 后置过滤：`processFilteringAfterResponse()`

位于 `process.go:542`，执行在 **上游响应回来之后**，主要处理两类情况：CNAME 重写链补全，以及响应 IP/CNAME 的黑名单检查。

```
上游返回响应
   │
   ├── 分支 A: 原请求被 CNAME 重写过（dctx.origQuestion 非空）
   │     │
   │     ├── NotFilteredAllowList → 放行
   │     ├── Rewritten / RewrittenRule / FilteredSafeSearch
   │     │     ├── 恢复 Req.Question 和 Res.Question 为原始域名
   │     │     ├── 插入 CNAME 记录：原域名 → CanonName
   │     │     └── 上游返回的 A/AAAA 记录追加在 CNAME 之后
   │     │
   │     └── 其他 Reason → 调用 filterAfterResponse()
   │
   └── 分支 B: 默认 → filterAfterResponse(ctx, l, dctx)
         │
         ├── protectionEnabled && responseFromUpstream → 继续
         │
         └── filterDNSResponse()
               ├── 遍历 Res.Answer 每个 RR
               │   ├─ CNAME 记录 → CheckHostRules() 匹配
               │   ├─ A/AAAA 记录 → IP 黑名单（Bogus NXDOMAIN）检查
               │   └─ HTTPS/SVCB 记录 → Hint IP 检查
               └── 命中 → 用 BlockingMode 重新生成响应
```

关键代码位于 `process.go:579` 的 `filterAfterResponse()` → `filterDNSResponse()`（`filter.go:116`）：

```go
func (s *Server) filterDNSResponse(...) (err error) {
    // 遍历响应 Answer，按 RR 类型分别检查
    for _, rr := range pctx.Res.Answer {
        switch rr := rr.(type) {
        case *dns.CNAME:
            // 递归检查 CNAME 目标是否命中黑名单
            cnameHost := strings.TrimSuffix(rr.Target, ".")
            if res, err = s.checkHostRules(cnameHost, qt, setts); res.IsFiltered {
                dctx.result = res
                pctx.Res = s.genDNSFilterMessage(ctx, l, pctx, res)
                return nil
            }
        case *dns.A:
            // 检查 Bogus NXDOMAIN（虚假 IP 黑名单）
            if setts.ClientSafeSearch.BogusNXDomain.Contains(rr.A) {
                pctx.Res = s.genDNSFilterMessage(ctx, l, pctx, dctx.result)
                return nil
            }
        case *dns.AAAA:
            // 同上 IPv6
        case *dns.HTTPS:
            // 检查 HTTPS/SVCB RR 的 IP Hint
        }
    }
    return nil
}
```

### 13.4 CNAME 重写的往返链路

DNS 重写（DNS Rewrite）是 AdGuardHome 最常用的功能之一，其生命周期跨越前后两个过滤阶段：

```
客户端请求 my-pc.local → IN A

 ┌── processFilteringBeforeRequest
 │    filterDNSRequest():
 │      ├─ CheckHost() → 命中 RewrittenRule
 │      │   CanonName = "my-pc.lan"
 │      │   IPList = [] (无 IP，只有 CNAME)
 │      ├─ isRewrittenCNAME() = true
 │      ├─ dctx.origQuestion = {Name: "my-pc.local.", Type: A}
 │      └─ req.Question[0].Name = "my-pc.lan."  ← 修改请求域名
 │
 ├── processUpstream():
 │    prx.Resolve() → 将 "my-pc.lan." 转发到上游，拿到其 IP
 │    pctx.Res.Answer = [A 192.168.1.100]
 │
 └── processFilteringAfterResponse
      processFilteringAfterResponse():
        ├─ dctx.origQuestion 非空
        ├─ 恢复 Question 为 "my-pc.local."
        ├─ 插入 CNAME: my-pc.local. → my-pc.lan.
        └─ 保留上游返回的 A 记录
          
最终响应给客户端：
  my-pc.local.  CNAME  my-pc.lan.
  my-pc.lan.    A      192.168.1.100
```

---

## 14. Cache 层与 TTL 策略

AdGuardHome 的 DNS 缓存完全由 `dnsproxy` 库的 `proxy.Cache` 组件提供，`dnsforward` 层仅透传配置。

### 14.1 缓存配置的透传链路

**旧架构 dnsforward** 经 `newProxyConfig()` → `proxy.Config`：
```go
// 透传由 config.go 的 newProxyConfig() 完成
conf = &proxy.Config{
    CacheEnabled:   s.conf.CacheEnabled,   // 总开关
    CacheSizeBytes: s.conf.CacheSize,      // 缓存容量（字节）
    CacheMinTTL:    s.conf.CacheTTLMin,    // 最小 TTL（秒）
    CacheMaxTTL:    s.conf.CacheTTLMax,    // 最大 TTL（秒）
    CacheOptimistic: s.conf.CacheOptimistic, // 乐观缓存（过期后仍尝试异步刷新）
}
```

**新架构 next/dnssvc** 直接从外部配置注入（`dnssvc.go:77`）：
```go
svc.proxyConf: &proxy.Config{
    CacheSizeBytes: c.CacheSize,
    CacheEnabled:   c.CacheEnabled,  // CacheSize > 0 自动为 true
}
```

### 14.2 TTL 四策略

dnsproxy 的缓存对 TTL 提供四层控制（按优先级排序）：

| 策略 | 字段 | 作用 | 默认值 |
|------|------|------|:------:|
| 1. 最大 TTL 封顶 | `CacheMaxTTL` | 上游返回 TTL 超过此值时，截断为该值（防止过长缓存） | 0 = 不限制 |
| 2. 最小 TTL 保底 | `CacheMinTTL` | 上游返回 TTL 低于此值时，延长到该值（防止过度刷新） | 0 = 不限制 |
| 3. 乐观缓存 | `CacheOptimistic` | 条目过期后仍返回给客户端，同时异步刷新（低延迟优先） | false |
| 4. 阻断响应固定 TTL | `BlockedResponseTTL` | 被过滤/拦截的响应统一 TTL（由 DNSFilter 自己设置，与 proxy.Cache 独立） | 3600 秒 |

### 14.3 阻断响应的独立 TTL

被 AdGuardHome 主动拦截的响应（广告、恶意域名、SafeSearch 等）不走 dnsproxy 的缓存系统，而是由过滤层直接设置固定 TTL：

```go
// filtering.go:181
type Config struct {
    // TTL (秒) 用于所有被过滤阻断的响应
    BlockedResponseTTL uint32  // 默认 3600
}

// dnsforward 使用时
func (s *Server) BlockedResponseTTL() (ttl uint32) {
    return s.dnsFilter.BlockedResponseTTL()
}

// 生成阻断响应时设置
func (s *Server) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
    resp = s.replyCompressed(req)
    resp.Rcode = dns.RcodeNameError
    if len(resp.Ns) > 0 {
        resp.Ns[0].Header().Ttl = s.BlockedResponseTTL()
    }
    return resp
}
```

### 14.4 缓存条目淘汰（Eviction）

dnsproxy 内部采用 **LRU（Least Recently Used）+ 字节数硬限制** 的混合淘汰策略：
- 每次写入缓存时检查 `CacheSizeBytes`，超过容量就淘汰最久未使用的条目
- 由 `golibs/cache`（LRU）底层实现，按时间戳排序双向链表维护访问热度
- 乐观缓存模式下，过期条目不会立即删除，而是命中时触发异步 goroutine 刷新

### 14.5 绕过缓存的情况

以下请求不会进入缓存：
- 被 AdGuardHome 本地拦截的响应（filter 阻断、DHCP、DDR、Rewrite） — 直接返回，由 BlockedResponseTTL 控制客户端侧缓存
- 非 IN Class 的请求
- 请求设置了 `CD`（Checking Disabled）或 `DO`（DNSSEC OK）位且代理启用了 DNSSEC — 为防止缓存污染

---

## 15. next/dnssvc 新架构 Entry Point 与切换路径

`internal/next/` 目录是 AdGuardHome 下一代架构的试验场，目前已实现一个可独立运行的精简 DNS 服务。

### 15.1 新架构总入口：`internal/next/cmd`

#### (1) Main 函数：`cmd/cmd.go:21`

```go
func Main(embeddedFrontend fs.FS) {
    ctx := context.Background()
    baseLogger := newBaseLogger(opts)

    // 1. 创建配置管理器（读 YAML → 组装 Service）
    confMgrConf := &configmgr.Config{
        BaseLogger: baseLogger,
        Frontend:   frontend,
        FileName:   opts.confFile,   // AdGuardHome.yaml
        // ...
    }

    // 2. 服务管理器管理 Web + DNS 两大服务
    svc, err := newServiceMgr(ctx, &serviceMgrConfig{
        confMgrConf: confMgrConf,
        logger:      baseLogger.With("svc"),
    })

    // 3. 启动全部服务
    errors.Check(svc.Start(startCtx))

    // 4. 信号处理（SIGHUP 触发 Refresh，SIGINT/SIGTERM 触发 Shutdown）
    sigHdlr := service.NewSignalHandler(...)
    sigHdlr.AddService(svc)
    os.Exit(sigHdlr.Handle(ctx))
}
```

#### (2) 服务管理器：`cmd/service.go:61`

```go
func (s *serviceMgr) Start(ctx context.Context) (err error) {
    var errs []error
    // 并行启动 Web UI + DNS
    errs = append(errs, s.confMgr.Web().Start(ctx))   // websvc.Service
    errs = append(errs, s.confMgr.DNS().Start(ctx))   // dnssvc.Service
    return errors.Join(errs...)
}

// SIGHUP 热重载
func (s *serviceMgr) Refresh(ctx context.Context) (err error) {
    _ = s.Shutdown(ctx)         // 1. 停掉旧服务
    _ = s.updConfMgr(ctx)       // 2. 重新读配置，重建 Manager + Services
    return s.Start(ctx)         // 3. 启动新服务（暴力全重启模式）
}
```

### 15.2 ConfigManager：配置 → 服务实例的装配器

`internal/next/configmgr/configmgr.go:101` 是架构核心的 **纯函数式装配器**，负责：

```
磁盘 YAML
   │
   ▼ read() → config 结构体
   │
   ▼ assemble()
   │    ├─ 解析 DNS 配置 → dnssvc.Config
   │    │     ├─ dnssvc.New(c)  → 创建 *dnssvc.Service
   │    │     └─ m.dns = svc
   │    │
   │    └─ 解析 Web 配置 → websvc.Config
   │          ├─ websvc.New(c) → 创建 *websvc.Service
   │          └─ m.web = svc
   │
   ▼ Manager {dns, web, current, fileName}
```

关键装配函数 `assemble()` (`configmgr.go:152`)：

```go
func (m *Manager) assemble(ctx, conf, frontend, webAddr, start) (err error) {
    // DNS 服务装配：纯数据驱动
    dnsConf := &dnssvc.Config{
        Logger:              m.baseLogger.With("dnssvc"),
        UpstreamMode:        conf.DNS.UpstreamMode,
        Addresses:           conf.DNS.Addresses,
        BootstrapServers:    conf.DNS.BootstrapDNS,
        UpstreamServers:     conf.DNS.UpstreamDNS,
        CacheSize:           conf.DNS.CacheSize,
        CacheEnabled:        conf.DNS.CacheSize > 0,
        // ...
    }
    err = m.updateDNS(ctx, dnsConf)  // Shutdown 旧的 → dnssvc.New() 创建新的

    // Web 服务装配（同样是数据驱动 + 重建）
    webSvcConf := &websvc.Config{ ConfigManager: m, ... }
    err = m.updateWeb(ctx, webSvcConf)
}
```

### 15.3 DNS 服务内部 Entry Point：`dnssvc.New()`

`internal/next/dnssvc/dnssvc.go:62`：

```go
func New(c *Config) (svc *Service, err error) {
    // 1. RateLimit 中间件（唯一的中间件）
    rlMw, err := newRatelimitMw(c.Logger, c.Ratelimit)

    svc = &Service{
        logger: c.Logger,
        proxyConf: &proxy.Config{  // 保存以便 Config() 回读
            CacheEnabled: c.CacheEnabled,
            CacheSizeBytes: c.CacheSize,
            // ...
        },
    }

    // 2. 地址 + 上游 解析
    upstreams, resolvers, err := addressesToUpstreams(
        c.Logger, c.UpstreamServers, c.BootstrapServers, ...)
    svc.bootstrapResolvers = resolvers

    // 3. 直接创建 proxy.Proxy（对比 dnsforward：省略了 Prepare → Start 两步）
    svc.proxy, err = proxy.New(&proxy.Config{
        UpstreamConfig:  &proxy.UpstreamConfig{Upstreams: upstreams},
        UDPListenAddr:   udpAddrs(c.Addresses),  // 一次性地址转换
        TCPListenAddr:   tcpAddrs(c.Addresses),
        RequestHandler:  rlMw.Wrap(proxy.DefaultHandler{}),  // 精简中间件链
        CacheEnabled:    c.CacheEnabled,
        DNSSECEnabled:   c.DNSSECEnabled,
        UseDNS64:        c.UseDNS64,
    })
    return svc, nil
}
```

### 15.4 Web API 动态重配：热切换路径

`internal/next/websvc/dns.go:63` 的 `handlePatchSettingsDNS()` 展示了新架构下 DNS 配置热更新的路径：

```
PATCH /api/v1/settings/dns
   │
   ▼ handlePatchSettingsDNS(w, r)
   │
   ├── 1. 取当前 DNS 服务配置副本
   │     dnsSvc := svc.confMgr.DNS()
   │     newConf := dnsSvc.Config()
   │
   ├── 2. JSON Patch 增量修改
   │     req.UpstreamMode.Set(&newConf.UpstreamMode)
   │     req.CacheSize > 0 → newConf.CacheEnabled = true
   │     // ...
   │
   ├── 3. 交给 ConfigManager 更新
   │     svc.confMgr.UpdateDNS(ctx, newConf)
   │        │
   │        ├── Manager.updateDNS()
   │        │     ├── prev.Shutdown(ctx)         // 关闭旧 dnssvc.Service
   │        │     └── dnssvc.New(c) → m.dns = svc  // 生成全新实例
   │        │
   │        ├── Manager.updateCurrentDNS(c)     // 更新内存配置镜像
   │        └── Manager.write(ctx)              // 序列化到 YAML 文件
   │
   └── 4. 启动新 DNS 服务
         newSvc := svc.confMgr.DNS()   // 拿到刚创建的新实例
         newSvc.Start(ctx)             // 启动监听
```

### 15.5 新旧架构实现对比

| 维度 | 旧架构 `dnsforward.Server` | 新架构 `next/dnssvc.Service` |
|------|:------------------------:|:--------------------------:|
| **启动模式** | `New()` → `Prepare()` → `Start()` 三阶段分离 | `New()` 内部同时创建 proxy 实例，外部再 `Start()` |
| **配置修改** | `Reconfigure()` 内部热切换，尽量复用实例 | 始终 `Shutdown 旧 → New 新 → Start 新`，纯不可变 |
| **配置存储** | 直接持有 `*ServerConfig`，全局指针耦合 | 通过 `configmgr.Manager` 统一管理，Service 仅持有创建参数 |
| **处理功能** | 9 模块管道 + 6 Checker 过滤 + DHCP + 日志/统计 + ipset | 仅依赖 `proxy.DefaultHandler`（转发 + 缓存） |
| **中间件链** | RateLimit → Logging → Server.Wrap (3 层) | 仅 RateLimit (1 层) |
| **客户端能力** | ClientID + 自定义上游 + 按客户端过滤 | 无 |
| **入口文件** | `internal/home/dns.go`（嵌在 globalContext 中） | `internal/next/cmd/cmd.go`（独立二进制） |
| **热更新策略** | 局部更新（部分字段支持运行时改） | 全量重建服务（简单可靠） |

新架构的核心设计哲学：**"配置即数据，服务即实例"**。每次配置变更都生成全新的 Service 对象，消除了旧架构中因运行时状态交织带来的复杂度代价，是未来 AdGuardHome 重构的方向。

---

## 16. 查询日志（Query Log）写入链路

查询日志是 AdGuardHome 审计与排障的核心，采用 **"内存缓冲 → 异步刷盘 → 轮转归档"** 的三级流水线。

### 16.1 日志入口：`processQueryLogsAndStats()`

`internal/dnsforward/stats.go:19` 是所有 DNS 请求的日志与统计分叉点，统一由处理管道第9模块调用：

```go
func (s *Server) processQueryLogsAndStats(ctx, l, dctx) (rc resultCode) {
    pctx := dctx.proxyCtx
    host := aghnet.NormalizeDomain(pctx.Req.Question[0].Name)
    processingTime := time.Since(dctx.startTime)

    // 1. 构造客户端标识（ClientID 优先于 IP）
    ip := pctx.Addr.Addr().AsSlice()
    s.anonymizer.Load()(ip)    // 可配置的 IP 匿名化
    ipStr := net.IP(ip).String()
    ids := []string{ipStr}
    if dctx.clientID != "" {
        ids = []string{dctx.clientID, ipStr}
    }

    s.serverLock.RLock()
    defer s.serverLock.RUnlock()

    // 2. 分流写入 Query Log
    if s.shouldLog(host, qt, cl, ids) {
        s.logQuery(dctx, ip, processingTime)
    }
    // 3. 分流写入 Stats（见下一章）
    if s.shouldCountStat(host, qt, cl, ids) {
        s.updateStats(dctx, ipStr, processingTime)
    }
}
```

`shouldLog()` 检查条件：
- 非 TypeANY 查询（若 `RefuseAny` 开启）
- 客户端 `IgnoreQueryLog` 标志未设置
- 域名不在忽略名单（`IgnoreEngine`）

### 16.2 Query Log Writer：`logQuery()` → `queryLog.Add()`

`internal/dnsforward/stats.go:99` 的 `logQuery()` 将 DNS 上下文转换为 `querylog.AddParams` 后提交：

```go
func (s *Server) logQuery(dctx *dnsContext, ip net.IP, processingTime time.Duration) {
    p := &querylog.AddParams{
        Question:   pctx.Req,
        Answer:     pctx.Res,
        OrigAnswer: dctx.origResp,      // 过滤前的原始上游响应（用于审计）
        Result:     dctx.result,
        ClientID:   dctx.clientID,
        ClientIP:   ip,
        Elapsed:    processingTime,
        Cached:     p.Cached,           // 缓存命中标记
    }
    // 协议类型标记（DoH/DoQ/DoT/DNSCrypt/Plain）
    p.ClientProto = protocolMap[pctx.Proto]
    // 上游地址（含缓存命中标识）
    p.Upstream = pctx.Upstream.Address()
    s.queryLog.Add(p)
}
```

### 16.3 内存缓冲：RingBuffer + 异步刷盘

`internal/querylog/qlog.go:26` 的 `queryLog` 结构体是日志写入的核心：

```go
type queryLog struct {
    // 环形内存缓冲区（容量 = MemSize，默认 1000）
    buffer *container.RingBuffer[*logEntry]

    bufferLock    sync.RWMutex     // 保护 buffer 并发写入
    fileFlushLock sync.Mutex       // 防止刷盘 goroutine 重入
    fileWriteLock sync.Mutex       // 保护文件追加写入
    flushPending  bool             // 刷盘进行中标记
}
```

写入路径 `queryLog.Add()` (`qlog.go:219`)：

```
调用 queryLog.Add(p)
   │
   ├── 参数校验 → newLogEntry() 构造 logEntry
   │     ├── Time: time.Now()
   │     ├── QHost/QType/QClass: 标准化问题
   │     ├── addResponse(Answer) → 解析响应中的 IP/CNAME
   │     └── addResponse(OrigAnswer, true) → 保存原始响应
   │
   ├── bufferLock.Lock()
   ├── buffer.Push(entry)               // 写入环形缓冲
   │
   ├── 触发条件：!flushPending && FileEnabled && buffer.Len() >= MemSize
   │     └── go l.flushLogBuffer()      // 异步刷盘 goroutine
   │
   └── bufferLock.Unlock()
```

### 16.4 刷盘与压缩：`flushLogBuffer()` → `flushToFile()`

`internal/querylog/querylogfile.go:19`：

```
flushLogBuffer(ctx)
   ├── fileFlushLock.Lock()          // 单 goroutine 刷盘
   ├── encodeEntries(ctx)
   │     ├── bufferLock.Lock()
   │     ├── Range 遍历 buffer，json.Encode 每个 entry
   │     ├── buffer.Clear()
   │     ├── flushPending = false
   │     └── bufferLock.Unlock()
   │
   └── flushToFile(ctx, b)
         ├── fileWriteLock.Lock()
         ├── os.OpenFile(O_WRONLY|O_CREATE|O_APPEND)
         ├── f.Write(b.Bytes())      // 追加 JSON Lines 格式
         └── f.Close()
```

**JSON 行格式**：每行一条 JSON，包含完整的 DNS 请求响应信息：
```json
{"T":"2026-06-15T10:30:00Z","QH":"example.com","QT":"A","QC":"IN",
 "IP":"192.168.1.100","CP":"doh","ANS":[{"Type":"A","TTL":300,"V":"93.184.216.34"}],
 "C":"rfilter","IN":false,"TM":"10ms"}
```

### 16.5 日志轮转与归档：`periodicRotate()`

`qlog.go:150` 每小时检查一次，超过 `RotationIvl`（支持 6h/1d/7d/30d/90d）则轮转：

```
periodicRotate(ctx)
   ├── 每小时触发 checkAndRotate(ctx)
   │     ├── 读 querylog.json 首条记录的时间戳
   │     ├── 若 oldest.Add(rotationIvl) < now → rotate()
   │     └── os.Rename("querylog.json", "querylog.json.1")
   │
   └── 循环至 ctx 取消
```

**存储文件**：
- `querylog.json` — 当前日志（JSON Lines 格式）
- `querylog.json.1` — 上一个周期的归档日志

### 16.6 Query Log 写入全链路时序

```
          DNS 请求处理完成
                  │
                  ▼
    processQueryLogsAndStats(stats.go:19)
                  │
       ┌──────────┴──────────┐
       │ Query Log 分支      │ Stats 分支
       ▼                     ▼
 logQuery(stats.go:99)   updateStats(...)
       │
       ▼
 queryLog.Add(p) (qlog.go:219)
       │
       ├─► newLogEntry() → 生成 logEntry
       │
       ├─► RingBuffer.Push(entry)  ──┐
       │                              │ 环形缓冲满
       │                      buffer.Len() >= MemSize
       │                              │
       └──────────────────────────────┘
                      │
                      ▼
          go flushLogBuffer() (异步 goroutine)
                      │
                      ├─► encodeEntries() → JSON 序列化
                      │
                      └─► flushToFile() → 追加到 querylog.json
                                    │
                      ┌─────────────┘
                      │ 每小时检查
                      ▼
              periodicRotate()
                      │
                      └─► os.Rename → querylog.json.1
```

---

## 17. 统计指标（Stats）上报与 DB Schema

统计系统为 Dashboard 提供数据支撑，采用 **"内存聚合 + BoltDB 持久化 + 按小时分片"** 的架构。

### 17.1 统计入口：`updateStats()`

`internal/dnsforward/stats.go:143` 从 DNS 上下文提取关键指标：

```go
func (s *Server) updateStats(dctx *dnsContext, clientIP string, processingTime time.Duration) {
    pctx := dctx.proxyCtx

    // 收集上游统计（主 + fallback）
    qs := pctx.QueryStatistics()
    var upstreamStats []*proxy.UpstreamStatistics
    if qs != nil {
        upstreamStats = append(upstreamStats, qs.Main()...)
        upstreamStats = append(upstreamStats, qs.Fallback()...)
    }

    e := &stats.Entry{
        Client:         or(dctx.clientID, clientIP),
        Domain:         aghnet.NormalizeDomain(pctx.Req.Question[0].Name),
        UpstreamStats:  upstreamStats,
        ProcessingTime: processingTime,
        Result:         mapFilteringResultToStatResult(dctx.result.Reason),
    }
    s.stats.Update(e)
}
```

结果映射：
| 过滤原因 | 统计结果枚举 |
|---------|------------|
| FilteredBlockList/Invalid/BlockedService | `RFiltered` |
| FilteredSafeBrowsing | `RSafeBrowsing` |
| FilteredParental | `RParental` |
| FilteredSafeSearch | `RSafeSearch` |
| 其他 | `RNotFiltered` |

### 17.2 Stats 内存聚合：`unit` 结构

`internal/stats/unit.go:95` 的 `unit` 是每小时的内存聚合单元：

```go
type unit struct {
    // 计数器 Maps（string → uint64）
    domains            map[string]uint64   // 各域名请求数（未过滤）
    blockedDomains     map[string]uint64   // 各域名请求数（已过滤）
    clients            map[string]uint64   // 各客户端请求数
    upstreamsResponses map[string]uint64   // 各上游响应数
    upstreamsTimeSum   map[string]uint64   // 各上游总耗时（微秒）

    nResult            []uint64            // 按结果分类计数 [RNotFiltered..RParental]
    nTotal             uint64              // 总请求数
    timeSum            uint64              // 总处理时间（微秒）
    id                 uint32              // UnitID = UNIX时间戳 / 3600
}
```

**聚合逻辑 `unit.add(e)`** (`unit.go:318`)：

```go
func (u *unit) add(e *Entry) {
    // 1. 按结果分类计数
    u.nResult[e.Result]++

    // 2. 域名计数（分过滤/未过滤）
    if e.Result == RNotFiltered {
        u.domains[e.Domain]++
    } else {
        u.blockedDomains[e.Domain]++
    }

    // 3. 客户端计数
    u.clients[e.Client]++

    // 4. 总耗时累加（用于平均计算）
    u.timeSum += uint64(e.ProcessingTime.Microseconds())
    u.nTotal++

    // 5. 上游耗时统计（跳过缓存命中和错误）
    for _, s := range e.UpstreamStats {
        if s.IsCached || s.Error != nil { continue }
        u.upstreamsResponses[s.Address]++
        u.upstreamsTimeSum[s.Address] += uint64(s.QueryDuration.Microseconds())
    }
}
```

### 17.3 数据库持久化：BoltDB Schema

`internal/stats/stats.go:108` 使用 **BoltDB（嵌入式 KV 数据库）**，Schema 设计极简：

```
stats.db (BoltDB 文件)
├── Bucket "00000000000005A8"   // 8字节 BigEndian UnitID
│   └── Key "0x00" → Value = GOB 编码的 unitDB
│
├── Bucket "00000000000005A9"
│   └── Key "0x00" → Value = GOB 编码的 unitDB
│
└── ...
```

`unitDB` 是数据库中的序列化结构（`unit.go:155`，注意 GOB 编码依赖字段名，不可重命名）：

```go
type unitDB struct {
    NResult            []uint64     // 结果分类计数
    Domains            []countPair  // Top 100 域名（已排序）
    BlockedDomains     []countPair  // Top 100 被拦截域名
    Clients            []countPair  // Top 100 客户端
    UpstreamsResponses []countPair  // Top 100 上游响应数
    UpstreamsTimeSum   []countPair  // Top 100 上游耗时总和
    NTotal             uint64       // 总请求数
    TimeAvg            uint32       // 平均耗时（微秒）= timeSum / nTotal
}

type countPair struct {
    Name  string   // 域名/客户端/上游标识
    Count uint64   // 计数
}
```

**序列化 `unit.serialize()`** (`unit.go:258`)：
```go
func (u *unit) serialize() (udb *unitDB) {
    return &unitDB{
        NTotal:  u.nTotal,
        NResult: append([]uint64{}, u.nResult...),
        // Top N 裁剪（各取前100）
        Domains:            convertMapToSlice(u.domains, 100),
        BlockedDomains:     convertMapToSlice(u.blockedDomains, 100),
        Clients:            convertMapToSlice(u.clients, 100),
        UpstreamsResponses: convertMapToSlice(u.upstreamsResponses, 100),
        UpstreamsTimeSum:   convertMapToSlice(u.upstreamsTimeSum, 100),
        TimeAvg:            uint32(u.timeSum / u.nTotal),  // 计算平均值
    }
}
```

### 17.4 定时刷盘：`periodicFlush()`

`stats.go:496` 每秒检查一次，是否跨小时：

```
periodicFlush()
   ├── flush()
   │     ├── id = newUnitID()  // 当前小时 ID
   │     ├── 若 curr.id != id 说明跨小时了
   │     │
   │     └── flushDB(id, limit, curr)
   │           ├── 序列化 curr → udb
   │           ├── Begin(true) 事务
   │           ├── flushUnitToDB(udb, tx, curr.id)
   │           │     ├── CreateBucketIfNotExists(idToUnitName(curr.id))
   │           │     └── Put(key=0x00, value=GOB(udb))
   │           │
   │           ├── 删除过期 Bucket（id - limit 之前的）
   │           ├── curr = newUnit(id)  // 新建当前小时单元
   │           └── Commit 事务
   │
   └── 循环：每秒检查，跨小时则刷盘
```

### 17.5 Stats 全链路时序

```
          DNS 请求处理完成
                  │
                  ▼
    processQueryLogsAndStats(stats.go:19)
                  │
       ┌──────────┴──────────┐
       │ Query Log 分支      │ Stats 分支
       ▼                     ▼
    logQuery(...)      stats.Update(e) (stats.go:278)
                             │
                             ├─► currMu.Lock()
                             │
                             └─► unit.add(e) → 内存聚合
                                        │
                      ┌─────────────────┘
                      │ 每秒检查：跨小时？
                      ▼
              periodicFlush()
                      │
                      ├─► 跨小时 → curr.serialize() → unitDB
                      │
                      ├─► BoltDB 事务
                      │   ├─ CreateBucket(unitID)
                      │   ├─ Put(GOB(unitDB))
                      │   ├─ DeleteBucket(过期unit)
                      │   └─ Commit
                      │
                      └─► curr = newUnit(新小时ID)
```

### 17.6 查询读取路径（Dashboard 用）

`stats.getData(limit)` → `loadUnits(limit)` → 从 BoltDB 读取最近 N 个 unit 聚合后返回：

```
GET /control/stats?limit=24
   │
   └─► StatsCtx.getData(limit=24)
         ├─► loadUnits(24) → 读最近24个 Bucket + 当前内存 unit
         ├─► dataFromUnits(units)
         │    ├─► 聚合 Top N：域名 / 被拦截域名 / 客户端 / 上游
         │    ├─► 聚合时间序列：按小时/天统计
         │    └─► 汇总总数：总请求 / 拦截数 / 安全浏览 / 家长控制 / 平均耗时
         └─► 返回 JSON 给前端 Dashboard
```

---

## 18. Admin 与 Config 实时 Hot Reload 触发链

AdGuardHome 提供 **Web API + 信号 + 新架构纯函数式** 三条配置热重载路径。

### 18.1 旧架构：Web API 触发 `Reconfigure()`

**入口**：`POST /control/dns_config` → `handleSetConfig()` (`internal/dnsforward/http.go:539`)

```
POST /control/dns_config (JSON Body)
   │
   ▼ handleSetConfig(w, r)
   │
   ├── 1. Decode JSON → jsonDNSConfig{}
   │    所有字段都是指针，支持增量更新（只更新设置的字段）
   │
   ├── 2. validate() 校验：
   │    - 上游可连通性
   │    - 阻止自指配置（避免把自己设为上游）
   │    - 缓存大小合理性
   │
   ├── 3. s.setConfig(req) → (shouldRestart bool)
   │    │
   │    ├── 非重启字段立即生效（无需重建服务）
   │    │    ├── BlockingMode → dnsFilter.SetBlockingMode()
   │    │    ├── BlockedResponseTTL → dnsFilter.SetBlockedResponseTTL()
   │    │    ├── ProtectionEnabled → dnsFilter.SetProtectionEnabled()
   │    │    ├── UpstreamMode → s.conf.UpstreamMode
   │    │    └── DNSSECEnabled / AAAADisabled → s.conf 直接赋值
   │    │
   │    └── setConfigRestartable(dc) → 检查是否需要重启
   │         ├── 检查字段组：Upstreams / Bootstrap / Fallback / Cache* /
   │         │              EDNSCS / Ratelimit / ResolveClients
   │         └── 任一变更 → shouldRestart = true
   │
   ├── 4. s.conf.ConfModifier.Apply(ctx)
   │    │    持久化配置到磁盘（AdGuardHome.yaml）
   │    └─► defaultConfigModifier.Apply() → config.write() → 写 YAML
   │
   └── 5. if restart: s.Reconfigure(ctx, nil)
        │
        └─► Server.Reconfigure() (dnsforward.go:848)
             ├── serverLock.Lock()
             ├── stopLocked(ctx) → dnsProxy.Shutdown()
             ├── time.Sleep(100ms) → 等待 fd 释放
             ├── s.Prepare(ctx, conf) → 重新准备 proxy / upstreams / addrProc
             └── s.startLocked(ctx) → 重启监听 + 协程
```

**重启字段 vs 非重启字段**：

| 非重启（立即生效） | 需重启（重建服务） |
|-------------------|------------------|
| BlockingMode      | UpstreamDNS 列表 |
| BlockedResponseTTL | BootstrapDNS 列表 |
| ProtectionEnabled | FallbackDNS 列表 |
| UpstreamMode      | CacheEnabled / Size / TTL |
| DNSSECEnabled     | EDNSCS 配置 |
| AAAADisabled      | Ratelimit 配置 |
| EDNSCSCustomIP    | ResolveClients |
| (仅设置)          | UsePrivateRDNS |

### 18.2 信号触发：SIGHUP 部分 reload

`internal/home/signal.go:94` 提供信号驱动的配置刷新：

```
kill -SIGHUP <pid>
   │
   ▼ signalHandler.handle(ctx)
   │
   └── reloadConfig(ctx) (signal.go:117)
        │
        ├── 1. clientStorage.ReloadARP(ctx)
        │    重新扫描 ARP 表更新客户端信息（runtime client）
        │
        └── 2. tlsManager.Refresh(ctx)
             重新加载 TLS 证书和密钥（支持证书热替换）
```

> **注意**：SIGHUP 只刷新 ARP 客户端和 TLS 证书，**不会触发 DNS 服务全量 Reconfigure**。DNS 配置变更必须走 Web API。

### 18.3 新架构：Web API 纯函数式热更新

**入口**：`PATCH /api/v1/settings/dns` → `handlePatchSettingsDNS()` (`internal/next/websvc/dns.go:63`)

```
PATCH /api/v1/settings/dns (JSON Patch)
   │
   ▼ handlePatchSettingsDNS(w, r)
   │
   ├── 1. Decode → ReqPatchSettingsDNS{}
   │    使用 jsonpatch.NonRemovable<T> 类型，区分"未设置"与"设为零值"
   │
   ├── 2. 取当前 DNS 服务配置副本（值语义，深拷贝）
   │    dnsSvc := svc.confMgr.DNS()
   │    newConf := dnsSvc.Config()  // 返回值拷贝，不影响正在运行的实例
   │
   ├── 3. 增量更新 newConf（Set 方法只修改被请求的字段）
   │    req.UpstreamMode.Set(&newConf.UpstreamMode)
   │    req.Addresses.Set(&newConf.Addresses)
   │    req.CacheSize > 0 → newConf.CacheEnabled = true
   │    ...
   │
   ├── 4. ConfigManager 更新
   │    svc.confMgr.UpdateDNS(ctx, newConf)
   │    │
   │    └─► configmgr.Manager.updateDNS() (configmgr.go:351)
   │         ├── prev := m.dns          // 旧服务实例
   │         ├── prev.Shutdown(ctx)    // 关闭旧服务（释放端口）
   │         ├── dnssvc.New(c)         // 创建全新实例（纯函数）
   │         └── m.dns = svc           // 原子替换指针
   │
   ├── 5. 持久化配置
   │    m.updateCurrentDNS(c)          // 更新内存配置镜像
   │    m.write(ctx)                   // 写 YAML 到磁盘
   │
   └── 6. 启动新服务
        newSvc := svc.confMgr.DNS()    // 拿到刚创建的新实例
        newSvc.Start(ctx)              // 启动监听
```

### 18.4 配置持久化：`defaultConfigModifier.Apply()`

`internal/home/config.go:1009` 是旧架构的配置写入统一入口：

```go
func (cm *defaultConfigModifier) Apply(ctx context.Context) {
    // 收集所有子系统当前配置 → 完整 YAML → 写磁盘
    err := cm.config.write(ctx, cm.logger, cm.tlsMgr, cm.auth, cm.workDir, cm.confPath)
}
```

所有子系统（dnsforward / querylog / stats / filtering）通过 `WriteDiskConfig()` 将运行时配置写回 `*configuration` 结构体，然后统一序列化到 `AdGuardHome.yaml`。

### 18.5 新旧架构 Hot Reload 对比

| 维度 | 旧架构 dnsforward | 新架构 next/dnssvc |
|------|:-----------------:|:------------------:|
| **触发入口** | `POST /control/dns_config` + `handleSetConfig` | `PATCH /api/v1/settings/dns` + `handlePatchSettingsDNS` |
| **更新模型** | 字段分组（重启/非重启） + 增量修改内存对象 | 纯不可变：取配置副本 → 修改 → 创建新实例 → 替换指针 |
| **重启粒度** | 部分字段无需重启，部分字段 `stop → Prepare → start` | 每次变更全量 `Shutdown 旧 → New 新 → Start 新` |
| **配置拷贝** | 指针语义，原地修改 | 值语义，每次生成全新 `dnssvc.Config` 副本 |
| **持久化时机** | `ConfModifier.Apply()` 在 API 处理中显式调用 | `configmgr.UpdateDNS()` 内部自动调用 `write()` |
| **原子性** | `serverLock` 全局锁，`stop → Prepare → start` 非原子 | `Shutdown 旧 → New 新` 两步，期间服务短暂不可用 |
| **信号支持** | SIGHUP 只刷新 ARP/TLS，不触发 DNS 配置重载 | `serviceMgr.Refresh()` 暴力全重启（读 YAML → 重建所有服务） |
| **配置存储** | 全局 `*configuration` 单例 + 各子系统内部状态 | `configmgr.Manager` 统一持有 `current` 配置镜像 |

### 18.6 热更新全链路对比图

**旧架构**：
```
POST /control/dns_config
       │
       ▼
 jsonDNSConfig → 校验 → setConfig()
       │
       ├─► 非重启字段：直接写内存 ✓
       │
       ├─► ConfModifier.Apply() → 写 YAML 磁盘
       │
       └─► 需重启字段：Reconfigure(ctx, nil)
                      │
                      └─► stop → Prepare → start (重建 proxy)
```

**新架构**：
```
PATCH /api/v1/settings/dns
       │
       ▼
 ReqPatchSettingsDNS → Config() 深拷贝 → 增量修改
       │
       ▼
 configmgr.UpdateDNS(ctx, newConf)
       │
       ├─► prev.Shutdown(ctx)
       ├─► dnssvc.New(newConf) → 全新实例
       ├─► m.dns = svc (原子替换)
       └─► write(ctx) → 持久化 YAML
       │
       ▼
 newSvc.Start(ctx) → 新实例启动监听
```

---

## 19. 关键文件索引（完整）

| 功能模块 | 文件路径 | 关键行号/函数 |
|---------|---------|-------------|
| DNS 服务器主体 & DHCP 接口 | `internal/dnsforward/dnsforward.go` | `DHCP` interface (L64), `Server` 结构体 (L99), `Start()` (L463), `ServeHTTP()` (L888), `setupFallbackDNS()` (L679), `Reconfigure()` (L848) |
| 监听器配置 | `internal/dnsforward/config.go` | `newProxyConfig()` (L331), `prepareTLS()` (L710), `preparePlain()` (L812), `loadUpstreams()` (L530), `filterOutAddrs()` (L630) |
| 统一入口 | `internal/dnsforward/requesthandler.go` | `ServeDNS()` (L18) |
| 中间件 & 访问控制 & ClientID 入口 | `internal/dnsforward/middleware.go` | `Wrap()` (L24), `serveBlockedResponse()` (L59), `isBlockedHost()` (L73), `clientIDFromDNSContext()` (L99), `logMiddleware.Wrap()` (L169) |
| ClientID 提取实现 | `internal/dnsforward/clientid.go` | `clientIDFromClientServerName()` (L20), `clientIDFromDNSContextHTTPS()` (L63), `clientServerName()` (L91), `clientServerNameFromHTTP()` (L130) |
| 访问控制引擎 | `internal/dnsforward/access.go` | `accessManager` (L22), `processAccessClients()` (L39), `newAccessCtx()` (L66), `allowlistMode()` (L108), `isBlockedClientID()` (L113), `isBlockedIP()` (L141) |
| 处理管道 & 上游转发 & DHCP 解析 | `internal/dnsforward/process.go` | `processDHCPHosts()` (L275), `processDHCPAddrs()` (L345), `processUpstream()` (L441), `setCustomUpstream()` (L516), `dhcpHostFromRequest()` (L494) |
| 过滤规则引擎 (前后置) | `internal/dnsforward/filter.go` | `filterDNSRequest()` (L28), `filterDNSResponse()` (L116), `filterAfterResponse()` (L97) |
| DNS 过滤核心 | `internal/filtering/filtering.go` | `DNSFilter` 结构体 (L252), `hostChecker` (L337), `CheckHost()` (L1787) |
| 日志统计入口 | `internal/dnsforward/stats.go` | `processQueryLogsAndStats()` (L19), `logQuery()` (L99), `updateStats()` (L143) |
| Query Log 写入器 | `internal/querylog/qlog.go` | `queryLog` 结构体 (L26), `Add()` (L219), `periodicRotate()` (L150) |
| Query Log 刷盘 | `internal/querylog/querylogfile.go` | `flushLogBuffer()` (L19), `encodeEntries()` (L36), `flushToFile()` (L80), `rotate()` (L103) |
| Query Log 条目结构 | `internal/querylog/entry.go` | `logEntry` 结构体, JSON 序列化 |
| Stats 内存聚合 | `internal/stats/unit.go` | `unit` 结构体 (L95), `add()` (L318), `serialize()` (L258), `unitDB` 结构体 (L155) |
| Stats 持久化 | `internal/stats/stats.go` | `StatsCtx` 结构体 (L110), `Update()` (L278), `periodicFlush()` (L496), `flushDB()` (L446) |
| Stats BoltDB 操作 | `internal/stats/unit.go` | `flushUnitToDB()` (L343), `loadUnitFromDB()` (L277), `idToUnitName()` (L207) |
| 上游配置构造 | `internal/dnsforward/upstreams.go` | `newBootstrap()` (L27), `newUpstreamConfig()` (L60), `newPrivateConfig()` (L97), `setProxyUpstreamMode()` (L143) |
| 客户端专属上游 | `internal/client/upstreammanager.go` | `customUpstreamConfig()` (L122), `newCustomUpstreamConfig()` (L209) |
| DoH 主路由注册 | `internal/home/dns.go` | `initDNS()` (L46), `newServerConfig()` (L263), `registerDoHHandlers()` (L598) |
| DoH 鉴权豁免 | `internal/home/authhttp.go` | `isDoHRoute()` (L327), `authMiddlewareDefault.Wrap()` (L404) |
| DoH 路由默认配置 | `internal/home/config.go` | `doHConfig` 结构体 (L209), 默认 routes (L469), `defaultConfigModifier` (L977), `Apply()` (L1009) |
| 配置修改 API (旧) | `internal/dnsforward/http.go` | `handleSetConfig()` (L539), `setConfig()` (L588), `setConfigRestartable()` (L652) |
| 信号处理 | `internal/home/signal.go` | `signalHandler.handle()` (L75), `reloadConfig()` (L117) |
| 新架构 dnssvc 实现 | `internal/next/dnssvc/dnssvc.go` | `New()` (L62), `Config()` (L158), `Start()` (L173) |
| 新架构总入口 | `internal/next/cmd/cmd.go` | `Main()` (L21) |
| 新架构服务管理 | `internal/next/cmd/service.go` | `serviceMgr` (L61), `Start()` (L79), `Refresh()` (L144) |
| 新架构配置管理 | `internal/next/configmgr/configmgr.go` | `Manager` (L101), `assemble()` (L152), `UpdateDNS()` (L216), `updateDNS()` (L351) |
| 新架构 Web API (热更新) | `internal/next/websvc/dns.go` | `handleGetSettingsDNS()` (L40), `handlePatchSettingsDNS()` (L63) |
| 配置修改接口定义 | `internal/agh/agh.go` | `ConfigModifier` 接口 (L15), `EmptyConfigModifier` (L22) |

---

## 20. 总结

AdGuardHome 的 DNS 多协议统一架构，通过五层核心设计、四个关键扩展机制、两组业务协同链路、两大可观测性系统、两条热重载路径与一条演进路径，实现了协议透明性、业务可扩展性、可观测性与长期可演进性的平衡：

### 核心五层设计

1. **协议抽象层**（dnsproxy 库提供）：6 种协议监听器 → 统一 `DNSContext`，对上层完全屏蔽协议差异，同时注入 `IsPrivateClient` / `RequestedPrivateRDNS` 供上层使用
2. **中间件装饰层**（3 层洋葱模型）：速率限制 → 日志注入 → ClientID 提取 + 访问控制，在进入主处理管道之前完成横切关注点
3. **统一入口层**：`ServeDNS()` 方法，所有 DNS 查询必经的单点入口
4. **模块化管道层**：9 个独立处理模块依次执行，按需提前短路返回
5. **过滤规则引擎层**：前后置双阶段过滤（processFilteringBeforeRequest + processFilteringAfterResponse），6 大 hostChecker 顺序执行并短路匹配

### 四个关键扩展机制

6. **上游分流层**（五层优先级链）：客户端专属 → 精确域名匹配 → 通配域名匹配 → 默认上游组 → Fallback 兜底，每一层都支持独立的域名分流语法与上游模式
7. **DoH 双入口复用**：dnsproxy 独立 HTTPS 监听器 + 主 Web 路由挂载，两条路径最终汇聚到同一个 `proxy.Proxy.ServeHTTP()` → `RequestHandler` → `ServeDNS()`，实现 DNS 处理逻辑的 100% 复用
8. **ClientID 跨协议识别**：DoH 优先从 URL 路径 `{ClientID}` 占位符提取 → DoH/DoT/DoQ 回退从 SNI 直接子域前缀提取 → 注入 context 供访问控制、自定义上游、日志统计使用
9. **缓存与 TTL 策略层**：dnsproxy 内置 LRU + 字节数硬限制的混合淘汰策略，四层 TTL 控制（最大封顶 / 最小保底 / 乐观缓存异步刷新 / 阻断响应固定 TTL）

### 两组业务协同链路

10. **访问控制双维度检查**（Wrap 中间件）：IP 白/黑名单（精确 + CIDR） + ClientID 白/黑名单 + 域名黑名单，白名单模式自动切换，支持协议差异化阻断
11. **DHCP ↔ DNS 双向解析联动**：DNS 通过 `DHCP` interface 解耦依赖 DHCP，前向 `*.lan` A/AAAA 查询经 `IPByHost()` 查租约返回，反向私有网段 PTR 查询经 `HostByIP()` 查租约返回，安全开关依赖 dnsproxy 注入的私有网段标识

### 两大可观测性系统

12. **查询日志系统**：`processQueryLogsAndStats()` 分叉点 → `queryLog.Add()` → RingBuffer 内存缓冲 → 阈值触发异步 goroutine 刷盘 → JSON Lines 追加写入 → 按 RotationIvl 轮转归档（querylog.json → querylog.json.1），IP 匿名化 + 忽略域名过滤 + 客户端级忽略开关
13. **统计指标系统**：`stats.Update()` → `unit.add()` 按小时内存聚合（域名/被拦截域名/客户端/上游四维计数 + 结果分类计数 + 平均耗时） → 跨小时触发 BoltDB 持久化（每小时一个 Bucket，GOB 编码 unitDB） → Dashboard 读取路径 `getData()` 聚合 Top N 与时间序列

### 两条热重载路径

14. **旧架构 Web API 热更新**：`POST /control/dns_config` → `handleSetConfig()` → 字段分组（非重启字段立即生效 / 需重启字段标记）→ `ConfModifier.Apply()` 持久化 YAML → `Reconfigure()` 全量 stop → Prepare → start
15. **新架构纯函数式热更新**：`PATCH /api/v1/settings/dns` → `handlePatchSettingsDNS()` → `Config()` 值拷贝 → 增量修改 → `configmgr.UpdateDNS()` 原子替换（Shutdown 旧 → New 新） → 持久化 → `Start()` 新实例

### 一条演进路径

16. **next/dnssvc 新架构迁移**：通过 `configmgr.Manager` 实现纯函数式装配 —— "配置即数据，服务即实例"，每次变更全量 Shutdown 旧服务 + New 新服务 + Start，以换取配置解耦与不可变性；简化中间件链至单一层，依托 `proxy.DefaultHandler` 完成核心转发与缓存

### 整体优势

- **可扩展性**：新增协议只需在 dnsproxy 中实现 Listener，上层逻辑零改动
- **一致性**：所有协议使用相同的过滤、统计、日志逻辑，行为一致
- **可测试性**：各模块独立可测，不依赖具体协议
- **可观测性**：查询日志 JSON 格式便于外部分析，统计指标按小时分片聚合，支持长历史 Dashboard
- **演进能力**：通过 Wrap 模式可无限扩展横切关注点（如 tracing、鉴权等），新架构纯函数式装配进一步降低状态耦合
- **灵活性**：上游分流支持按客户端、域名多级精细化调度，Fallback 保障解析可靠性
- **部署弹性**：DoH 双入口模式可在独立专用端口与共享 Web 端口之间自由选择
- **安全性**：私有网段 DHCP 解析对外部客户端屏蔽，UDP 阻断采用丢包避免放大攻击，Bogus NXDOMAIN 检查过滤虚假响应，IP 匿名化保护隐私
- **解耦性**：DNS 与 DHCP 通过 interface 解耦；配置持久化通过 `ConfigModifier` 接口解耦；新架构 ConfigManager 将配置读写与服务生命周期解耦
- **性能可控**：Cache 支持 TTL 上下限、乐观缓存、LRU 淘汰；查询日志 RingBuffer 降低锁竞争；统计指标内存聚合 + 批量持久化平衡写入吞吐
- **运维友好**：热更新区分重启/非重启字段最小化服务中断，SIGHUP 支持证书与 ARP 表刷新，配置变更全程持久化到 YAML 可审计

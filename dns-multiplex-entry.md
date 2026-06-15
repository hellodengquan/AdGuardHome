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

- **自定义上游设置**：检查该客户端是否有专属上游配置
- 调用 `prx.Resolve(ctx, pctx)` 通过 dnsproxy 转发到上游
- 支持的上游模式：
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

## 7. 架构演进：`next/dnssvc` 新架构

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

### 7.1 新旧架构对比

| 特性 | 旧架构 (`dnsforward`) | 新架构 (`next/dnssvc`) |
|------|----------------------|-----------------------|
| 功能完整度 | 完整（过滤、统计、日志、DHCP 联动等） | 精简版（仅代理转发） |
| 处理管道 | 9 个处理模块 | 依赖 `proxy.DefaultHandler` |
| 配置耦合度 | 高（与全局 Context 深度耦合） | 低（纯函数式创建） |
| 中间件 | 3 层（Rate + Log + Wrap） | 1 层（Rate） |

---

## 8. 关键文件索引

| 功能模块 | 文件路径 | 关键行号/函数 |
|---------|---------|-------------|
| DNS 服务器主体 | `internal/dnsforward/dnsforward.go` | `Server` 结构体 (L99), `Start()` (L463), `ServeHTTP()` (L888) |
| 监听器配置 | `internal/dnsforward/config.go` | `newProxyConfig()` (L331), `prepareTLS()` (L710), `preparePlain()` (L812) |
| 统一入口 | `internal/dnsforward/requesthandler.go` | `ServeDNS()` (L18) |
| 中间件实现 | `internal/dnsforward/middleware.go` | `Wrap()` (L24), `logMiddleware.Wrap()` (L169) |
| 处理管道 | `internal/dnsforward/process.go` | 9 个 `process*` 方法 |
| 日志统计 | `internal/dnsforward/stats.go` | `processQueryLogsAndStats()` (L19) |
| 主服务初始化 | `internal/home/dns.go` | `initDNS()` (L46), `newServerConfig()` (L263), `registerDoHHandlers()` (L598) |
| 新架构实现 | `internal/next/dnssvc/dnssvc.go` | `New()` (L62) |
| DoH API 配置 | `internal/dnsforward/http.go` | `registerHandlers()` (L823), HTTP 控制接口 |

---

## 9. 总结

AdGuardHome 的 DNS 多协议统一架构，通过以下四层设计实现了高度的协议透明性：

1. **协议抽象层**（dnsproxy 库提供）：6 种协议监听器 → 统一 `DNSContext`，对上层完全屏蔽协议差异
2. **中间件装饰层**（3 层洋葱模型）：速率限制、日志注入、ClientID/访问控制 — 以相同逻辑处理所有协议
3. **统一入口层**：`ServeDNS()` 方法，所有 DNS 查询必经的单点入口
4. **模块化管道层**：9 个独立处理模块依次执行，按需提前短路返回

这种架构带来的优势：
- **可扩展性**：新增协议只需在 dnsproxy 中实现 Listener，上层逻辑零改动
- **一致性**：所有协议使用相同的过滤、统计、日志逻辑，行为一致
- **可测试性**：各模块独立可测，不依赖具体协议
- **演进能力**：通过 Wrap 模式可无限扩展横切关注点（如 tracing、鉴权等）

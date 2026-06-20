# AdGuard Home HTTPS 证书管理与后台安全鉴权协作流程解析

## 一、整体架构概览

AdGuard Home 的 HTTPS 证书管理与安全鉴权体系由两大核心子系统构成，二者通过 `webAPI` 中间层实现深度耦合：

```
┌─────────────────────────────────────────────────────────────────┐
│                        启动初始化流程                            │
│  run() ──→ initTLS() ──→ initUsers() ──→ newWeb() ──→ start()  │
└─────────────────────────────────────────────────────────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌──────────────────────┐                         ┌──────────────────────┐
│  证书管理层          │                         │  安全鉴权层          │
│  tlsManager          │◄────── setWebAPI() ────│  auth + webAPI       │
│  aghtls.Manager      │       双向引用          │  SessionStorage      │
│  FSWatcher           │                         │  authMiddleware      │
└──────────────────────┘                         └──────────────────────┘
         │                                                 │
         └──────────────────────┬──────────────────────────┘
                                ▼
                      ┌──────────────────┐
                      │   HTTP 服务层    │
                      │  HTTP + HTTPS    │
                      │  (含鉴权中间件)  │
                      └──────────────────┘
```

---

## 二、HTTPS 证书管理：自动续签触发机制

### 2.1 核心数据结构

#### `tlsManager` — 证书管理主控制器

**位置**：`internal/home/tls.go:35-80`

```go
type tlsManager struct {
    mu            *sync.Mutex              // 保护 status, certLastMod, extTLSConf 等
    status        *tlsConfigStatus         // 证书当前状态（NotBefore/NotAfter等）
    certLastMod   time.Time                // 证书文件最后修改时间戳 ⭐
    rootCerts     *x509.CertPool           // 系统根CA池
    web           *webAPI                  // 对Web服务的反向引用（循环依赖）
    extTLSConf    *tlsConfigSettings       // TLS配置（证书路径/端口/协议等）
    confModifier  agh.ConfigModifier       // 配置持久化修改器
    manager       aghtls.Manager           // 底层证书文件监控器 ⭐⭐
    customCipherIDs []uint16               // 自定义密码套件
}
```

#### `aghtls.Manager` — 文件系统监控接口层

**位置**：`internal/aghtls/manager.go:24-38`

```go
type Manager interface {
    service.Interface                          // Start/Shutdown 生命周期
    service.Refresher                          // Refresh() 手动刷新

    Set(ctx, certKey TLSPair) error            // 设置需监控的证书/密钥路径
    Updates(ctx) <-chan UpdateSignal           // 文件变更信号通道 ⭐⭐⭐
}
```

#### `aghtls.DefaultManager` — 默认实现

**位置**：`internal/aghtls/defaultmanager.go:28-34`

```go
type DefaultManager struct {
    logger  *slog.Logger
    pairMu  *sync.Mutex
    updates chan UpdateSignal              // 带缓冲(1)的信号通道
    watcher aghos.FSWatcher                // 底层OS文件系统监听器
    pair    TLSPair                        // CertPath + KeyPath
}
```

### 2.2 证书自动续签触发流程（四步触发链）

```
  外部证书续签工具
    (certbot / openssl等)
         │
         ▼
① 证书/密钥文件被修改写入磁盘
         │
         ▼  FSWatcher（fsnotify）OS级事件
② aghtls.DefaultManager.handleEvents() 收到文件变更事件
   位置：internal/aghtls/defaultmanager.go:147-163
         │
         ▼  Refresh() → updates channel
③ tlsManager.handleCertFileChange() 循环 <-range updates
   位置：internal/home/tls.go:217-232
         │
         ▼  调用 reload()
④ tlsManager.reload() → 重新加载证书 + 重启HTTPS服务器
   位置：internal/home/tls.go:238-288
```

#### 关键步骤详解：

**步骤 ③ — 信号监听循环** (`tls.go:217-232`)

```go
func (m *tlsManager) handleCertFileChange(ctx context.Context) {
    updates := m.manager.Updates(ctx)   // 获取信号通道
    if updates == nil { return }

    for range updates {                 // 阻塞等待文件变更信号
        m.logger.DebugContext(ctx, "reloading")
        m.reload(ctx)                   // 触发重载
    }
}
```

**步骤 ④ — 重载逻辑中的文件变更判定** (`tls.go:238-260`)

```go
func (m *tlsManager) reload(ctx context.Context) {
    // ... 加锁 ...

    certPath := tlsConfPtr.CertificatePath
    fi, _ := os.Stat(certPath)

    // ⭐ 关键对比：文件修改时间 == 上次记录时间？
    if fi.ModTime().UTC().Equal(m.certLastMod) {
        m.logger.InfoContext(ctx, "certificate file is not modified")
        return                              // 无变更则跳过，防抖动
    }

    m.logger.InfoContext(ctx, "certificate file is modified")
    // ... 执行 loadTLSConfig + reconfigureDNSServer + tlsConfigChanged ...
    m.certLastMod = fi.ModTime().UTC()      // 更新时间戳
}
```

### 2.3 启动时序中的关键初始化点

**位置**：`internal/home/home.go:899-946` (initTLS) + `home.go:881` (tlsMgr.start)

```
initTLS() 执行序列：
  1. 创建 aghos.OSWatcher (fsnotify 封装) — 监听磁盘文件
  2. 创建 aghtls.NewDefaultManager(watcher) — 管理监控路径
  3. aghtlsMgr.Start(ctx)
       └→ watcher.Start() + 启动 handleEvents() goroutine
  4. newTLSManager(...)
       └→ m.manager.Set(ctx, certPath, keyPath) 注册监控路径
       └→ loadTLSConfig() + setCertFileTime()  初始化时间戳
  5. confModifier.setTLSManager(tlsMgr)

tlsMgr.start(ctx) 执行序列（非首次运行时）：
  1. registerWebHandlers()  注册 /control/tls/* API
  2. m.web.tlsConfigChanged() 通知 web 初始化 HTTPS 配置
  3. go m.handleCertFileChange(ctx)  ⭐ 启动文件变更监听 goroutine
```

---

## 三、管理后台安全鉴权：Cookie Session 体系

### 3.1 三层架构模型

```
┌─────────────────────────────────────────────────────────────┐
│  ① HTTP 层：Cookie 传输                                      │
│     名称: agh_session                                         │
│     值: hex(SessionToken)                                     │
│     属性: HttpOnly=true, SameSite=Lax, Path=/                │
│     Expires: 365 天（cookieTTL）                              │
├─────────────────────────────────────────────────────────────┤
│  ② 中间件层：authMiddlewareDefault.Wrap()                    │
│     → userFromRequest()                                      │
│       ├─ 优先: Cookie → sessionTokenFromHex()                │
│       │          → FindByToken() → 内存 + bbolt 查询          │
│       └─ 备选: Basic Auth (带登录速率限制)                    │
├─────────────────────────────────────────────────────────────┤
│  ③ 存储层：DefaultSessionStorage                             │
│     内存 map[SessionToken]*Session + bbolt 持久化             │
│     SessionTTL: 30天（configurable via http.session_ttl）     │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 核心数据结构

#### `Session` — 会话对象

**位置**：`internal/aghuser/session.go:24-38`

```go
type Session struct {
    Expire    time.Time       // 过期时间点 = 创建时间 + SessionTTL
    UserLogin Login           // 用户登录名（冗余，便于快速查询）
    Token     SessionToken    // 16字节 加密随机 token
    UserID    UserID          // UUID v7 用户唯一标识
}
```

#### `DefaultSessionStorage` — 会话存储

**位置**：`internal/aghuser/sessionstorage.go:66-88`

```go
type DefaultSessionStorage struct {
    db         *bbolt.DB                  // 磁盘持久化（sessions-2 bucket）
    mu         *sync.Mutex
    clock      timeutil.Clock
    userDB     DB                        // 用户数据库（关联校验）
    sessions   map[SessionToken]*Session // ⭐ 内存索引（热路径）
    sessionTTL time.Duration             // 30天（可配置）
}
```

### 3.3 登录 → Session 创建 → Cookie 下发流程

**位置**：`internal/home/authhttp.go:108-199` (handleLogin + newCookie)

```
POST /control/login
     │
     ▼
handleLogin()
  ├─ 1. 解析 loginJSON {name, password}
  ├─ 2. 登录速率限制检查（按 RemoteIP 限流）
  ├─ 3. 调用 newCookie()
  │     ├─ auth.users.ByLogin() → 查用户
  │     ├─ user.Password.Authenticate() → bcrypt 校验
  │     ├─ auth.sessions.New(user)
  │     │    └─ 生成 SessionToken{16随机字节}
  │     │    └─ Expire = Now + SessionTTL(30天)
  │     │    └─ store() → 写入 bbolt（二进制序列化）
  │     │    └─ 加入内存 map 索引
  │     └─ 构造 http.Cookie:
  │          Name: "agh_session"
  │          Value: hex.EncodeToString(Token[:])  ⭐ 二进制转十六进制字符串
  │          Expires: Now + 365天 (cookieTTL)    ⭐ 注意：与 SessionTTL 不同
  │          HttpOnly: true  (防XSS读取)
  │          SameSite: Lax   (防CSRF)
  │          Secure: 未设置！  ⚠️ 详见第五节
  └─ 4. http.SetCookie(w, cookie) + 响应 200 OK
```

### 3.4 请求鉴权流程

**位置**：`internal/home/authhttp.go:404-425` (authMiddlewareDefault.Wrap)

```
每个 HTTP 请求进入 Wrap():
  │
  ├─ needsAuthentication()?
  │    └─ 查用户DB，无用户时放行（首次安装模式）
  │
  ├─ handleAuthenticatedUser()
  │    └─ userFromRequest()
  │         ├─ 尝试 Cookie 方式:
  │         │    r.Cookie("agh_session")
  │         │      → sessionTokenFromHex() 长度校验 + 解码
  │         │      → sessions.FindByToken()
  │         │           │  查内存 map（O(1)）
  │         │           └─ 命中后检查 now.After(s.Expire)?
  │         │                  是 → deleteByToken() 清理过期
  │         │                  否 → 返回 Session
  │         │      → users.ByLogin(s.UserLogin) 校验用户仍存在
  │         │      → 返回 *User
  │         └─ 备选 Basic Auth 方式（带限流）
  │
  │    ├─ 用户已认证 + 访问 /login.html → 重定向到 /
  │    └─ 用户已认证 + 其他路径 → h.ServeHTTP(r.WithContext(withWebUser()))
  │
  ├─ handlePublicAccess()
  │    ├─ 公开资源放行: /assets/*, /login.*, /control/login 等
  │    ├─ DoH 路由放行
  │    └─ 根路径 / 未登录 → 重定向 /login.html
  │
  └─ 以上皆不满足 → 返回 401 Unauthorized
```

### 3.5 Session 过期清理机制

**启动时清理**（`sessionstorage.go:149-192` `loadSessions`）：

```
NewDefaultSessionStorage() 初始化时：
  → loadSessions()
    → 遍历 bbolt "sessions-2" bucket 全部记录
    → bboltSessionHandler() 逐条检查：
        ├─ 二进制反序列化失败 → 标记删除
        ├─ now.After(s.Expire) → 标记删除（已过期）
        └─ 对应 UserLogin 查不到用户 → 标记删除
    → 批量提交 bbolt 事务
```

**请求时懒清理**（`sessionstorage.go:379-400` `FindByToken`）：

```
FindByToken() 命中内存缓存后：
  now.After(s.Expire)?
    → 是 → deleteByToken() 同步删除内存+磁盘 → 返回 nil
    → 否 → 返回 Session 供使用
```

---

## 四、关键时间参数与双向约束

### 4.1 三个关键 TTL 对比

| 参数 | 常量/配置位置 | 默认值 | 作用域 | 影响 |
|------|--------------|--------|--------|------|
| `cookieTTL` | `authhttp.go:29` | **365 天** | 浏览器端 Cookie 过期 | 控制浏览器何时丢弃 Cookie 文件。Cookie 过期后浏览器不再发送，即使用户 Session 实际未过期 |
| `sessionTTL` | `config.go:196` http.session_ttl | **30 天** | 服务端 Session 过期 | 控制服务端 Session 的绝对过期时间，过期后即使 Cookie 存在也会被服务端拒绝 |
| `Session.Expire` | `sessionstorage.go:330` 创建时计算 | 动态值 | 单个会话实例 | 创建时间 + sessionTTL，存入 bbolt 和内存 |

### 4.2 双向约束关系

#### 约束 ①：Cookie 存活期 ≥ Session 存活期（自然满足）

```
浏览器时间轴 T:
  T0: 登录，下发 Cookie (Expires=T0+365天)，Session (Expire=T0+30天)
  T15: 正常访问，一切OK
  T30: Session过期 → FindByToken() 发现过期 → 清理 + 返回401
        ↪ 用户需重新登录，获得新 Cookie + Session
  T60: 即使浏览器 Cookie 还存在（还有305天），也无法通过鉴权
        ↪ 因为服务端 Session 已销毁，Cookie 值对应 token 查不到
  T365: 浏览器最终删除该 Cookie 文件
```

**设计意图**：`cookieTTL > sessionTTL` 是故意的。Cookie 只是存储凭证的容器，真正的失效控制权在服务端。这样：
- 服务端可随时通过销毁 Session 强制登出（不依赖客户端行为）
- 用户长期使用后需定期重新认证（30天周期，增强安全）
- 浏览器 Cookie 长期留存减少「记住我」反复登录的感知（但实际上受 sessionTTL 约束）

#### 约束 ②：HTTPS 服务器启动强依赖证书就绪

**位置**：`web.go:398-417` `waitForTLSReady()`

```go
func (web *webAPI) waitForTLSReady() (ok bool) {
    web.httpsServer.cond.L.Lock()
    defer web.httpsServer.cond.L.Unlock()

    if web.httpsServer.inShutdown { return false }

    // ⭐ 条件变量阻塞等待，直到 enabled=true 被设置
    for !web.httpsServer.enabled {
        web.httpsServer.cond.Wait()          // 睡眠挂起
        if web.httpsServer.inShutdown { return false }
    }
    return true
}
```

触发 `enabled=true` 的路径（二者任一）：
1. **启动时**：`tlsManager.start()` → `m.web.tlsConfigChanged(ctx, m.extTLSConf)` → 设 cert + enabled=true
2. **证书变更**：`tlsManager.reload()` → `m.web.tlsConfigChanged(...)` → 设新 cert + enabled=tlsConf.Enabled
3. **API配置**：`handleTLSConfigure()` → `m.setConfig()` → `go m.web.tlsConfigChanged(...)`

#### 约束 ③：证书重载导致 HTTPS 服务器重建 → 所有现存连接（含已鉴权）被断开

**位置**：`web.go:213-247` `tlsConfigChanged()`

```go
func (web *webAPI) tlsConfigChanged(ctx, tlsConf) {
    // 解析新证书
    cert, _ = tls.X509KeyPair(...)

    web.httpsServer.cond.L.Lock()
    if web.httpsServer.server != nil {
        // ⚠️ 优雅关闭老 HTTPS 服务器
        // → 所有正在进行中的 TLS 连接被断开
        // → 已登录用户的 TCP/TLS 通道失效，需重新建立
        shutdownSrv(ctx, ..., web.httpsServer.server)
        shutdownSrv3(...)
    }
    web.httpsServer.enabled = enabled
    web.httpsServer.cert = cert
    web.httpsServer.cond.Broadcast()     // 唤醒 serveTLS() goroutine
    web.httpsServer.cond.L.Unlock()
}
```

**后果分析**：
- 服务器端关闭只是断开了 **TCP/TLS 传输层连接**
- **Session 数据不受影响**（仍在内存 map + bbolt 中）
- 浏览器下次请求时，由于 `agh_session` Cookie 仍然存在，会自动：
  1. 发起新的 HTTPS 握手（使用新证书）
  2. 请求携带原 Cookie
  3. 服务端鉴权中间件 FindByToken() 命中缓存
  4. **用户无感恢复登录状态** ✅

#### 约束 ④：TLS 配置变更需登录后才能操作（鉴权保护）

**位置**：`tls.go:1122-1126` 注册的 HTTP API 路径

```
GET  /control/tls/status     ← 需要登录才能查证书状态
POST /control/tls/validate   ← 需要登录才能校验证书有效性
POST /control/tls/configure  ← 需要登录才能修改 TLS 配置 ⭐关键
```

**保护机制**：这些 API 没有出现在 `isPublicResource()` (`authhttp.go:298-324`) 的白名单中，因此必须通过 `authMiddlewareDefault` 的鉴权校验。

**安全闭环**：
```
要修改证书配置 → 需要登录鉴权 → 登录需要 HTTPS 通道（如已启用TLS）
         ↑                              │
         └────────── 互相依赖 ──────────┘
```

#### 约束 ⑤：Cookie Secure 标志缺失的隐式约束

**当前代码** (`authhttp.go:235-242`)：

```go
return &http.Cookie{
    Name:     sessionCookieName,
    Value:    hex.EncodeToString(sess.Token[:]),
    Path:     "/",
    Expires:  time.Now().Add(cookieTTL),
    HttpOnly: true,              // ✅ 防 XSS
    SameSite: http.SameSiteLaxMode, // ✅ 防 CSRF
    // Secure: true,             // ❌ 未设置！
}, nil
```

**隐式约束**：`Secure` 属性未根据是否启用 HTTPS 动态设置。

- 当 TLS 未启用（纯 HTTP）：`Secure` 未设置是正确的（否则 Cookie 无法通过 HTTP 发送）
- 当 TLS 已启用：缺少 `Secure` 意味着 Cookie **可能**被降级通过 HTTP 发送（如果用户访问 http:// 版本）
- 这要求管理员**必须在网络层强制 HTTPS 重定向**，否则存在会话劫持降级风险

---

## 五、端到端完整协作流程图

### 场景 A：证书续签 → HTTPS 重启 → 用户无感重连

```
时间轴 │ 证书管理侧                          安全鉴权侧 / 用户侧
───────┼───────────────────────────────────────────────────────────
 T0    │  certbot 写入新 cert.pem + key.pem  │  用户通过 HTTPS 正常操作
       │                                    │  (持有 agh_session Cookie)
       │  ▼ FSWatcher 捕获 WRITE 事件
 T0+1  │  aghtlsMgr.handleEvents()          │
       │    → Refresh() → updates<-{}       │
       │  ▼
 T0+2  │  tlsManager.handleCertFileChange() │  (连接还在，继续响应请求)
       │    → reload()
       │      os.Stat() 发现 ModTime 变化
       │      loadTLSConfig() 解析新证书
       │      reconfigureDNSServer()        │
       │  ▼
 T0+3  │  m.web.tlsConfigChanged()          │  正在进行的请求被中断
       │    → shutdownSrv(HTTPS_Server)     │  ▼ 浏览器感知连接断开
       │    → 设置新 cert + enabled=true    │  ▼ 自动重试（浏览器行为）
       │    → cond.Broadcast()              │
       │  ▼ serveTLS() 被唤醒               │  重新发起 TLS 握手（新证书）
 T0+4  │  ListenAndServeTLS() 监听新端口    │  请求 GET /...
       │                                    │    Cookie: agh_session=xxxx
       │                                    │  ▼ 鉴权中间件
       │                                    │    FindByToken() → 命中内存缓存
       │                                    │    → Session 未过期 → ✅ 通过
       │                                    │  ▼ 响应正常数据
 T0+5  │  HTTPS 服务恢复正常                │  用户完全无感
       │                                    │  (证书已更新，会话保持登录)
```

### 场景 B：管理员登录 → 通过 API 配置新证书

```
管理员浏览器                                 后端服务
    │                                           │
    │  ① GET /login.html (HTTP/HTTPS)           │
    │  ◄────────── 登录页面 ────────────────────│
    │                                           │
    │  ② POST /control/login                   │
    │     {name, password}                     │
    │     ───────────────────────────────────►│
    │                                           │ newCookie() 生成 Session
    │                                           │ 写入 bbolt + 内存索引
    │  ◄──── Set-Cookie: agh_session=xxx ──────│
    │                                           │
    │  ③ POST /control/tls/configure           │
    │     {certificate_chain: base64, ...}     │
    │     Cookie: agh_session=xxx              │
    │     ───────────────────────────────────►│
    │                                           │ 鉴权中间件 → FindByToken 成功
    │                                           │ handleTLSConfigure():
    │                                           │   1. unmarshalTLS + base64 解码
    │                                           │   2. validateTLSSettings 端口检查
    │                                           │   3. loadTLSConfig 解析校验证书
    │                                           │   4. setConfig() 更新内部状态
    │                                           │   5. reconfigureDNSServer()
    │                                           │   6. go web.tlsConfigChanged()
    │                                           │      → 异步重启 HTTPS 服务器
    │  ◄──── 200 OK {status, ...} ────────────│
    │     (响应先返回，重启在后台进行)           │
    │                                           │
    │  ④ 后续请求在新 HTTPS 通道上继续           │
```

---

## 六、关键代码文件索引

| 模块 | 核心文件 | 关键行号 | 职责 |
|------|---------|---------|------|
| **证书管理器** | `internal/home/tls.go` | 35(tlsManager), 110(newTLSManager), 217(handleCertFileChange), 238(reload), 566(handleTLSConfigure) | TLS 配置管理、证书重载、API |
| **文件监控层** | `internal/aghtls/manager.go` | 24(Manager接口), 64(Updates通道) | 证书文件监控抽象 |
| **文件监控实现** | `internal/aghtls/defaultmanager.go` | 52(Set), 117(Start), 147(handleEvents) | fsnotify 集成、信号分发 |
| **认证主模块** | `internal/home/auth.go` | 89(auth), 124(newAuth), 159(middleware) | 认证模块初始化、用户DB |
| **认证HTTP层** | `internal/home/authhttp.go` | 29(cookieTTL), 108(handleLogin), 202(newCookie), 375(authMiddlewareDefault), 404(Wrap), 495(userFromRequest) | 登录登出、Cookie 处理、鉴权中间件 |
| **Session结构** | `internal/aghuser/session.go` | 9(Token长度), 24(Session) | 会话对象定义 |
| **Session存储** | `internal/aghuser/sessionstorage.go` | 66(DefaultSessionStorage), 97(NewDefaultSessionStorage), 325(New), 380(FindByToken) | 会话持久化 + 内存缓存 |
| **Web服务器** | `internal/home/web.go` | 117(httpsServer), 213(tlsConfigChanged), 253(start), 334(tlsServerLoop), 398(waitForTLSReady) | HTTP/HTTPS 服务生命周期 |
| **配置结构** | `internal/home/config.go` | 180(httpConfig), 196(SessionTTL), 462(SessionTTL默认值) | http.session_ttl 配置项 |
| **启动流程** | `internal/home/home.go` | 757(run), 899(initTLS), 1066(initUsers) | 整体初始化时序 |

# Web 鉴权与 API 中间件处理链路

本文档对照 AdGuard Home 源码，详细说明 Web 鉴权体系中的 **Session 认证**、**Basic Auth 认证**、**GLiNet Token 认证** 和 **限流保护** 的处理流程。

---

## 一、整体架构概览

### 1.1 中间件注册链路

HTTP 请求经过的中间件层（从外到内）：

```
HTTP 请求
    ↓
[limitRequestBody]     请求体大小限制 (64KB / 4MB)
    ↓
[logMw]                日志中间件
    ↓
[authMiddleware]       认证中间件 (核心)
    ↓
[postInstallHandler]   安装状态检查
    ↓
业务 Handler
```

**注册位置**：[internal/home/web.go:266-274](internal/home/web.go#L266-L274)

```go
hdlr := withMiddlewares(web.conf.mux, limitRequestBody)
logMw := httputil.NewLogMiddleware(logger, slog.LevelDebug)
hdlr = logMw.Wrap(hdlr)
hdlr = web.auth.middleware().Wrap(hdlr)
```

### 1.2 认证模式选择

系统根据配置选择两种认证中间件之一：

| 模式 | 中间件类型 | 适用场景 |
|------|-----------|---------|
| 默认模式 | `authMiddlewareDefault` | 标准部署，支持 Session + Basic Auth |
| GLiNet 模式 | `authMiddlewareGLiNet` | GL.iNet 路由器集成，使用文件 Token |

**工厂方法**：[internal/home/auth.go:159-181](internal/home/auth.go#L159-L181)

```go
func (a *auth) middleware() (mw httputil.Middleware) {
    if a.isGLiNet {
        return newAuthMiddlewareGLiNet(...)
    }
    return newAuthMiddlewareDefault(...)
}
```

---

## 二、Session 认证机制

### 2.1 会话数据结构

**定义**：[internal/aghuser/session.go:24-38](internal/aghuser/session.go#L24-L38)

```go
type Session struct {
    Expire    time.Time       // 会话过期时间
    UserLogin Login           // 关联的用户名
    Token     SessionToken    // 16字节加密随机令牌
    UserID    UserID          // 用户 UUID
}
```

- `SessionToken` 是 16 字节的加密安全随机数，使用 `crypto/rand` 生成
- 会话持久化存储在 bbolt 数据库中（`sessions.db`）

### 2.2 登录流程 (Session 创建)

**入口**：`POST /control/login` → [internal/home/authhttp.go:108-199](internal/home/authhttp.go#L108-L199)

```
用户提交用户名密码
    ↓
1. 限流检查 (rateLimiter.check) → 被封禁则返回 429
    ↓
2. 用户查询 (users.ByLogin) → 用户不存在则 inc 失败计数
    ↓
3. 密码验证 (bcrypt.CompareHashAndPassword) → 密码错误则 inc 失败计数
    ↓
4. 成功登录 → remove 限流计数
    ↓
5. 创建会话 (sessions.New) → 生成 16 字节 Token
    ↓
6. 设置 Cookie: agh_session=<hex(token)>
    Cookie 属性: HttpOnly, SameSite=Lax, 有效期 365 天
```

**关键代码**：[internal/home/authhttp.go:202-243](internal/home/authhttp.go#L202-L243)

```go
func newCookie(ctx context.Context, auth *auth, req loginJSON, addr string) (*http.Cookie, error) {
    user, _ := auth.users.ByLogin(ctx, aghuser.Login(req.Name))
    if user == nil {
        rateLimiter.inc(addr)
        return nil, errInvalidLogin
    }
    if !user.Password.Authenticate(ctx, req.Password) {
        rateLimiter.inc(addr)
        return nil, errInvalidLogin
    }
    rateLimiter.remove(addr)

    sess, _ := auth.sessions.New(ctx, user)
    return &http.Cookie{
        Name:     sessionCookieName,  // "agh_session"
        Value:    hex.EncodeToString(sess.Token[:]),
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    }, nil
}
```

### 2.3 Session 存储实现

**核心接口**：[internal/aghuser/sessionstorage.go:23-39](internal/aghuser/sessionstorage.go#L23-L39)

```go
type SessionStorage interface {
    New(ctx context.Context, u *User) (*Session, error)
    FindByToken(ctx context.Context, t SessionToken) (*Session, error)
    DeleteByToken(ctx context.Context, t SessionToken) error
    Close() error
}
```

**存储机制**：
- **内存缓存**：`map[SessionToken]*Session` 快速查询
- **持久化**：bbolt 数据库，bucket 名为 `"sessions-2"`
- **二进制编码**：4字节过期时间 + 2字节用户名长度 + 用户名

**会话验证流程**：[internal/aghuser/sessionstorage.go:380-400](internal/aghuser/sessionstorage.go#L380-L400)

```
FindByToken(token)
    ↓
1. 内存查找 sessions[token] → 不存在返回 nil
    ↓
2. 检查是否过期 (now > Expire) → 过期则删除并返回 nil
    ↓
3. 返回会话对象
```

### 2.4 Session 认证中间件流程

**核心方法**：[internal/home/authhttp.go:404-425](internal/home/authhttp.go#L404-L425)

```go
func (mw *authMiddlewareDefault) Wrap(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !mw.needsAuthentication(ctx) {
            h.ServeHTTP(w, r)  // 无用户配置，跳过认证
            return
        }

        if mw.handleAuthenticatedUser(ctx, w, r, h, path) {
            return  // 已认证用户
        }

        if mw.handlePublicAccess(w, r, h, path) {
            return  // 公开资源
        }

        w.WriteHeader(http.StatusUnauthorized)  // 401 未授权
    })
}
```

**用户提取流程**：[internal/home/authhttp.go:495-507](internal/home/authhttp.go#L495-L507)

```
userFromRequest(r)
    ↓
1. 尝试 Cookie 认证 → userFromCookie
    ↓ 失败则
2. 尝试 Basic Auth 认证 → userFromRequestBasicAuth
```

---

## 三、Basic Auth 认证

### 3.1 认证流程

**实现**：[internal/home/authhttp.go:557-601](internal/home/authhttp.go#L557-L601)

```
Authorization: Basic <base64(username:password)>
    ↓
1. 解析用户名密码 (r.BasicAuth())
    ↓
2. 限流检查 → 被封禁则返回错误
    ↓
3. 用户查询 (users.ByLogin)
    ↓
4. bcrypt 密码验证
    ↓
5. 成功则 remove 限流计数，失败则 inc 计数
    ↓
返回用户对象
```

**限流集成**：

```go
rateLimiter := mw.rateLimiter
if left := rateLimiter.check(remoteIP); left > 0 {
    return nil, fmt.Errorf("login attempt blocked for %s", left)
}

defer func() {
    if err != nil {
        rateLimiter.inc(remoteIP)  // 认证失败，计数+1
        return
    }
    rateLimiter.remove(remoteIP)    // 认证成功，清除计数
}()
```

> **注意**：代码库中未实现 Bearer Token 认证（`Authorization: Bearer <token>`），仅支持 Basic Auth 和 Session Cookie。

---

## 四、GLiNet Token 认证（特殊模式）

### 4.1 适用场景

GL.iNet 路由器集成模式，通过文件系统共享 Token 实现免密登录。

**中间件**：[internal/home/authglinet.go:68-129](internal/home/authglinet.go#L68-L129)

### 4.2 认证流程

```
Cookie: Admin-Token=<token>
    ↓
1. 读取 Cookie "Admin-Token"
    ↓
2. 打开文件: gl_token_<token>
    ↓
3. 读取 4 字节 Unix 时间戳
    ↓
4. 检查 token 是否过期 (now - timestamp < 3600s)
    ↓
5. 有效则放行，否则返回 401
```

**Token 验证**：[internal/home/authglinet.go:158-168](internal/home/authglinet.go#L158-L168)

```go
func (mw *authMiddlewareGLiNet) checkToken(ctx context.Context, token string) bool {
    tokenDate := mw.tokenDate(ctx, glFilePrefix+token)
    now := mw.clock.Now()
    if now.Before(tokenDate.Add(mw.ttl)) {  // ttl = 3600s
        return true
    }
    return false
}
```

---

## 五、限流保护机制

### 5.1 限流接口

**定义**：[internal/home/authratelimiter.go:12-23](internal/home/authratelimiter.go#L12-L23)

```go
type loginRateLimiter interface {
    check(usrID string) time.Duration  // 检查剩余封禁时间
    inc(usrID string)                  // 增加失败计数
    remove(usrID string)               // 清除记录
}
```

### 5.2 限流算法

**实现类**：`authRateLimiter` - 基于 IP 的滑动窗口计数

**数据结构**：[internal/home/authratelimiter.go:50-57](internal/home/authratelimiter.go#L50-L57)

```go
type authRateLimiter struct {
    failedAuths map[string]failedAuth  // key: IP, value: {until, num}
    failedAuthsLock sync.Mutex
    blockDur        time.Duration      // 封禁时长 (配置: AuthBlockMin)
    maxAttempts     uint               // 最大尝试次数 (配置: AuthAttempts)
}

type failedAuth struct {
    until time.Time  // 封禁截止时间
    num   uint       // 累计失败次数
}
```

### 5.3 核心逻辑

**检查逻辑**：[internal/home/authratelimiter.go:81-93](internal/home/authratelimiter.go#L81-L93)

```go
func (ab *authRateLimiter) checkLocked(usrID string, now time.Time) time.Duration {
    a, ok := ab.failedAuths[usrID]
    if !ok || a.num < ab.maxAttempts {
        return 0  // 未达到阈值，不封禁
    }
    return a.until.Sub(now)  // 返回剩余封禁时间
}
```

**计数递增**：[internal/home/authratelimiter.go:109-126](internal/home/authratelimiter.go#L109-L126)

```go
func (ab *authRateLimiter) incLocked(usrID string, now time.Time) {
    until := now.Add(failedAuthTTL)  // 1分钟内的失败计数
    attNum := uint(1)

    if a, ok := ab.failedAuths[usrID]; ok {
        until = a.until
        attNum = a.num + 1
    }
    if attNum >= ab.maxAttempts {
        until = now.Add(ab.blockDur)  // 超过阈值，延长封禁
    }

    ab.failedAuths[usrID] = failedAuth{num: attNum, until: until}
}
```

### 5.4 配置与初始化

**配置项**：
- `AuthAttempts`：最大尝试次数，0 表示禁用
- `AuthBlockMin`：封禁时长（分钟），0 表示禁用

**初始化**：[internal/home/home.go:1074-1081](internal/home/home.go#L1074-L1081)

```go
var rateLimiter loginRateLimiter
if config.AuthAttempts > 0 && config.AuthBlockMin > 0 {
    blockDur := time.Duration(config.AuthBlockMin) * time.Minute
    rateLimiter = newAuthRateLimiter(blockDur, config.AuthAttempts)
} else {
    rateLimiter = emptyRateLimiter{}  // 空实现，不禁用
}
```

### 5.5 限流触发点

限流在以下场景生效：

1. **登录接口**：`POST /control/login` - [internal/home/authhttp.go:137-151](internal/home/authhttp.go#L137-L151)
2. **Basic Auth 认证**：每个 API 请求 - [internal/home/authhttp.go:575-588](internal/home/authhttp.go#L575-L588)

**登录接口限流响应**：
```http
HTTP/1.1 429 Too Many Requests
Retry-After: <剩余秒数>

auth: blocked for <duration>
```

---

## 六、公开资源白名单

### 6.1 无需认证的路径

**判断逻辑**：[internal/home/authhttp.go:298-324](internal/home/authhttp.go#L298-L324)

```go
func isPublicResource(p string) bool {
    isAsset, _ := path.Match("/assets/*", p)
    isLogin, _ := path.Match("/login.*", p)

    paths := []string{
        "/control/login",
        "/apple/doh.mobileconfig",
        "/apple/dot.mobileconfig",
        "/control/install/get_addresses",
        "/control/install/check_config",
        "/control/install/configure",
        "/install.html",
    }
    return isAsset || isLogin || slices.Contains(paths, p)
}
```

### 6.2 DoH 公开路由

DNS-over-HTTPS 路由也无需认证，由配置项 `HTTPConfig.DoH.Routes` 指定。

---

## 七、完整处理链路图

### 7.1 默认认证模式

```
HTTP 请求
    ↓
┌─────────────────────────────────┐
│  需要认证? (needsAuthentication)│
└───────────┬─────────────────────┘
            │ 否
            ├────────→ 直接放行
            │ 是
            ↓
┌─────────────────────────────────┐
│  提取用户 (userFromRequest)     │
│  ├─ 尝试 Cookie Session         │
│  └─ 失败则尝试 Basic Auth       │
└───────────┬─────────────────────┘
            │ 成功
            ├────────→ 已登录用户访问 login.html → 重定向到 /
            │        其他路径 → 注入用户上下文 → 业务 Handler
            │ 失败
            ↓
┌─────────────────────────────────┐
│  公开资源? (isPublicResource)   │
└───────────┬─────────────────────┘
            │ 是
            ├────────→ 直接放行
            │ 否
            ↓
┌─────────────────────────────────┐
│  访问 / 或 /index.html?         │
└───────────┬─────────────────────┘
            │ 是
            ├────────→ 重定向到 /login.html
            │ 否
            ↓
          返回 401 Unauthorized
```

### 7.2 GLiNet 认证模式

```
HTTP 请求
    ↓
┌─────────────────────────────────┐
│  公开资源 or DoH 路由?          │
└───────────┬─────────────────────┘
            │ 是
            ├────────→ 直接放行
            │ 否
            ↓
┌─────────────────────────────────┐
│  Cookie 认证 (Admin-Token)      │
│  ├─ 读取 Token 文件             │
│  └─ 检查时间戳 + TTL            │
└───────────┬─────────────────────┘
            │ 成功
            ├────────→ 放行
            │ 失败
            ↓
┌─────────────────────────────────┐
│  访问 / 或 /index.html?         │
└───────────┬─────────────────────┘
            │ 是
            ├────────→ 重定向到根域名
            │ 否
            ↓
          返回 401 Unauthorized
```

---

## 八、关键安全设计

### 8.1 密码安全
- 使用 bcrypt 算法存储密码哈希（cost = default）
- 密码验证使用恒定时间比较（bcrypt 内置）

### 8.2 Session 安全
- 16 字节加密安全随机 Token
- Cookie 设置 `HttpOnly` 防止 XSS 窃取
- Cookie 设置 `SameSite=Lax` 防止 CSRF
- 会话过期自动清理

### 8.3 限流安全
- 基于 IP 的失败计数
- 滑动窗口（1分钟内的失败累计）
- 超过阈值后封禁 N 分钟
- 每次 check 自动清理过期记录

### 8.4 代理信任
- `X-Real-IP`、`X-Forwarded-For` 等头仅在可信代理范围内使用
- 登录限流使用 `r.RemoteAddr` 而非代理头，防止伪造 IP 绕过限流

---

## 九、核心文件索引

| 功能模块 | 文件路径 |
|---------|---------|
| 认证中间件核心 | [internal/home/authhttp.go](internal/home/authhttp.go) |
| 认证管理器 | [internal/home/auth.go](internal/home/auth.go) |
| 限流实现 | [internal/home/authratelimiter.go](internal/home/authratelimiter.go) |
| GLiNet 认证 | [internal/home/authglinet.go](internal/home/authglinet.go) |
| Session 存储 | [internal/aghuser/sessionstorage.go](internal/aghuser/sessionstorage.go) |
| Session 数据结构 | [internal/aghuser/session.go](internal/aghuser/session.go) |
| 用户数据库 | [internal/aghuser/db.go](internal/aghuser/db.go) |
| 通用中间件 | [internal/home/middlewares.go](internal/home/middlewares.go) |
| 中间件注册 | [internal/home/web.go](internal/home/web.go) |

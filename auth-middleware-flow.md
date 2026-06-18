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

## 九、CSRF 防御机制

AdGuard Home **没有采用** 传统的 CSRF Token 方案，而是通过多层间接防御来阻止跨站请求伪造。以下逐一说明每一层防御的代码挂载位置和原理。

### 9.1 SameSite Cookie 策略（核心防御层）

**挂载位置**：登录成功时设置 Cookie 的属性

[internal/home/authhttp.go:235-241](internal/home/authhttp.go#L235-L241)

```go
return &http.Cookie{
    Name:     sessionCookieName,
    Value:    hex.EncodeToString(sess.Token[:]),
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode,
}, nil
```

**防御原理**：`SameSite=Lax` 意味着：
- 跨站顶级导航的 GET 请求**会**携带 Cookie（允许从外部链接跳转到 AGH）
- 跨站的 POST/PUT/DELETE 请求**不会**携带 Cookie（阻止 CSRF 攻击）
- 同站请求正常携带 Cookie

这是 AdGuard Home **最核心** 的 CSRF 防御手段。攻击者从恶意网站发起的跨站 POST 请求将被浏览器拦截 Session Cookie，导致认证失败。

### 9.2 Content-Type 校验（路由级防御层）

**挂载位置**：路由注册时的 `ensure` 方法 → `ensureContentType`

[internal/home/control.go:251-282](internal/home/control.go#L251-L282)

```go
func (web *webAPI) ensure(method string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        m := r.Method
        if m != method {
            // 405 Method Not Allowed
            return
        }

        if modifiesData(m) {  // POST / PUT / DELETE
            if !web.ensureContentType(w, r) {
                return  // 415 Unsupported Media Type
            }
            globalContext.controlLock.Lock()
            defer globalContext.controlLock.Unlock()
        }

        handler(w, r)
    }
}
```

[internal/home/control.go:289-336](internal/home/control.go#L289-L336)

```go
func (web *webAPI) ensureContentType(w http.ResponseWriter, r *http.Request) (ok bool) {
    cType := r.Header.Get(httphdr.ContentType)
    if r.ContentLength == 0 {
        if cType == "" {
            return true  // 无 body 且无 content-type，放行
        }
        // 有 content-type 但无 body → 拒绝
    }

    if cType == aghhttp.HdrValApplicationJSON {
        return true  // 仅允许 application/json
    }
    // 415 Unsupported Media Type
    return false
}
```

**防御原理**：
- HTML `<form>` 提交的 Content-Type 是 `application/x-www-form-urlencoded` 或 `multipart/form-data`
- AGH 的所有数据修改 API **强制要求** `Content-Type: application/json`
- 浏览器同源策略禁止跨域 JavaScript 设置非标准 Content-Type（除非 CORS 预检通过）
- 因此 CSRF 攻击者无法伪造合法的 `application/json` 请求

**路由级中间件注册链**：

[internal/home/home.go:772-774](internal/home/home.go#L772-L774)

```go
mw := &webMw{}
mux := http.NewServeMux()
httpReg := aghhttp.NewDefaultRegistrar(mux, mw.wrap)
```

[internal/home/control.go:232-237](internal/home/control.go#L232-L237)

```go
func (mw *webMw) set(web *webAPI) {
    mw.postInstallMw = web.postInstallHandler
    mw.ensureMw = func(method string, h http.HandlerFunc) http.Handler {
        return web.postInstallHandler(gziphandler.GzipHandler(web.ensure(method, h)))
    }
}
```

即每个通过 `httpReg.Register` 注册的 API 路由会经过：

```
httpReg.Register(method, path, handler)
    ↓
mw.wrap(method, handler)
    ↓
mw.ensureMw(method, handler)
    ↓
postInstallHandler → gzipHandler → ensure(method检查 + contentType检查) → handler
```

### 9.3 CORS 限制（跨域隔离层）

**挂载位置**：HTTPS 重定向处理中

[internal/home/control.go:410-421](internal/home/control.go#L410-L421)

```go
originURL := &url.URL{
    Scheme: urlutil.SchemeHTTP,
    Host:   r.Host,
}
respHdr.Set(httphdr.AccessControlAllowOrigin, originURL.String())
respHdr.Set(httphdr.Vary, httphdr.Origin)
```

**防御原理**：
- `Access-Control-Allow-Origin` 仅设置为 `http://<当前Host>`，不使用通配符 `*`
- 跨域 JavaScript 请求因 CORS 策略被浏览器阻止
- 此层仅在 HTTPS 强制重定向场景下生效

### 9.4 CSRF 防御总结

| 防御层 | 机制 | 挂载位置 | 防护范围 |
|--------|------|---------|---------|
| SameSite=Lax | 浏览器阻止跨站 POST Cookie | authhttp.go:241 | 所有需要认证的 POST 请求 |
| Content-Type 校验 | 拒绝非 JSON 请求 | control.go:271-278 | 所有数据修改 API |
| 空Body+ContentType 拒绝 | 阻止表单风格伪造 | control.go:303-313 | 有 ContentType 但无 Body 的请求 |
| CORS Origin 限制 | 仅允许同源域 | control.go:415-421 | 跨域 JS 请求 |

> **结论**：AdGuard Home 没有使用 CSRF Token，而是依赖 `SameSite=Lax` + `Content-Type: application/json` 强制要求的双重间接防御。这在现代浏览器（2020+）环境下是有效的，但对非常老的浏览器（不支持 SameSite）不提供保护。

---

## 十、鉴权失败审计日志

### 10.1 登录接口审计

**挂载位置**：`handleLogin` 中的 `writeErrorWithIP`

[internal/home/authhttp.go:85-105](internal/home/authhttp.go#L85-L105)

```go
func (web *webAPI) writeErrorWithIP(
    ctx context.Context,
    err error,
    r *http.Request,
    w http.ResponseWriter,
    code int,
    remoteIP string,
) {
    web.logger.ErrorContext(
        ctx,
        "http error",
        "host", r.Host,
        "method", r.Method,
        "url", r.URL,
        "status", code,
        "ip", remoteIP,
        slogutil.KeyError, err,
    )
    http.Error(w, err.Error(), code)
}
```

**审计日志触发点**（登录流程）：

| 场景 | HTTP 状态码 | 日志级别 | 日志内容 | 代码位置 |
|------|-----------|---------|---------|---------|
| 远程地址解析失败 | 400 | Error | `auth: getting remote address` | authhttp.go:125-135 |
| 限流命中 | 429 | Error | `auth: blocked for <duration>` | authhttp.go:140-151 |
| IP 地址解析失败 | 500 | Error | `auth: parsing remote address` | authhttp.go:165-175 |
| 用户名或密码错误 | 403 | Error | `invalid username or password` | authhttp.go:184 |

**登录成功审计**：

[internal/home/authhttp.go:189](internal/home/authhttp.go#L189)

```go
web.logger.InfoContext(ctx, "successful login", "user", req.Name, "ip", logIP)
```

### 10.2 认证中间件审计

**挂载位置**：`authMiddlewareDefault.handleAuthenticatedUser`

[internal/home/authhttp.go:436-444](internal/home/authhttp.go#L436-L444)

```go
u, err := mw.userFromRequest(ctx, r)
if err != nil {
    mw.logger.ErrorContext(ctx, "retrieving user from request", slogutil.KeyError, err)
}
if u == nil {
    mw.logger.DebugContext(ctx, "no user found in request")
    return false
}
```

| 场景 | 日志级别 | 日志内容 | 说明 |
|------|---------|---------|------|
| Session Token 解析/查找出错 | Error | `retrieving user from request` | Cookie 存在但 Token 非法或存储异常 |
| 无有效凭据 | Debug | `no user found in request` | Cookie 缺失 + Basic Auth 缺失，或凭据无效 |

> **注意**：认证中间件中**没有**记录未认证请求的来源 IP。中间件在无凭据时仅记录 Debug 级别的 `"no user found in request"`，不包含 IP 信息。仅登录接口 (`handleLogin`) 通过 `writeErrorWithIP` 记录了来源 IP。

### 10.3 Basic Auth 审计

**挂载位置**：`userFromRequestBasicAuth`

[internal/home/authhttp.go:575-597](internal/home/authhttp.go#L575-L597)

Basic Auth 的审计**不在中间件层**，而是通过限流计数间接体现：
- 限流命中：`rateLimiter.check` 返回 `left > 0` → 中间件返回 `nil`，上层记录 Error
- 用户名错误：`errInvalidLogin` → defer 中 `rateLimiter.inc`
- 密码错误：`errInvalidLogin` → defer 中 `rateLimiter.inc`
- 成功：defer 中 `rateLimiter.remove`

### 10.4 GLiNet 审计

[internal/home/authglinet.go:147](internal/home/authglinet.go#L147)

```go
mw.logger.ErrorContext(ctx, "no authentication cookie", slogutil.KeyError, err)
```

[internal/home/authglinet.go:165](internal/home/authglinet.go#L165)

```go
mw.logger.DebugContext(ctx, "authentication token has expired")
```

### 10.5 通用 API 错误审计

[internal/aghhttp/aghhttp.go:31-53](internal/aghhttp/aghhttp.go#L31-L53)

```go
func ErrorAndLog(ctx context.Context, l *slog.Logger, r *http.Request, w http.ResponseWriter,
    code int, format string, args ...any) {
    text := fmt.Sprintf(format, args...)
    l.WarnContext(ctx, "http error",
        "host", r.Host,
        "method", r.Method,
        "raddr", r.RemoteAddr,
        "request_uri", r.RequestURI,
        "status", code,
        slogutil.KeyError, text,
    )
    http.Error(w, text, code)
}
```

**审计信息字段**：

| 字段 | 来源 | 说明 |
|------|------|------|
| `host` | `r.Host` | 请求的 Host 头 |
| `method` | `r.Method` | HTTP 方法 |
| `url` / `request_uri` | `r.URL` / `r.RequestURI` | 请求路径 |
| `status` | 函数参数 | HTTP 状态码 |
| `ip` / `raddr` | `remoteIP` / `r.RemoteAddr` | 客户端 IP |
| `error` | 错误信息 | 具体错误描述 |

---

## 十一、Session 续期分析

### 11.1 Session TTL 配置

**配置**：[internal/home/config.go:194-196](internal/home/config.go#L194-L196)

```go
type httpConfig struct {
    SessionTTL timeutil.Duration `yaml:"session_ttl"`
}
```

**默认值**：[internal/home/config.go:462](internal/home/config.go#L462)

```go
SessionTTL: timeutil.Duration(30 * timeutil.Day),  // 默认 30 天
```

### 11.2 Session 创建时的过期时间

[internal/aghuser/sessionstorage.go:325-331](internal/aghuser/sessionstorage.go#L325-L331)

```go
func (ds *DefaultSessionStorage) New(ctx context.Context, u *User) (*Session, error) {
    s := &Session{
        Token:     NewSessionToken(),
        UserID:    u.ID,
        UserLogin: u.Login,
        Expire:    ds.clock.Now().Add(ds.sessionTTL),  // 创建时间 + TTL
    }
    // ...
}
```

### 11.3 Session 查找时的过期检查（无续期）

[internal/aghuser/sessionstorage.go:380-400](internal/aghuser/sessionstorage.go#L380-L400)

```go
func (ds *DefaultSessionStorage) FindByToken(ctx context.Context, t SessionToken) (*Session, error) {
    ds.mu.Lock()
    defer ds.mu.Unlock()

    s, ok := ds.sessions[t]
    if !ok {
        return nil, nil
    }

    now := ds.clock.Now()
    if now.After(s.Expire) {
        err = ds.deleteByToken(ctx, t)
        return nil, nil  // 过期则删除，不续期
    }

    return s, nil  // 未过期则返回，但不更新 Expire
}
```

**关键结论**：AdGuard Home **没有实现 Session 续期机制**。

- Session 创建时设置 `Expire = now + sessionTTL`
- 每次 `FindByToken` 仅检查是否过期，过期则删除
- **不会**在用户活动时延长过期时间
- Cookie 的 `Expires` 字段设为 `time.Now().Add(cookieTTL)`（365 天），但 Session 本身的 TTL 由配置决定（默认 30 天）
- 这意味着：即使用户每天活跃使用，Session 也会在 30 天后硬性过期，用户必须重新登录

### 11.4 Cookie TTL 与 Session TTL 的关系

| 时间维度 | 值 | 代码位置 |
|---------|---|---------|
| Cookie `Expires` | 365 天 | authhttp.go:29,239 |
| Session `Expire` | 默认 30 天（可配置 `session_ttl`） | config.go:462 |
| 实际会话有效期 | **取决于 Session TTL**（取较短者） | sessionstorage.go:330 |

Cookie 365 天过期 ≠ 会话 365 天有效。Cookie 只是浏览器端保存 Token 的容器，实际会话有效期由服务端 Session TTL 决定。

---

## 十二、限流命中后的回退响应

### 12.1 登录接口限流响应

**挂载位置**：[internal/home/authhttp.go:137-151](internal/home/authhttp.go#L137-L151)

```go
if rateLimiter := web.auth.rateLimiter; rateLimiter != nil {
    if left := rateLimiter.check(remoteIPStr); left > 0 {
        w.Header().Set(httphdr.RetryAfter, strconv.Itoa(int(left.Seconds())))
        web.writeErrorWithIP(
            ctx,
            fmt.Errorf("auth: blocked for %s", left),
            r,
            w,
            http.StatusTooManyRequests,
            remoteIPStr,
        )
        return
    }
}
```

**响应格式**：

```http
HTTP/1.1 429 Too Many Requests
Retry-After: <剩余封禁秒数>
Content-Type: text/plain; charset=utf-8

auth: blocked for 1m30s
```

**响应特征**：
- 状态码 `429 Too Many Requests`
- `Retry-After` 头告知客户端剩余封禁时间（秒）
- 响应体为纯文本错误描述
- 日志记录 Error 级别，包含来源 IP

### 12.2 Basic Auth 限流响应

**挂载位置**：[internal/home/authhttp.go:575-578](internal/home/authhttp.go#L575-L578)

```go
rateLimiter := mw.rateLimiter
if left := rateLimiter.check(remoteIP); left > 0 {
    return nil, fmt.Errorf("login attempt blocked for %s", left)
}
```

**响应特征**：
- Basic Auth 的限流发生在中间件层的 `userFromRequestBasicAuth` 中
- 限流命中时返回 `nil, error`
- 上层 `handleAuthenticatedUser` 检测到 `u == nil`，走到 `handlePublicAccess` 或返回 `401`
- **不会返回 429**，而是返回 `401 Unauthorized`
- **不设置 `Retry-After` 头**
- 审计日志仅为 Debug 级别的 `"no user found in request"`

> **注意**：这是一个设计上的不一致。登录接口限流返回 429 + Retry-After，但 Basic Auth 限流被"吞掉"变成 401。客户端无法通过 HTTP 状态码区分"密码错误"和"被限流"。

### 12.3 限流状态流转

```
初始状态: 无记录
    ↓ inc(ip)
1次失败: num=1, until=now+1min
    ↓ inc(ip)
2次失败: num=2, until=now+1min  (保留原 until)
    ↓ ...
N次失败 (N ≥ maxAttempts): num=N, until=now+blockDur  (延长封禁)
    ↓ check(ip)
返回 left = until - now > 0 → 429 / 401
    ↓ 等待 until 过期
cleanupLocked 自动清理
    ↓ 或认证成功
remove(ip) → 清除记录
```

---

## 十三、认证中间件完整执行顺序

### 13.1 全局中间件链（HTTP Server 层）

以 HTTP 明文服务器为例，完整链路：

[internal/home/web.go:262-290](internal/home/web.go#L262-L290)

```
HTTP 请求到达
    ↓
┌────────────────────────────────────────────────┐
│ 1. http.Server                                  │
│    - ReadTimeout / WriteTimeout                 │
│    - ReadHeaderTimeout                          │
│    - Protocols: HTTP/1.1, unencrypted H2        │
└───────────────────────┬────────────────────────┘
                        ↓
┌────────────────────────────────────────────────┐
│ 2. auth.middleware().Wrap(hdlr)                 │
│    即 authMiddlewareDefault.Wrap               │
│    ┌──────────────────────────────────────────┐│
│    │ 2a. needsAuthentication?                 ││
│    │     否 → 跳过认证                        ││
│    │     是 ↓                                 ││
│    │ 2b. handleAuthenticatedUser              ││
│    │     ├─ userFromCookie                    ││
│    │     │   ├─ Cookie 不存在 →               ││
│    │     │   └─ Cookie 存在 →                 ││
│    │     │       ├─ hex解码 → sessionTokenFromHex│
│    │     │       ├─ 查找会话 → sessions.FindByToken│
│    │     │       └─ 查找用户 → users.ByLogin   ││
│    │     └─ userFromRequestBasicAuth           ││
│    │         ├─ Basic Auth 头不存在 → nil      ││
│    │         ├─ 限流检查 → rateLimiter.check   ││
│    │         ├─ 用户查找 → users.ByLogin       ││
│    │         ├─ 密码验证 → bcrypt              ││
│    │         └─ 成功 remove/失败 inc 限流计数   ││
│    │ 2c. handlePublicAccess                    ││
│    │     ├─ isPublicResource                   ││
│    │     ├─ isDoHRoute                         ││
│    │     └─ 根路径重定向                        ││
│    │ 2d. 401 Unauthorized                      ││
│    └──────────────────────────────────────────┘│
└───────────────────────┬────────────────────────┘
                        ↓
┌────────────────────────────────────────────────┐
│ 3. logMw.Wrap(hdlr)                             │
│    日志中间件 (slog LevelDebug)                 │
└───────────────────────┬────────────────────────┘
                        ↓
┌────────────────────────────────────────────────┐
│ 4. withMiddlewares(mux, limitRequestBody)       │
│    请求体大小限制 (64KB / 4MB)                  │
└───────────────────────┬────────────────────────┘
                        ↓
┌────────────────────────────────────────────────┐
│ 5. http.ServeMux 路由分发                       │
└───────────────────────┬────────────────────────┘
                        ↓
           ┌────────────┴────────────┐
           ↓                         ↓
    /control/* API路由          / 静态资源路由
           ↓                         ↓
┌─────────────────────┐   ┌──────────────────────┐
│ 6. ensure(method,h) │   │ postInstallHandler   │
│   ├─ 方法检查       │   │   ├─ 安装状态检查     │
│   ├─ Content-Type   │   │   └─ HTTPS重定向      │
│   └─ controlLock    │   │ gzipHandler          │
└─────────┬───────────┘   └──────────────────────┘
          ↓
┌─────────────────────┐
│ 7. 业务 Handler      │
│   可通过            │
│   webUserFromContext │
│   获取当前用户      │
└─────────────────────┘
```

### 13.2 路由级中间件链（API 路由）

通过 `httpReg.Register` 注册的 API 路由：

[internal/home/control.go:232-237](internal/home/control.go#L232-L237)

```
httpReg.Register(method, path, handler)
    ↓ wrapFn(method, handler)
    ↓ mw.ensureMw(method, handler)
    ↓
postInstallHandler(handler)
    ├─ firstRun → 重定向到 /install.html
    └─ !firstRun ↓
handleHTTPSRedirect(handler)
    ├─ forceHTTPS + 非TLS → 307 重定向到 HTTPS
    ├─ 设置 HSTS 头
    ├─ 设置 Access-Control-Allow-Origin
    └─ 继续 ↓
gzipHandler(handler)
    ↓
ensure(method, handler)
    ├─ 方法不匹配 → 405
    ├─ 数据修改方法 (POST/PUT/DELETE) →
    │   ├─ ensureContentType
    │   │   ├─ Content-Length=0 + 无CT → 放行
    │   │   ├─ Content-Length=0 + 有CT → 415
    │   │   ├─ CT=application/json → 放行
    │   │   └─ 其他CT → 415
    │   └─ globalContext.controlLock (并发保护)
    └─ 继续 ↓
业务 handler
```

### 13.3 用户上下文传递

认证成功后，用户信息通过 Context 传递到业务层：

[internal/home/context.go:37-55](internal/home/context.go#L37-L55)

```
authMiddlewareDefault.handleAuthenticatedUser
    ↓
withWebUser(ctx, u)  →  context.WithValue(ctx, ctxKeyWebUser, u)
    ↓
r.WithContext(withUser)  →  新 Request 带用户上下文
    ↓
h.ServeHTTP(w, r)  →  传递到后续中间件和 Handler
    ↓
业务 Handler 中:
    u, ok := webUserFromContext(ctx)  →  获取当前用户
```

**消费位置示例**：

[internal/home/profilehttp.go:54-61](internal/home/profilehttp.go#L54-L61)

```go
u, ok := webUserFromContext(ctx)
if !ok {
    w.WriteHeader(http.StatusUnauthorized)
    return
}
name = string(u.Login)
```

### 13.4 三种 Server 的中间件一致性

HTTP、HTTPS、HTTP/3 三个服务器使用相同的中间件链：

| 服务器 | Handler 构建 | 代码位置 |
|--------|-------------|---------|
| HTTP | `auth.middleware().Wrap(logMw.Wrap(limitRequestBody(mux)))` | web.go:266-274 |
| HTTPS | `auth.middleware().Wrap(logMw.Wrap(limitRequestBody(mux)))` | web.go:365-369 |
| HTTP/3 | `auth.middleware().Wrap(limitRequestBody(mux))` | web.go:433 |

> **注意**：HTTP/3 服务器**缺少**日志中间件 `logMw`，这可能是疏忽。

---

## 十四、核心文件索引

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
| 路由级中间件 (ensure/ContentType) | [internal/home/control.go](internal/home/control.go) |
| 用户上下文传递 | [internal/home/context.go](internal/home/context.go) |
| 路由注册器 | [internal/aghhttp/registrar.go](internal/aghhttp/registrar.go) |
| HTTP 错误审计 | [internal/aghhttp/aghhttp.go](internal/aghhttp/aghhttp.go) |
| 会话配置 | [internal/home/config.go](internal/home/config.go) |
| Profile 鉴权消费示例 | [internal/home/profilehttp.go](internal/home/profilehttp.go) |

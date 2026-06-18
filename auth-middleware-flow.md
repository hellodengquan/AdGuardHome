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

### 9.5 CSRF Token 轮换：代码不存在与并发风险推演

#### 9.5.1 代码库中不存在 CSRF Token 轮换

经过对整个代码库的搜索，确认以下事实：

| 搜索关键词 | 搜索范围 | 结果 |
|-----------|---------|------|
| `csrf` / `xsrf` / `csrfToken` | `**/*.go` | 无匹配 |
| `rotate` / `rotation` / `regenerate` | `**/*.go` | 仅匹配 querylog 轮转，无鉴权相关 |
| `nonce` | `**/*.go` | 无匹配 |
| `_token` | `**/*.go` | 仅匹配 GLiNet `gl_token_*` 文件前缀 |

**结论**：代码库中**完全没有** CSRF Token 的生成、验证、轮换逻辑。因此也不存在 "CSRF token 轮换时并发更新" 的代码挂载点。

#### 9.5.2 Session Token 是唯一的 Token 机制

AdGuard Home 唯一与 "token" 相关的机制是 **Session Token**，它在登录时生成：

[internal/aghuser/session.go:14-21](internal/aghuser/session.go#L14-L21)

```go
func NewSessionToken() (t SessionToken) {
    _, _ = rand.Read(t[:])  // 16字节 crypto/rand
    return t
}
```

**Session Token 的生命周期**：

```
创建:  登录成功 → sessions.New() → NewSessionToken() → store(bbolt) → 内存map写入
使用:  每次请求 → Cookie 携带 → FindByToken() → 内存map查找
销毁:  登出 → DeleteByToken() → remove(bbolt) → 内存map删除
过期:  FindByToken() 检查 Expire → deleteByToken()
```

**关键点**：Session Token 在创建后**永远不会被轮换或替换**。同一个 Token 从登录到过期/登出始终不变。

#### 9.5.3 如果存在 CSRF Token 轮换，并发风险会挂载在哪里

虽然代码库没有 CSRF Token 轮换，但为了理解 "如果存在" 时的并发风险，以下是推演分析。

**假设 CSRF Token 轮换设计**：每次请求后重新生成 CSRF Token，新旧 Token 短暂并存。

**并发风险挂载点推演**：

```
假设的 CSRF Token 轮换流程:
    请求到达
    ↓
验证 CSRF Token (读 map[token] → 比对)
    ↓
生成新 CSRF Token (crypto/rand → 新 token)
    ↓
更新存储 (map[old] = nil, map[new] = value)  ← 并发风险挂载点
    ↓
写入响应 Header / Cookie (Set-Cookie: new_token)
```

**并发风险场景**：

```
Tab 1: 请求 → 验证 token_A → 生成 token_B → 存储 token_B → 响应 Set-Cookie: token_B
Tab 2: 请求 → 验证 token_A (还没收到 token_B) → 生成 token_C → 存储 token_C
    问题: Tab 1 收到 token_B 但 Tab 2 已经生成了 token_C
    token_B 和 token_C 哪个有效？如果只保留最新，Tab 1 的 token_B 失效
```

**在当前代码中的等价风险**：

虽然不存在 CSRF Token 轮换，但**多 Tab 同时登录**会触发类似的并发场景：

```
Tab 1: POST /control/login → newCookie() → sessions.New() → Token_A
Tab 2: POST /control/login → newCookie() → sessions.New() → Token_B
```

两个 Tab 登录成功后会创建**两个不同的 Session**，各自有独立的 Token。这不是 bug（设计如此），但意味着同一用户可以同时持有多个有效 Session。

**并发写入的实际代码挂载点**：

[internal/aghuser/sessionstorage.go:325-343](internal/aghuser/sessionstorage.go#L325-L343)

```go
func (ds *DefaultSessionStorage) New(ctx context.Context, u *User) (s *Session, err error) {
    s = &Session{
        Token:  NewSessionToken(),   // ① 锁外：生成随机 Token
        // ...
    }

    err = ds.store(s)               // ② 锁外：写入 bbolt（事务内）
    if err != nil {
        return nil, fmt.Errorf("storing session: %w", err)
    }

    ds.mu.Lock()                    // ③ 加锁
    defer ds.mu.Unlock()
    ds.sessions[s.Token] = s        // ④ 锁内：写入内存 map
    return s, nil
}
```

**并发风险分析**：

| 步骤 | 是否在锁内 | 并发风险 |
|------|-----------|---------|
| ① 生成 Token | ❌ 锁外 | 无风险（Token 是随机的，碰撞概率可忽略） |
| ② 写入 bbolt | ❌ 锁外 | bbolt 内部有事务锁，不会并发冲突 |
| ③④ 内存 map 写入 | ✅ 锁内 | `ds.mu` 保护，不会并发冲突 |

**结论**：多 Tab 同时登录时，`sessions.New()` 的并发写入是安全的。但不存在 Token 轮换，因此不存在 Token 轮换时的并发更新风险。

---

## 十、鉴权失败审计日志

### 10.1 管理员登录成功路径的完整审计链

登录成功的代码从 `handleLogin` 到最终 HTTP 响应，经过以下完整审计链路：

```
POST /control/login
    │
    ▼
[步骤 1] JSON 解码
    代码: authhttp.go:111-117
    失败: aghhttp.ErrorAndLog → 400 + Warn 级别 "http error" (含 method/raddr/request_uri)
    审计字段: method, request_uri, status, error
    缺失字段: ❌ 无 IP（此时还未提取 IP）
    │
    ▼ 成功
[步骤 2] 提取远程 IP
    代码: authhttp.go:119-135
    失败: writeErrorWithIP → 400 + Error 级别 "auth: getting remote address"
    审计字段: host, method, url, status, ip, error
    ✅ 此处开始有 IP 审计
    │
    ▼ 成功
[步骤 3] 限流检查
    代码: authhttp.go:137-151
    命中: writeErrorWithIP → 429 + Error 级别 "auth: blocked for <duration>"
          + Retry-After 响应头
    审计字段: host, method, url, status, ip, error
    ✅ 有 IP，有封禁时长
    │
    ▼ 未命中
[步骤 4] 解析 realIP（用于日志显示）
    代码: authhttp.go:153-161
    失败: Error 级别 "getting real ip" + remote_ip
    注意: 此步骤仅影响日志中显示的 IP（logIP），不影响认证
    如果解析失败，logIP 退回到 remoteIPStr
    │
    ▼
[步骤 5] 解析 remoteIP（用于可信代理判断）
    代码: authhttp.go:163-175
    失败: writeErrorWithIP → 500 + Error 级别 "auth: parsing remote address"
    审计字段: host, method, url, status, ip, error
    ✅ 有 IP
    │
    ▼ 成功
[步骤 6] 确定日志 IP（logIP）
    代码: authhttp.go:177-180
    逻辑: 如果 remoteIP 在 trustedProxies 内，logIP = realIP
          否则 logIP = remoteIPStr
    无审计: 仅内部变量赋值
    │
    ▼
[步骤 7] 创建 Cookie（认证核心）
    代码: authhttp.go:182 → newCookie() → authhttp.go:202-243
    失败路径 (7a): 用户不存在
        代码: authhttp.go:215-218
        操作: rateLimiter.inc(addr)
        返回: errInvalidLogin → writeErrorWithIP → 403 + Error 级别
        审计字段: host, method, url, status, ip, error
        ✅ 有 IP，有限流计数
        ❌ 但日志内容仅为 "invalid username or password"，无法区分用户不存在还是密码错误
    失败路径 (7b): 密码错误
        代码: authhttp.go:221-226
        操作: rateLimiter.inc(addr)
        返回: errInvalidLogin → writeErrorWithIP → 403 + Error 级别
        审计字段: 同上
        ❌ 与用户不存在返回相同错误信息（安全设计，但影响审计可读性）
    成功路径 (7c): 认证成功
        代码: authhttp.go:228
        操作: rateLimiter.remove(addr)
        无独立日志: 仅清除限流计数
    │
    ▼ 成功
[步骤 8] 创建 Session
    代码: newCookie() → authhttp.go:230-233
    失败: sessions.New() 返回错误 → 直接返回，无独立审计日志
          上层 writeErrorWithIP → 403 + Error 级别 "storing session"
    │
    ▼ 成功
[步骤 9] 登录成功审计日志 ★
    代码: authhttp.go:189
    ────────────────────────────────────────────
    web.logger.InfoContext(ctx, "successful login",
        "user", req.Name,
        "ip", logIP)
    ────────────────────────────────────────────
    审计字段: user (用户名), ip (经过可信代理判断的 IP)
    日志级别: Info
    ✅ 有用户名 + IP
    ❌ 无 User-ID、无 Session Token、无 User-Agent、无请求路径
    │
    ▼
[步骤 10] 设置响应
    代码: authhttp.go:191-198
    操作: Set-Cookie (agh_session) + Cache-Control: no-store + OK
    无审计
```

**登录成功路径审计链总览**：

| 步骤 | 代码位置 | 审计动作 | 日志级别 | 关键字段 |
|------|---------|---------|---------|---------|
| 2 | authhttp.go:124-135 | IP 提取失败 | Error | ip, error |
| 3 | authhttp.go:137-151 | 限流命中 | Error | ip, error, Retry-After |
| 4 | authhttp.go:153-161 | realIP 解析失败 | Error | remote_ip, error |
| 5 | authhttp.go:163-175 | remoteIP 解析失败 | Error | ip, error |
| 7a | authhttp.go:215-218 + 184 | 用户不存在 | Error | ip, error |
| 7b | authhttp.go:221-226 + 184 | 密码错误 | Error | ip, error |
| **9** | **authhttp.go:189** | **登录成功** | **Info** | **user, ip** |
| 10 | authhttp.go:191-198 | 设置 Cookie + OK | 无 | — |

### 10.2 管理员登录失败路径的完整审计链

登录失败的所有可能路径和审计记录：

```
POST /control/login
    │
    ├─ [FAIL-A] JSON 解码失败
    │     代码: authhttp.go:112-117
    │     响应: 400 Bad Request
    │     审计: aghhttp.ErrorAndLog → Warn "http error"
    │     字段: method, raddr, request_uri, status, error
    │     缺失: ❌ 无 IP（此时尚未提取）
    │     日志输出: "json decode: <error>"
    │
    ├─ [FAIL-B] 远程 IP 提取失败
    │     代码: authhttp.go:124-135
    │     响应: 400 Bad Request
    │     审计: writeErrorWithIP → Error "http error"
    │     字段: host, method, url, status, ip=r.RemoteAddr, error
    │     日志输出: "auth: getting remote address: <error>"
    │
    ├─ [FAIL-C] 限流命中
    │     代码: authhttp.go:137-151
    │     响应: 429 Too Many Requests + Retry-After 头
    │     审计: writeErrorWithIP → Error "http error"
    │     字段: host, method, url, status, ip, error
    │     日志输出: "auth: blocked for 1m30s"
    │     特殊: 响应体包含封禁时长，Retry-After 头包含秒数
    │
    ├─ [FAIL-D] remoteIP 解析失败
    │     代码: authhttp.go:163-175
    │     响应: 500 Internal Server Error
    │     审计: writeErrorWithIP → Error "http error"
    │     字段: host, method, url, status, ip=r.RemoteAddr, error
    │     日志输出: "auth: parsing remote address: <error>"
    │
    ├─ [FAIL-E] 用户不存在
    │     代码: authhttp.go:215-218 → 184
    │     响应: 403 Forbidden
    │     审计: writeErrorWithIP → Error "http error"
    │     字段: host, method, url, status, ip=logIP, error
    │     日志输出: "invalid username or password"
    │     副作用: rateLimiter.inc(addr) — 限流计数 +1
    │     特殊: ❌ 无法区分 "用户不存在" 和 "密码错误"
    │
    ├─ [FAIL-F] 密码错误
    │     代码: authhttp.go:221-226 → 184
    │     响应: 403 Forbidden
    │     审计: writeErrorWithIP → Error "http error"
    │     字段: 同 FAIL-E
    │     日志输出: "invalid username or password"
    │     副作用: rateLimiter.inc(addr) — 限流计数 +1
    │     特殊: ❌ 与 FAIL-E 返回完全相同的错误信息
    │
    └─ [FAIL-G] Session 创建失败
          代码: authhttp.go:230-233 → 184
          响应: 403 Forbidden
          审计: writeErrorWithIP → Error "http error"
          字段: host, method, url, status, ip=logIP, error
          日志输出: "storing session: <error>"
          副作用: rateLimiter.remove(addr) — 已清除限流（因为认证已通过）
          特殊: 认证成功但 Session 存储失败，理论上不应该发生
```

**登录失败路径审计字段完整性**：

| 字段 | FAIL-A | FAIL-B | FAIL-C | FAIL-D | FAIL-E | FAIL-F | FAIL-G |
|------|--------|--------|--------|--------|--------|--------|--------|
| IP 地址 | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 用户名 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| HTTP 方法 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 请求路径 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 状态码 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 错误详情 | ✅ | ✅ | ✅ | ✅ | ❌* | ❌* | ✅ |
| 限流状态 | — | — | ✅ | — | ✅ (inc) | ✅ (inc) | ✅ (remove) |
| User-Agent | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

*FAIL-E/F 的错误信息统一为 `"invalid username or password"`，无法区分具体原因。

**关键审计缺陷**：

1. **FAIL-A 无 IP**：JSON 解码失败时还未提取远程 IP，无法追溯恶意请求来源
2. **FAIL-E/F 不区分原因**：安全设计选择（防止用户名枚举），但降低了审计可读性
3. **所有失败路径无 User-Agent**：无法识别攻击工具特征
4. **所有失败路径无用户名**：即使 FAIL-E/F 时已知提交的用户名，也不记录
5. **无限流计数审计**：`rateLimiter.inc()` 是内存操作，不产生日志

### 10.3 认证中间件审计

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

#### 10.2.1 未授权 API 访问漏审计的完整代码路径

未授权 API 请求从进入到返回 401，经过的完整代码路径和审计点如下：

```
请求到达 authMiddlewareDefault.Wrap
    │
    ├─ [审计点 1] needsAuthentication() → 无用户时直接放行
    │     (无审计)
    │
    └─ 有用户 → handleAuthenticatedUser()
          │
          ├─ userFromRequest()
          │     ├─ 尝试 Cookie 认证 → userFromCookie
          │     │     ├─ Cookie 不存在 → 无日志
          │     │     ├─ Token 解析失败 → 错误向上传递
          │     │     └─ Session 不存在/过期 → 返回 nil
          │     └─ 失败则尝试 Basic Auth → userFromRequestBasicAuth
          │           ├─ 无 Basic Auth 头 → 返回 nil, nil
          │           ├─ 限流命中 → 返回 nil, error
          │           └─ 密码错误 → 返回 nil, error
          │
          ├─ [审计点 2] err != nil → Error 级别 "retrieving user from request"
          │     (无 IP，只有错误信息)
          │
          ├─ [审计点 3] u == nil → Debug 级别 "no user found in request"
          │     (无 IP，无路径，无方法)
          │
          └─ return false → 进入 handlePublicAccess()
                │
                ├─ 公开资源 → 直接放行 (无审计)
                ├─ DoH 路由 → 直接放行 (无审计)
                └─ 根路径 → 重定向到 login.html (无审计)
                      │
                      └─ 其他路径 → 最终返回 401
                            │
                            └─ [审计点 4] w.WriteHeader(401)
                                  (完全没有审计日志！)
```

**四处关键漏审计位置**：

| 位置 | 场景 | 审计缺失 | 代码位置 |
|------|------|---------|---------|
| 审计点 1 | 首次安装/无用户时跳过认证 | 所有请求都无审计 | authhttp.go:408-412 |
| 审计点 2 | 认证过程出错（如限流命中） | Error 级别但不含 IP | authhttp.go:437-439 |
| 审计点 3 | 无有效凭据（最常见） | Debug 级别且不含 IP/方法/路径 | authhttp.go:441-444 |
| 审计点 4 | 最终返回 401 | **完全没有日志** | authhttp.go:423 |

**最严重的漏审计：最终 401 响应**

[internal/home/authhttp.go:423](internal/home/authhttp.go#L423)

```go
// Wrap 方法最后一行
w.WriteHeader(http.StatusUnauthorized)
```

这行代码直接返回 401，**没有任何日志记录**。既不记录请求来源 IP，也不记录请求路径和方法。这意味着：

- 攻击者暴力扫描 API 路径时不会留下审计痕迹
- 无法事后追溯哪些未授权请求访问了哪些接口
- 无法统计未授权访问的频率和来源

#### 10.2.2 各认证方式的审计粒度对比

| 认证方式 | 成功审计 | 失败审计 | 失败时是否有 IP | 日志级别 |
|---------|---------|---------|---------------|---------|
| 登录接口 (Session) | ✅ `"successful login"` 含用户+IP | ✅ 含 IP | ✅ | Info / Error |
| Session Cookie | ❌ 无成功审计 | ❌ 仅 Debug | ❌ | Debug |
| Basic Auth | ❌ 无成功审计 | ❌ 仅 Debug（限流时 Error） | ❌ | Debug / Error |
| GLiNet Token | ❌ 无成功审计 | ✅ Error 级 "no authentication cookie" | ❌ | Error / Debug |
| 最终 401 响应 | — | ❌ **完全无日志** | ❌ | 无 |

**设计不一致性**：
- 登录接口的审计最完善（有 IP、有用户、有明确级别）
- 认证中间件的审计粒度极粗（Debug 级别，无 IP）
- 最终返回 401 时完全没有审计

这导致一个安全盲区：攻击者可以通过 API 接口进行大量未授权尝试，而只会在日志中留下模糊的 `"no user found in request"` Debug 记录，甚至在某些路径上什么都不留下。

#### 10.2.3 业务层二次鉴权的漏审计

除了认证中间件层的漏审计，部分业务 Handler 内部还会进行二次鉴权检查，这些检查的失败也通常没有审计：

**示例：profile 接口**

[internal/home/profilehttp.go:53-59](internal/home/profilehttp.go#L53-L59)

```go
u, ok := webUserFromContext(ctx)
if !ok {
    w.WriteHeader(http.StatusUnauthorized)
    return
}
```

- 直接返回 401，**完全没有日志**
- 理论上不会走到这里（中间件已认证），但属于防御性编程
- 如果中间件出现逻辑漏洞导致绕过，这里也不会留下审计痕迹

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

### 10.5 审计日志下游 Sink

AdGuard Home 没有独立的审计日志系统，所有鉴权相关日志**直接通过主日志管道输出**。以下是完整的日志写入链路。

#### 10.5.1 日志初始化入口

**位置**：[internal/next/cmd/log.go:13-39](internal/next/cmd/log.go#L13-L39)

```go
func newBaseLogger(opts *options) (baseLogger *slog.Logger) {
    var output io.Writer
    switch opts.confFile {
    case "stdout":
        output = os.Stdout
    case "stderr":
        output = os.Stderr
    case "syslog":
        // TODO(a.garipov):  Add a syslog handler to golibs.
    default:
        // TODO(a.garipov):  Use the path.
    }

    return slogutil.New(&slogutil.Config{
        Output: output,           // 输出 sink
        Format: slogutil.FormatText,  // 格式：文本
        Level:  lvl,              // 级别：Info / Debug
        AddTimestamp: true,
    })
}
```

#### 10.5.2 完整的日志 Sink 链路

```
slog.Logger.ErrorContext() / InfoContext() / DebugContext()
    ↓
golibs/logutil/slogutil  (标准库 slog 的包装层)
    ↓
slog.TextHandler (标准库)
    ↓
io.Writer (os.Stdout / os.Stderr)
    ↓
进程标准输出 / 标准错误
    ↓
由 systemd / docker / 终端 等外部环境收集
```

**关键说明**：

| 项目 | 值 | 说明 |
|------|---|------|
| 日志框架 | Go 标准库 `log/slog` | 结构化日志 |
| 格式 | `slogutil.FormatText` | 文本格式（非 JSON） |
| 默认输出 | `os.Stderr` | 标准错误输出 |
| 可选输出 | `os.Stdout` / syslog（TODO） | 通过命令行配置 |
| 文件输出 | **未实现** | `default:` 分支是 TODO |
| 时间戳 | 启用 | `AddTimestamp: true` |
| 日志级别 | Info（默认）/ Debug（verbose 模式） | |

#### 10.5.3 鉴权日志的 Sink 路径

**登录相关日志**：

```
handleLogin()
    ↓
web.logger.ErrorContext / InfoContext
    ↓  (logger 来自 web.auth.logger, 继承自 baseLogger)
baseLogger (slog.Logger 实例)
    ↓
slog.TextHandler
    ↓
os.Stderr
```

**Session 存储日志**：

[internal/aghuser/sessionstorage.go:136-137](internal/aghuser/sessionstorage.go#L136-L137)

```go
bl = &bbolt.DefaultLogger{
    Writer: slog.NewLogLogger(l.Handler(), slog.LevelDebug),
}
```

bbolt 数据库的内部日志通过 `slog.NewLogLogger` 桥接到 `log.Logger` 接口，再转发回 slog handler。

#### 10.5.4 审计能力评估

| 审计需求 | 是否满足 | 说明 |
|---------|---------|------|
| 登录成功记录 | ✅ | `"successful login"` 含用户名和 IP |
| 登录失败记录 | ✅ | `"invalid username or password"` 含 IP |
| 限流封禁记录 | ✅ | `"auth: blocked for X"` 含 IP |
| 未授权 API 访问 | ❌ | 仅 Debug 级别 `"no user found in request"`，不含 IP |
| 登出记录 | ❌ | 未找到显式登出审计日志 |
| 持久化审计文件 | ❌ | 仅输出到 stdout/stderr，无文件 sink |
| 结构化审计字段 | ❌ | 日志非 JSON 格式，解析成本高 |
| 独立审计通道 | ❌ | 鉴权日志与其他日志混在一起 |

### 10.6 通用 API 错误审计

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

### 11.5 关于 "自动刷新" 注释的澄清

配置注释中写道：

[internal/home/config.go:195](internal/home/config.go#L195)

```go
// An active session is automatically refreshed once a day.
```

**但实际代码中并没有实现 session 自动刷新逻辑**。这是一个**文档与代码不一致**的问题：

- 注释声称 "活跃会话每天自动刷新一次"
- 但 `FindByToken` 方法仅检查过期，不更新 `Expire` 时间
- 没有找到任何后台 goroutine 或定时刷新机制
- `SessionStorage` 接口也没有 `Refresh` / `Extend` 方法

> **结论**：该注释是历史遗留或计划中的功能描述，**当前版本（代码库现状）并未实现 session 自动刷新**。

### 11.6 多 Tab 并发刷新的竞争路径分析

由于 Session 没有续期机制，"多 Tab 同时刷新" 的并发竞争主要体现在**读取层面**。以下是并发安全设计的详细分析。

#### 11.6.1 Session 存储的并发锁（单点锁）

**锁定义**：[internal/aghuser/sessionstorage.go:74-75](internal/aghuser/sessionstorage.go#L74-L75)

```go
// mu protects sessions.
mu *sync.Mutex
```

**锁粒度**：**全局单锁**（整个 storage 一个 Mutex）

这就是所谓的"单点锁" —— 所有 session 操作共享同一个互斥锁。

#### 11.6.2 各方法的锁持有范围

| 方法 | 锁类型 | 锁内操作 | 锁外操作 | 代码位置 |
|------|-------|---------|---------|---------|
| `New` | 写锁（互斥） | 内存 map 写入 | bbolt 写入（store） | sessionstorage.go:338-343 |
| `FindByToken` | 读锁（互斥） | 内存 map 查找 + 过期检查 + 删除 | 无 | sessionstorage.go:381-399 |
| `DeleteByToken` | 写锁（互斥） | 内存 map 删除 + bbolt 删除 | 无 | sessionstorage.go:405-409 |

**注意**：`New` 方法中，bbolt 数据库写入（`ds.store(s)`）是在锁外执行的，只有最后写入内存 map 时才加锁。这降低了锁的持有时间，但也意味着：

1. bbolt 写入成功但加锁前如果有并发同 token 的删除，可能有不一致（但 token 是随机的，概率极低）
2. 锁的粒度是"整个 sessions map"，而不是 per-session

#### 11.6.3 多 Tab 并发刷新的实际执行流

当用户打开多个 Tab 同时刷新页面时，每个 Tab 都会触发一次认证中间件：

```
Tab 1: GET /                    Tab 2: GET /
    │                               │
    ▼                               ▼
authMiddlewareDefault.Wrap      authMiddlewareDefault.Wrap
    │                               │
    ▼                               ▼
userFromCookie()                 userFromCookie()
    │                               │
    ▼                               ▼
sessions.FindByToken(token)    sessions.FindByToken(token)
    │                               │
    └───────────┬───────────────────┘
                │
                ▼
        ds.mu.Lock()  ← 串行化，只有一个能进入
                │
                ▼
        内存 map 查找
        过期检查（都不会过期，因为 TTL 30 天）
        返回 session 指针
                │
                ▼
        ds.mu.Unlock()
                │
    ┌───────────┴───────────────────┐
    ▼                               ▼
users.ByLogin(login)             users.ByLogin(login)
    │                               │
    ▼                               ▼
db.mu.Lock()  ← 用户 DB 也是单点锁
    │
    ▼
loginToUserID 映射查找
返回 user 指针
    │
    ▼
db.mu.Unlock()
    │
    ▼
注入上下文 → 业务 Handler
```

**并发特征**：

1. **读操作串行化**：所有 `FindByToken` 调用被 `ds.mu` 强制串行，N 个并发请求会排队
2. **无 singleflight 合并**：N 个相同 token 的并发请求会执行 N 次相同的查找
3. **锁持有时间很短**：仅内存 map 查找，无 IO，通常微秒级
4. **对性能影响小**：因为锁内操作极快，即使并发很高也不会成为瓶颈

#### 11.6.4 两层单点锁的嵌套关系

认证中间件的完整调用路径中，存在**两层嵌套的单点锁**：

```
authMiddlewareDefault.handleAuthenticatedUser
    ↓
userFromCookie
    ↓
sessions.FindByToken  →  ds.mu.Lock()  [外层锁：session storage]
    ├─ sessions map 查找
    └─ ds.mu.Unlock()
    ↓
users.ByLogin  →  db.mu.Lock()  [内层锁：user DB]
    ├─ loginToUserID 查找
    └─ db.mu.Unlock()
```

两层都是**全局单锁**设计：
- `ds.mu`：保护 session 内存 map
- `db.mu`：保护用户数据的两个 map（`loginToUserID` 和 `userIDToUser`）

#### 11.6.5 并发安全保证

SessionStorage 接口明确要求所有方法必须并发安全：

[internal/aghuser/sessionstorage.go:20](internal/aghuser/sessionstorage.go#L20)

```go
// All methods must be safe for concurrent use.
```

**安全保证方式**：
- 读操作：`ds.mu.Lock()` → 内存查找 → `ds.mu.Unlock()`
- 写操作：先写 bbolt（事务内）→ 再加锁写内存 map
- 删除操作：加锁 → 删 bbolt → 删内存 → 解锁

> **注意**：`New` 方法的 bbolt 写入在锁外执行，存在理论上的 TOCTOU 风险。但由于 session token 是 16 字节加密随机数，冲突概率可忽略不计，这是一个可接受的权衡。

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

### 13.3 全局控制锁（controlLock）

在路由级中间件的 `ensure` 方法中，所有数据修改操作（POST/PUT/DELETE）都会被**全局控制锁**串行化。

**锁定义**：[internal/home/home.go:73](internal/home/home.go#L73)

```go
controlLock sync.Mutex
```

**锁的作用域**：全局单实例，保护所有 `control/*` 修改类 API 的并发执行。

**挂载位置**：[internal/home/control.go:275-277](internal/home/control.go#L275-L277)

```go
if modifiesData(m) {
    if !web.ensureContentType(w, r) {
        return
    }
    globalContext.controlLock.Lock()
    defer globalContext.controlLock.Unlock()
}
```

**并发影响**：

| 影响 | 说明 |
|------|------|
| 所有写操作串行 | POST/PUT/DELETE 请求会排队，同一时间只有一个能执行 |
| 读操作不受影响 | GET 请求不持有该锁，可并发执行 |
| 锁粒度粗 | 所有修改类 API 共享一把锁，而非 per-resource |
| 锁持有时间长 | 整个业务 handler 执行期间都持有锁 |

**典型场景**：多 Tab 同时提交配置修改时，请求会被强制串行，避免并发写入导致的配置不一致。

#### 13.3.1 "多 Tab 刷新 token 触发 controlLock" 的澄清

首先需要澄清：**AdGuard Home 没有 "刷新 token" 这个 API 操作**。

`config.go:195` 的注释 "An active session is automatically refreshed once a day" 是**文档与代码不一致**，实际代码中不存在 session 自动刷新或 token 刷新逻辑。

但如果将"刷新 token"广义理解为以下场景，controlLock 的性能影响如下：

| 场景 | HTTP 方法 | 是否触发 controlLock | 性能影响 |
|------|----------|---------------------|---------|
| 多 Tab 刷新页面（GET /） | GET | ❌ 否 | 无影响，完全并发 |
| 多 Tab 获取 profile（GET /control/profile） | GET | ❌ 否 | 无影响，完全并发 |
| 多 Tab 同时登录（POST /control/login） | POST | ❌ 否 | 无影响（直接用 mux.Handle 注册，不走 httpReg） |
| 多 Tab 同时登出（GET /control/logout） | GET | ❌ 否 | 无影响 |
| 多 Tab 同时更新 profile（PUT /control/profile/update） | PUT | ✅ 是 | 串行执行 |
| 多 Tab 同时修改 DNS 配置（POST /control/dns_config） | POST | ✅ 是 | 串行执行 |

**关键路径对比**：

```
登录接口 (POST /control/login):
  auth middleware → mux.Handle → handleLogin
  (不经过 httpReg → ensure → controlLock)

其他写接口 (POST /control/*):
  auth middleware → mux → httpReg → ensureMw → ensure → controlLock.Lock → handler
```

登录接口特殊之处在于它是通过 `mux.Handle("POST /control/login", ...)` 直接注册的，**不经过** `httpReg.Register`，因此也**不会**被 `ensure` 中间件的 `controlLock` 保护。

#### 13.3.2 controlLock 串行的性能影响分析

**写操作延迟 = 排队时间 + 执行时间**

假设 N 个 Tab 同时发起写请求：

```
Tab 1:  ████████ (执行 100ms)
Tab 2:    ████████ (等待 0ms + 执行 100ms)
Tab 3:      ████████ (等待 100ms + 执行 100ms)
Tab N:        ...
```

**性能影响因素**：

| 因素 | 影响程度 | 说明 |
|------|---------|------|
| 写操作耗时 | 🔴 高 | 写操作越慢，排队等待越长 |
| 并发写数量 | 🟡 中 | N 个并发的总耗时约为 N × 单次耗时 |
| 读写比例 | 🟢 低 | AGH 绝大多数是读操作，写操作很少 |
| 用户数 | 🟢 低 | 通常只有 1-2 个管理员用户 |

**实际影响评估**：

对于 AdGuard Home 的典型使用场景（家庭/小型网络，1-2 个管理员），`controlLock` 串行化的性能影响**可以忽略不计**：
- 管理员操作频率低，很少出现并发写
- 大部分写操作（如修改配置）耗时在几十毫秒级别
- GET 请求（页面刷新、状态查询）不受影响

但如果有多个 Tab 同时自动刷新某个写操作 API（理论场景），则会出现明显的排队延迟。

### 13.4 用户上下文传递

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

### 13.5 三种 Server 的中间件一致性

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
| 日志基础设置 | [internal/next/cmd/log.go](internal/next/cmd/log.go) |
| 日志工具常量 | [internal/aghslog/aghslog.go](internal/aghslog/aghslog.go) |
| 全局控制锁 | [internal/home/home.go](internal/home/home.go) |
| Profile 鉴权消费示例 | [internal/home/profilehttp.go](internal/home/profilehttp.go) |

# AdGuard Home 配置初始化、迁移与热加载代码分析

本文从代码实现角度梳理 AdGuard Home 的三大配置流程：初始化向导（Setup Wizard）、版本迁移（Config Migration）和运行时配置热加载（Hot Reload）。

---

## 一、初始化向导（Setup Wizard）

### 1.1 首次运行检测

程序入口 `main.go` → `home.Main()` → `run()`。

首次运行的判断逻辑位于 `internal/home/home.go:1345` 的 `detectFirstRun()` 函数：

```go
func detectFirstRun(ctx context.Context, l *slog.Logger, workDir, confPath string) (ok bool) {
    if !filepath.IsAbs(confPath) {
        confPath = filepath.Join(workDir, confPath)
    }
    _, err := os.Stat(confPath)
    if err == nil {
        return false          // 配置文件存在，非首次
    } else if errors.Is(err, os.ErrNotExist) {
        return true           // 配置文件不存在，首次运行
    }
    // 其他错误也视为首次运行
    return true
}
```

**首次运行与非首次运行的关键差异：**

| 阶段 | 首次运行 | 非首次运行 |
|---|---|---|
| `setupContext()` (home.go:182) | 检查网络权限、端口绑定能力 | 读取并解析配置文件 `parseConfig()` |
| `run()` (home.go:753) | 不启动 DNS 服务器 | 立即启动 DNS 服务器 `runDNSServer()` |
| Web 路由 (web.go:192) | 注册 install handlers，所有请求重定向到 `/install.html` | 注册 control handlers |

### 1.2 Setup Wizard 前端流程

前端入口：`client/src/install/index.tsx` → `Setup` 组件 (`client/src/install/Setup/index.tsx`)。

向导共 **5 个步骤**：

| 步骤 | 组件 | 内容 |
|---|---|---|
| 1 | `Greeting` | 欢迎页面 |
| 2 | `Settings` | Web 端口、DNS 端口、绑定 IP 配置 |
| 3 | `Auth` | 设置管理员用户名和密码 |
| 4 | `Devices` | 设备配置说明页 |
| 5 | `Submit` | 完成页，跳转 Dashboard |

前端 Redux Actions 位于 `client/src/actions/install.ts`，主要 API 调用：

- `getDefaultAddresses()` → `GET /control/install/get_addresses`
- `checkConfig()` → `POST /control/install/check_config`
- `setAllSettings()` → `POST /control/install/configure`

### 1.3 后端 Install API

所有 install handler 位于 `internal/home/controlinstall.go`，通过 `registerInstallHandlers()` 注册。

#### ① 获取地址信息 (`handleInstallGetAddresses`)

`controlinstall.go:46` - 返回网络接口列表、版本号、建议 Web 端口、默认 DNS 端口。

```go
func (web *webAPI) handleInstallGetAddresses(w http.ResponseWriter, r *http.Request) {
    data := getAddrsResponse{
        Version:  version.Version(),
        WebPort:  int(web.conf.defaultWebPort),  // 默认 3000，可通过 ADGUARD_HOME_DEFAULT_WEB_PORT 环境变量覆盖
        DNSPort:  int(defaultPortDNS),           // 53
        Interfaces: ...,                         // 通过 aghnet.GetValidNetInterfacesForWeb() 获取
    }
    aghhttp.WriteJSONResponseOK(ctx, l, w, r, data)
}
```

#### ② 配置预检 (`handleInstallCheckConfig`)

`controlinstall.go:189` - 检查 Web/DNS 端口占用、静态 IP 检测、Linux 下 systemd-resolved DNSStubListener 检测。

关键流程：
- `validateWeb()`：校验 TCP 端口唯一性 + 端口可绑定性
- `validateDNS()`：校验 TCP/UDP 端口 + 检测 DNSStubListener 占用 53 端口（可 autofix）
- `handleStaticIP()`：检查指定 IP 所在网卡是否已配置静态 IP

#### ③ 配置提交 (`handleInstallConfigure` → `finalizeInstall`)

`controlinstall.go:431` - 这是核心函数，完整流程如下：

```
1. decodeApplyConfigReq() 解码请求，判断是否需要重启 HTTP 服务（端口/IP 变更时）
2. 校验密码长度 (≥8 runes)
3. 校验 DNS TCP/UDP 端口可用性
4. finalizeInstall():
   ├─ 备份当前 config (失败时回滚 copyInstallSettings)
   ├─ 设置 DNS.BindHosts / DNS.Port / HTTPConfig.Address
   ├─ web.auth.addUser() 创建管理员用户
   ├─ startMods() 初始化并启动 DNS 服务器
   │   ├─ initDNS() 初始化 stats / querylog / filtering / dnsServer
   │   ├─ tlsMgr.start() 启动 TLS
   │   └─ startDNSServer() 启动 DNS 监听
   ├─ config.write() 写入 AdGuardHome.yaml
   ├─ web.conf.firstRun = false  (标记首次运行结束)
   ├─ web.registerControlHandlers() 替换为正式 API 路由
   └─ 如端口/IP 变更：在独立 goroutine 中 Shutdown 当前 HTTP Server
      (web.start() 的外层 for 循环会创建新的 HTTP Server 监听新地址)
```

### 1.4 HTTP Server 的地址切换机制

`internal/home/web.go:253` 的 `web.start()` 采用 **无限 for 循环** 模式，支持运行时切换监听地址：

```go
func (web *webAPI) start(ctx context.Context) {
    go web.tlsServerLoop(ctx)
    for !web.httpsServer.inShutdown {
        printHTTPAddresses(...)
        errs := make(chan error, 2)
        hdlr := withMiddlewares(web.conf.mux, limitRequestBody)
        // 每次循环都创建新的 http.Server 实例
        web.httpServer = &http.Server{
            Addr:    web.conf.BindAddr.String(),
            Handler: hdlr,
            ...
        }
        go func() {
            errs <- web.httpServer.ListenAndServe()
        }()
        // 阻塞直到 Server 被 Shutdown
        err := <-errs
        if !errors.Is(err, http.ErrServerClosed) {
            panic(err)
        }
    }
}
```

当 `handleInstallConfigure` 检测到 Web 端口/IP 变更时，会调用 `web.httpServer.Shutdown()`，`ListenAndServe()` 返回 `http.ErrServerClosed`，外层 for 循环重新以新的 `BindAddr` 创建 Server。

### 1.5 Setup 失败回滚机制

`finalizeInstall()` 是整个 Setup 流程中最核心、最容易失败的环节。其回滚机制是**分层、局部**的，并非事务级全量回滚。

#### 回滚层级一：配置值回滚（最外层）

`controlinstall.go:484-492` - 仅回滚 DNS/Web 地址和端口：

```go
curConfig := &configuration{}
copyInstallSettings(curConfig, config)   // 先备份当前配置

defer func() {
    if err != nil {
        copyInstallSettings(config, curConfig)  // 失败时回滚
    }
}()

// 之后才修改这些值
config.DNS.BindHosts = []netip.Addr{req.DNS.IP}
config.DNS.Port = req.DNS.Port
config.HTTPConfig.Address = netip.AddrPortFrom(req.Web.IP, req.Web.Port)
```

`copyInstallSettings()` (`controlinstall.go:374`) 只复制 3 个字段：

```go
func copyInstallSettings(dst, src *configuration) {
    dst.HTTPConfig = src.HTTPConfig
    dst.DNS.BindHosts = src.DNS.BindHosts
    dst.DNS.Port = src.DNS.Port
}
```

> **注意**：这层回滚只能恢复 config 对象上的 HTTP/DNS 地址字段，无法回滚已经启动的服务器、已经写入磁盘的文件、已经创建的用户。

#### 回滚层级二：DNS 服务器初始化失败

`dns.go:159-163` - `initDNSServer()` 内部失败时关闭 DNS 服务器：

```go
globalContext.dnsServer, err = dnsforward.NewServer(...)
defer func() {
    if err != nil {
        closeDNSServer(ctx)
    }
}()
```

`closeDNSServer()` 会清理 `globalContext.dnsServer`、`stats`、`queryLog`、`filters` 等模块。

#### 回滚层级三：配置文件写入失败

`config.write()` 自身使用 `renameio` 原子写入（先写临时文件，再 `rename`），所以写入过程中失败不会损坏已有配置文件。但是如果 **之前的步骤都成功了，只有最后写文件失败**，就会出现 **运行时状态已变更但磁盘未持久化** 的不一致状态 —— 进程重启后配置会丢失。

#### 不回滚的操作

| 操作 | 失败是否回滚 | 原因 |
|---|---|---|
| `web.auth.addUser()` 创建用户 | ❌ 不回滚 | 用户信息仅存在内存，`copyInstallSettings` 不包含用户 |
| `startMods()` 启动 DNS/TLS 等模块 | ⚠️ 部分回滚 | 子模块有各自的 defer 清理，但整体无 SAGA 编排 |
| `web.registerControlHandlers()` 切换路由 | ❌ 不回滚 | 在 `config.write()` 成功之后才执行，若 write 失败则不会走到这步 |
| HTTP Server Shutdown（端口变更时） | ❌ 不回滚 | 在返回响应后异步执行，无法回滚 |

### 1.6 Setup Wizard 中途中断后的恢复路径

Setup Wizard 的中断场景可以分为 **进程内中断**（请求失败、panic 等）和 **进程级中断**（进程崩溃、机器断电、用户 Ctrl+C）两类，恢复机制完全不同。

#### 场景一：请求处理过程中失败（进程仍在）

触发点：`handleInstallConfigure` / `finalizeInstall` 内部某个步骤报错返回。

**恢复路径**：

```
前端收到 4xx/5xx 错误响应
    ↓
停留在 Setup Wizard 页面（未跳转）
    ↓
用户修改参数后重试 POST /control/install/configure
    ↓
重复执行 finalizeInstall() 全部步骤
    ↓
最终成功 → web.conf.firstRun = false → 切换路由
```

关键点：
- **幂等性**：虽然步骤不是严格幂等的，但重复执行是安全的
  - `auth.addUser()`：如果用户已存在会返回错误，但由于 Setup 只有一个用户，失败只会在第一次成功之后才发生（概率极低）
  - `startMods()`：内部 `initDNSServer` 会先检查并清理旧实例再创建新的
  - `config.write()`：总是用当前内存状态全量覆盖写入
  - `registerControlHandlers()`：被 `webRegistered` 等标志位保护，不会重复注册
- **回滚仅恢复内存中的 config 字段**（见 1.5 节），不会回滚磁盘文件

#### 场景二：finalizeInstall 成功但 HTTP Shutdown 异步 goroutine 中崩溃

触发点：`config.write()`、`registerControlHandlers()` 已执行成功，但后续 `shutdownSrv()` 所在 goroutine panic。

**恢复路径**：

```
finalizeInstall() 返回 200 OK
    ↓
前端跳转 Dashboard
    ↓
后台 goroutine 执行 shutdownSrv() 时 panic
    ↓
slogutil.RecoverAndLog 捕获 panic 并记录日志（不崩溃进程）
    ↓
HTTP Server 因 ListenAndServe 返回 ErrServerClosed 而重启 for 循环
    ↓
使用新 BindAddr 创建新 Server（正常恢复）
```

这个场景的保障来自 `web.start()` 的无限 for 循环（`web.go:262`）—— 只要进程不崩溃，HTTP Server 总会自动恢复。

#### 场景三：进程级中断（崩溃/断电/信号）

触发点：在 `config.write()` 之前或之后进程终止。

**关键分界点**：`controlinstall.go:552` 的 `web.conf.firstRun = false` 以及之前的 `config.write()` 调用。

| 中断时机 | 磁盘状态 | 下次启动行为 |
|---|---|---|
| `config.write()` 之前 | 没有 `AdGuardHome.yaml` | `detectFirstRun()` → true，重新进入 Setup Wizard |
| `config.write()` 成功之后 | 已有 `AdGuardHome.yaml` | `detectFirstRun()` → false，正常加载配置启动 |
| `config.write()` 写入过程中 | renameio 原子写入保证要么旧文件要么新文件，不会有中间态 | 等同于上两种之一 |

#### 场景四：config.write() 成功但 firstRun=false 未持久化

这是一个**潜在的不一致窗口**：

```
config.write() 成功（磁盘已有 YAML）
    ↓ （尚未执行 web.conf.firstRun = false）
进程崩溃
    ↓
下次启动：detectFirstRun() 发现 YAML 存在 → 返回 false
    ↓
正常启动，跳过 Setup Wizard ✅
```

结论：只要 `config.write()` 成功了，即使后续步骤中断，下次启动也会走正常加载路径。**真正不安全的只有 `config.write()` 之前的中断**——此时磁盘上没有 YAML，只能重来。

### 1.7 多 Client 并发调 Setup API 的资源竞争路径

Setup 阶段有 3 个 API 端点，它们的中介件保护和竞争风险各不相同：

```
GET  /control/install/get_addresses  → preInstallHandler（无锁）
POST /control/install/check_config   → preInstallHandler + ensure（controlLock）
POST /control/install/configure      → preInstallHandler + ensure（controlLock）
```

#### 竞争路径一：GET get_addresses 与 POST configure 的读写竞争

`get_addresses` 是 GET 请求，**不经过 `ensure()` 中间件**，因此不持有 `controlLock`。

```
Client A: GET /install/get_addresses            （无锁，并发执行）
Client B: POST /install/configure               （持 controlLock）
  ├─ config.DNS.BindHosts = [req.DNS.IP]        （写全局变量）
  ├─ config.DNS.Port = req.DNS.Port             （写全局变量）
  ├─ config.HTTPConfig.Address = ...            （写全局变量）
  └─ web.conf.firstRun = false
```

如果 Client A 的 `handleInstallGetAddresses` 正在读取 `web.conf.defaultWebPort`，而 Client B 的 `finalizeInstall` 正在修改 `config.DNS.Port`，理论上存在 data race。

**实际风险**：极低。因为：
1. `get_addresses` 只读 `web.conf.defaultWebPort` 和 `defaultPortDNS`，这两个值在 Setup 期间不会被 `configure` 修改
2. Go 的 `net/http` 默认为每个请求创建独立 goroutine，但 `handleInstallGetAddresses` 中没有读共享可变状态

#### 竞争路径二：两个 POST configure 的双写竞争

两个浏览器标签页同时提交 Setup：

```
Client A: POST /install/configure  ──┐
                                      ├─ controlLock 互斥，串行执行
Client B: POST /install/configure  ──┘
```

`controlLock` 保证了串行，但问题在于 **第一个请求完成后 `firstRun` 被设为 false**，第二个请求会被 `preInstallHandler` 拦截：

```go
// control.go:340-352
func (web *webAPI) preInstallHandler(handler http.Handler) (wrapped http.Handler) {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !web.conf.firstRun {
            http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
            return
        }
        handler.ServeHTTP(w, r)
    })
}
```

**竞争时序分析**：

| 时刻 | Client A | Client B | firstRun |
|---|---|---|---|
| T1 | 获取 controlLock | 等待 | true |
| T2 | addUser(), startMods(), config.write() | 等待 | true |
| T3 | web.conf.firstRun = false | 等待 | **false** |
| T4 | registerControlHandlers(), 返回 200 | 获取 controlLock | false |
| T5 | — | 进入 preInstallHandler | false |
| T6 | — | **返回 403 Forbidden** | false |

Client B 会被 **403 拒绝**，因为 `firstRun` 已经被 Client A 设为 false。

**但是**：`firstRun` 的读写**没有原子操作保护**。`preInstallHandler` 在 `ensure()` 中间件 **之前** 执行，所以 Client B 在 T4 获取 `controlLock` 之前，就已经检查了 `firstRun`。极端情况下：

```
Client B: preInstallHandler 检查 firstRun == true（通过！）
Client A: 同时执行 finalizeInstall，设置 firstRun = false
Client B: 获取 controlLock，执行 handleInstallConfigure
Client B: addUser() → panic!（用户已存在）
```

这是 `web.conf.firstRun` 字段 **缺少原子/锁保护** 导致的潜在 data race。实际触发概率极低（需要两个请求在微秒级窗口内交叉），但 `go race detector` 可以检测到。

#### 竞争路径三：POST configure 与 GET 普通页面的路由竞争

`finalizeInstall` 在 `config.write()` 成功后执行 `registerControlHandlers()`，这会向 `mux` 注册新的路由。同时 HTTP Server 还在处理其他请求。

```
Client A: POST /install/configure
  └─ registerControlHandlers()  // 向 mux 注册 /control/status 等路由

Client C: GET /control/status    // 尝试访问刚注册的路由
```

Go 的 `http.ServeMux` 不是并发安全的写入对象，但 `registerControlHandlers` 在 `controlLock` 保护下执行，而 `mux.Handle` 只在启动时和 Setup 完成时调用（各一次），所以实际不会出现并发写入 `mux` 的情况。

#### 竞争路径四：addUser 的重复创建

`auth.addUser()` 内部调用 `aghuser.DefaultDB.Create()`，后者用 `sync.Mutex` 保护且检查重复：

```go
// aghuser/db.go:127-148
func (db *DefaultDB) Create(ctx context.Context, u *User) (err error) {
    db.mu.Lock()
    defer db.mu.Unlock()
    // 检查 UserID 重复
    _, ok := db.userIDToUser[u.ID]
    if ok { return fmt.Errorf("userid: %w", errors.ErrDuplicated) }
    // 检查 Login 重复
    _, ok = db.loginToUserID[u.Login]
    if ok { return fmt.Errorf("login: %w", errors.ErrDuplicated) }
    // 插入
    db.userIDToUser[u.ID] = u
    db.loginToUserID[u.Login] = u.ID
}
```

如果竞争路径二中的极端情况发生（两个 configure 同时进入 `addUser`），第二个会因 `ErrDuplicated` 而 panic（`auth.go:218` 的 `panic(err)`），导致请求 500 但不会破坏数据。

### 1.8 Setup 完成后客户端跳转回首页的状态同步路径

Setup Wizard 的最后一步（Step 5）是用户点击 "Open Dashboard" 按钮，触发全页面跳转。这个过程中涉及多个状态同步环节。

#### 前端跳转链路

```
用户点击 "Open Dashboard"
  │
  ▼
Controls.tsx:88  onClick={() => this.props.openDashboard(ip, port)}
  │
  ▼
Setup/index.tsx:63  openDashboard(ip, port)
  │  ┌──────────────────────────────────────────────────┐
  │  │ const openDashboard = (ip, port) => {            │
  │  │   let address = getWebAddress(ip, port);         │
  │  │   if (ip === '0.0.0.0') {                       │
  │  │     address = getWebAddress(                     │
  │  │       window.location.hostname, port);           │
  │  │   }                                             │
  │  │   window.location.replace(address);              │
  │  │ };                                              │
  │  └──────────────────────────────────────────────────┘
  │
  ▼
helpers.tsx:249  getWebAddress(ip, port)
  │  生成 URL: http://ip:port 或 http://ip（端口 80 时省略）
  │  IPv6 地址处理: http://[::1]:port
  │
  ▼
window.location.replace(address)  ← 全页面替换跳转
```

**关键点**：`window.location.replace()` 不是 `window.location.href = ...`，它**替换**浏览器历史记录中当前条目，用户不能按"后退"回到安装向导。

#### 后端状态切换与客户端请求的竞态

跳转后客户端请求新 URL 时，后端可能处于以下三种状态之一：

| 后端状态 | 触发条件 | 客户端看到的结果 |
|---|---|---|
| HTTP Server 仍在旧端口/IP 上运行 | Web 端口未变（`restartHTTP == false`） | 立即加载 Dashboard，走 `registerControlHandlers` 注册的新路由 |
| HTTP Server 正在 Shutdown 过渡期 | Web 端口/IP 变更，Shutdown goroutine 正在执行 | 请求超时或连接拒绝（短暂窗口，< 1s） |
| HTTP Server 已在新端口/IP 上重启 | Web 端口/IP 变更，新 Server 已在 for 循环中创建 | 正常加载 Dashboard |

**端口变更时的关键时序**：

```
finalizeInstall():
  1. aghhttp.OK(ctx, l, w)              ← 返回 200 给前端
  2. rc.Flush()                          ← 立即刷新响应（不等 goroutine）
  3. go shutdownSrv(web.httpServer)      ← 异步 Shutdown 旧 Server

前端收到 200:
  → Redux dispatch(setAllSettingsSuccess)
  → dispatch(nextStep())                 ← Step 5
  → 用户看到 "Open Dashboard" 按钮

用户点击 "Open Dashboard":
  → window.location.replace(newUrl)
  → 浏览器发起 GET / 请求到新地址

此时后端:
  web.start() 的 for 循环检测到 ErrServerClosed
  → 创建新 http.Server{Addr: newAddr}
  → ListenAndServe(newAddr)
  → 新请求到达 → Dashboard 加载
```

`rc.Flush()` (`controlinstall.go:559`) 是关键优化——它确保 200 响应立即写回客户端，不会等到 `defer` 或 goroutine 执行完毕。

#### 认证状态同步

Setup 阶段的 API 是**免认证**的（`isPublicResource` 列表包含所有 `/control/install/*` 路径，见 `authhttp.go:313-321`）。跳转到 Dashboard 后，前端需要重新建立认证会话：

```
浏览器跳转到 http://newIp:newPort/
  │
  ▼
App.tsx useEffect → dispatch(getDnsStatus())
  │
  ▼
GET /control/status  ← 需要认证
  │
  ├─ 无 Cookie → 403 Forbidden
  │     │
  │     ▼
  │     Api.ts:26  makeRequest() 检测 403:
  │       if (error.response.status === 403 && shouldRedirect) {
  │         window.location.replace(loginPageUrl)  ← 重定向到 /login.html
  │       }
  │
  └─ 有 Cookie（Setup 期间未设 Cookie，所以总是走 403 分支）
```

**Setup 不设 Cookie**：`handleInstallConfigure` 返回的只是 `aghhttp.OK()`，不像 `handleLogin` 那样调用 `http.SetCookie(w, cookie)`。因此跳转到 Dashboard 后，用户**必须重新登录**。

完整登录流程 (`actions/login.ts:11-22`)：

```
用户在 /login.html 输入用户名密码
  → apiClient.login(values)  → POST /control/login
  → handleLogin() 返回 Set-Cookie: agh_session=xxx
  → window.location.replace(dashboardUrl)  ← 再次全页面跳转到 /
  → App.tsx 加载 → dispatch(getDnsStatus()) → GET /control/status（带 Cookie）
  → 200 OK → Dashboard 渲染
```

#### 前端全局状态初始化

Dashboard 加载时 `App.tsx:120-134` 触发初始数据拉取：

```typescript
useEffect(() => {
    dispatch(getDnsStatus());          // GET /control/status → 填充 dashboard Redux state
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            dispatch(getTimerStatus());  // 页面可见时刷新保护计时器
        }
    });
}, []);
```

`getDnsStatus()` 返回的数据填充 `dashboard` Redux slice，包括：`protectionEnabled`、`dnsAddresses`、`dnsVersion`、`isCoreRunning` 等，这些是 Dashboard 页面渲染的基础数据。

---

## 二、版本迁移（Config Migration）

### 2.1 迁移机制总览

AdGuard Home 使用 **schema_version** 标记配置文件格式版本，当前最新版本为 **34**（`internal/configmigrate/configmigrate.go:5`）。

迁移入口位于 `internal/home/config.go:684` 的 `parseConfig()`：

```go
func parseConfig(ctx context.Context, l *slog.Logger, workDir, confPath string) (err error) {
    config.fileData, err = readConfigFile(ctx, l, workDir, confPath)
    // 创建迁移器
    migrator := configmigrate.New(&configmigrate.Config{
        Logger:     l.With(slogutil.KeyPrefix, "config_migrator"),
        WorkingDir: workDir,
        DataDir:    filepath.Join(workDir, dataDir),
    })
    // 执行迁移
    var upgraded bool
    config.fileData, upgraded, err = migrator.Migrate(
        ctx,
        config.fileData,
        configmigrate.LastSchemaVersion,  // 目标版本 = 34
    )
    if upgraded {
        // 迁移后立即写回文件（使用 renameio 原子写入）
        maybe.WriteFile(confPath, config.fileData, aghos.DefaultPermFile)
    }
    // 反序列化到全局 config 对象
    yaml.Unmarshal(config.fileData, &config)
    validateConfig(ctx, l, config.fileData)
    ...
}
```

### 2.2 Migrator 核心实现

`internal/configmigrate/migrator.go`

`Migrate()` 方法流程：

```
1. yaml.Unmarshal(body, &diskConf)  解析为通用 map[string]any (yobj)
2. 读取当前 schema_version (diskConf["schema_version"])
3. validateVersion() 校验：current ≤ target ≤ LastSchemaVersion
4. 若 current == target：直接返回原数据
5. 否则调用 upgradeConfigSchema() 执行升级
   └─ 按顺序从 current 到 target-1，逐个调用迁移函数
      upgrades[0] → migrateTo1
      upgrades[1] → migrateTo2
      ...
      upgrades[33] → migrateTo34
6. 重新序列化 YAML 并返回
```

**迁移函数表**（`migrator.go:113`）：

```go
upgrades := [LastSchemaVersion]migrateFunc{
    0:  m.migrateTo1,
    1:  m.migrateTo2,
    ...
    33: m.migrateTo34,
}
```

每个版本迁移函数都在独立文件中实现（`v1.go` ~ `v34.go`），函数签名统一为：

```go
func (m Migrator) migrateToN(ctx context.Context, diskConf yobj) (err error)
```

### 2.3 YAML 操作工具

`internal/configmigrate/yaml.go` 提供了三个核心工具函数：

| 函数 | 作用 |
|---|---|
| `fieldVal[T](obj, key)` | 类型安全地读取 map 中的字段值 |
| `moveVal[T](src, dst, srcKey, dstKey)` | 将字段从 src 移动到 dst（支持改名） |
| `moveSameVal[T](src, dst, key)` | 将字段从 src 移动到 dst（同名） |

### 2.4 迁移实例：v33 → v34

`internal/configmigrate/v34.go` - 将 `tls.allow_unencrypted_doh` 移动到 `http.doh.insecure_enabled`，同时新增默认 DoH 路由：

```go
func (m Migrator) migrateTo34(_ context.Context, diskConf yobj) (err error) {
    diskConf["schema_version"] = 34
    httpConf, _, _ := fieldVal[yobj](diskConf, "http")
    tlsConf, _, _ := fieldVal[yobj](diskConf, "tls")
    // 新增 http.doh 节点，包含默认路由
    dohConf := yobj{
        "routes": yarr{
            "GET /dns-query", "POST /dns-query",
            "GET /dns-query/{ClientID}", "POST /dns-query/{ClientID}",
        },
    }
    httpConf["doh"] = dohConf
    // 从 tls.allow_unencrypted_doh 移动到 http.doh.insecure_enabled
    return moveVal[bool](tlsConf, dohConf, "allow_unencrypted_doh", "insecure_enabled")
}
```

### 2.5 迁移失败回滚机制

迁移过程中如果某一步失败，整个迁移流程会**立即中止并返回错误**，但**不会回滚到之前的 schema_version**。这是一个值得注意的设计决策。

#### 迁移执行路径

`migrator.go:108` 的 `upgradeConfigSchema()` 按顺序逐个调用迁移函数：

```go
func upgradeConfigSchema(diskConf yobj, upgrades ...migrateFunc) (err error) {
    for i, migrate := range upgrades {
        err = migrate(diskConf)
        if err != nil {
            // 失败时直接返回错误，不回滚已完成的迁移
            return fmt.Errorf("version %d: %w", i+1, err)
        }
    }
    return nil
}
```

#### 两层安全保障

虽然没有显式的回滚逻辑，但有两层安全机制防止损坏数据：

| 层级 | 机制 | 位置 | 作用 |
|---|---|---|---|
| 第一层 | **内存中操作** | `migrator.go:45` `Migrate()` | 整个迁移在 `yobj`（`map[string]any`）内存对象上进行，不修改原始 YAML 字节 |
| 第二层 | **原子写回** | `config.go:684` `parseConfig()` | 迁移成功后才调用 `maybe.WriteFile()`（内部用 renameio），失败则不写 |

#### 迁移失败的影响

如果从 v10 迁到 v34 过程中 v25 的迁移函数报错：
1. **磁盘文件不变** —— 仍是 v10 格式（原子写入未触发）
2. **程序启动失败** —— `parseConfig()` 返回错误，程序无法继续运行
3. **无法降级重试** —— 迁移是单向的，且没有回滚函数，只能人工修复配置文件

> **设计权衡**：每个迁移函数本身是"幂等 + 小步"的，且配置文件是只读的（迁移过程中），所以即使中途失败，最坏情况是启动失败，不会破坏数据。

### 2.6 测试保障

`internal/configmigrate/testdata/TestMigrateConfig_Migrate/` 目录下每个版本都有 `input.yml` 和 `output.yml` 用例，通过 `configmigrate_test.go` 驱动迁移测试，确保每个版本迁移的输入输出严格符合预期。

---

## 三、敏感数据与配置加密存储

AdGuard Home 的 YAML 配置文件中存储了两类敏感数据：**用户密码** 和 **TLS 私钥**。它们采用了不同的保护策略。

### 3.1 用户密码：bcrypt 单向哈希

#### 写入挂载点

用户密码在两个入口被哈希后存储：

**入口一：Setup Wizard 创建管理员**

`auth.go:204-227` 的 `addUser()` 是 Setup 创建管理员用户时的调用点：

```go
func (a *auth) addUser(ctx context.Context, u *webUser, password string) (err error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return fmt.Errorf("generating hash: %w", err)
    }
    u.PasswordHash = string(hash)
    err = a.users.Create(ctx, u.toUser())  // 存入 DefaultDB（内存）
    // ...
}
```

`addUser()` 只修改内存中的 `aghuser.DefaultDB`，密码哈希的磁盘持久化由后续的 `config.write()` 完成（见 3.6 节 `configuration.write()` 中 `auth.usersList()` → `config.Users` → YAML 序列化）。

**入口二：配置迁移 v4 → v5（明文→哈希）**

`configmigrate/v5.go:24-48` 是历史遗留的明文密码迁移：

```go
func (m *Migrator) migrateTo5(_ context.Context, diskConf yobj) (err error) {
    // 从 auth_name + auth_pass 迁移到 users[].name + users[].password
    pass, ok, err := fieldVal[string](diskConf, "auth_pass")
    delete(diskConf, "auth_pass")
    hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
    user["password"] = string(hash)  // 哈希后写入 YAML
    diskConf["users"] = yarr{user}
}
```

v5 迁移是**唯一读取明文密码**的地方，之后的版本中密码在 YAML 里始终以 bcrypt 哈希存储。

#### 验证挂载点

`aghuser/aghuser.go:52-53` 的 `DefaultPassword.Authenticate()` 是登录验证的调用点：

```go
func (p *DefaultPassword) Authenticate(ctx context.Context, passwd string) (ok bool) {
    return bcrypt.CompareHashAndPassword([]byte(p.hash), []byte(passwd)) == nil
}
```

调用链：`handleLogin()` → `auth.middleware()` → `DefaultPassword.Authenticate()`

#### YAML 中的存储格式

```yaml
users:
- name: admin
  password: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

`password` 字段存储的是 bcrypt 哈希值（`$2a$` 前缀），明文密码永远不会写入 YAML。

### 3.2 TLS 私钥：明文存储 + 文件引用两种模式

`config.go:300-363` 的 `tlsConfigSettings` 定义了两对互斥字段：

```go
type tlsConfigSettings struct {
    // 模式一：内联存储（明文写入 YAML）
    CertificateChain string `yaml:"certificate_chain" json:"certificate_chain"`
    PrivateKey       string `yaml:"private_key"       json:"private_key"`

    // 模式二：文件路径引用（不写入 YAML）
    CertificatePath  string `yaml:"certificate_path"  json:"certificate_path"`
    PrivateKeyPath   string `yaml:"private_key_path"  json:"private_key_path"`

    // 运行时加载的二进制数据（yaml:"-" json:"-" 不序列化）
    CertificateChainData []byte `yaml:"-" json:"-"`
    PrivateKeyData       []byte `yaml:"-" json:"-"`
}
```

#### 模式一：内联存储

用户通过 API 提交证书/私钥内容（`certificate_chain` + `private_key`），数据直接以 PEM 格式明文写入 YAML：

```yaml
tls:
  certificate_chain: |
    -----BEGIN CERTIFICATE-----
    MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQEL...
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAQIBAQCN/Y6b...
    -----END PRIVATE KEY-----
```

**安全隐患**：私钥以明文形式存储在 YAML 文件中，任何有文件读权限的进程都能获取。

#### 模式二：文件路径引用

用户指定证书和私钥的文件路径，YAML 中只存储路径：

```yaml
tls:
  certificate_path: /path/to/cert.pem
  private_key_path: /path/to/key.pem
```

**加载挂载点**：`tls.go:361-375` 的 `loadCertificateChainData()` 和 `loadPrivateKeyData()`：

```go
func loadCertificateChainData(extTLSConf *tlsConfigSettings) (err error) {
    extTLSConf.CertificateChainData = []byte(extTLSConf.CertificateChain)
    if extTLSConf.CertificatePath != "" {
        if extTLSConf.CertificateChain != "" {
            return errors.Error("certificate data and file can't be set together")
        }
        extTLSConf.CertificateChainData, err = os.ReadFile(extTLSConf.CertificatePath)
    }
}
```

`CertificateChainData` 和 `PrivateKeyData` 标记为 `yaml:"-" json:"-"`，确保：
- 不会被写入 YAML 文件
- 不会被返回给前端 API（`json:"-"`）

运行时热加载也走这条路径：`handleCertFileChange()` → `reload()` → `loadTLSConfig()` → `loadCertificateChainData()`。

#### 模式互斥校验

`loadCertificateChainData()` (`tls.go:365`) 和 `loadPrivateKeyData()` 都校验：如果同时提供了内联数据和文件路径，直接报错。这保证了两种模式不会混淆。

### 3.3 Session 存储：bbolt 加密无关 + 内存索引

`aghuser/sessionstorage.go` 使用 bbolt（BoltDB）存储 session 数据：

```
sessions.db (bbolt)
  └─ bucket "sessions-2"
      ├─ token₁ → {userLogin, expire, userID}
      ├─ token₂ → {userLogin, expire, userID}
      └─ ...
```

- Session token 由 `crypto/rand` 生成（`session.go:15`），32 字节随机数
- bbolt 文件本身**不加密**，session 数据以 gob 序列化存储
- 内存中维护 `map[SessionToken]*Session` 索引（`sessionstorage.go:83`），由 `sync.Mutex` 保护
- `DefaultSessionStorage.mu` 保证并发安全（`sessionstorage.go:75`）

### 3.4 敏感数据保护总览

| 数据类型 | 存储位置 | 保护方式 | 风险点 |
|---|---|---|---|
| 用户密码 | `AdGuardHome.yaml` → `users[].password` | bcrypt 哈希（`$2a$10$`） | 无 |
| TLS 私钥（内联模式） | `AdGuardHome.yaml` → `tls.private_key` | **明文** | ⚠️ 文件读权限即可获取私钥 |
| TLS 私钥（文件引用模式） | 外部文件 | 文件系统权限 | 依赖 OS 文件权限保护 |
| TLS 证书/私钥运行时数据 | 内存 `CertificateChainData`/`PrivateKeyData` | `yaml:"-" json:"-"` 不暴露 | 内存 dump 可获取 |
| Session token | `sessions.db` (bbolt) | `crypto/rand` 生成 | bbolt 文件不加密 |
| API 认证 | Cookie / Basic Auth | Session token 或 bcrypt 验证 | 明文 HTTP 下可被嗅探 |

**结论**：AdGuard Home 对用户密码使用了业界标准的 bcrypt 单向哈希保护，但对 TLS 私钥的内联存储是明文的。如果需要更高的安全性，应使用文件引用模式并配合 OS 级文件权限保护。

---

## 四、运行时配置热加载

AdGuard Home 的热加载机制分为两层：**配置持久化**（写入 YAML 文件）和 **运行时生效**（通知各模块重配）。

### 4.1 ConfigModifier 接口

`internal/agh/agh.go:15` 定义了统一的配置修改回调接口：

```go
type ConfigModifier interface {
    Apply(ctx context.Context)
}
```

全局默认实现是 `internal/home/config.go:977` 的 `defaultConfigModifier`：

```go
type defaultConfigModifier struct {
    auth     *auth
    config   *configuration
    logger   *slog.Logger
    tlsMgr   *tlsManager
    workDir  string
    confPath string
}

func (cm *defaultConfigModifier) Apply(ctx context.Context) {
    // 将所有模块的运行时状态回写到全局 config，再原子写入 YAML
    err := cm.config.write(ctx, cm.logger, cm.tlsMgr, cm.auth, cm.workDir, cm.confPath)
    if err != nil {
        cm.logger.ErrorContext(ctx, "writing config", slogutil.KeyError, err)
    }
}
```

### 4.2 配置持久化：configuration.write()

`internal/home/config.go:873` - 将所有模块的运行时状态汇总到全局 `config` 对象后，使用 `renameio` 原子写入磁盘：

```go
func (c *configuration) write(
    ctx context.Context, l *slog.Logger,
    tlsMgr *tlsManager, auth *auth,
    workDir string, confPath string,
) (err error) {
    c.Lock()
    defer c.Unlock()
    // 从各模块拉取最新配置
    if auth != nil        { config.Users = auth.usersList(ctx) }
    if tlsMgr != nil      { config.TLS = *tlsMgr.extendedTLSConfig() }
    if globalContext.stats != nil       { globalContext.stats.WriteDiskConfig(...) }
    if globalContext.queryLog != nil    { globalContext.queryLog.WriteDiskConfig(...) }
    if globalContext.filters != nil     { globalContext.filters.WriteDiskConfig(config.Filtering) }
    if globalContext.dnsServer != nil   { globalContext.dnsServer.WriteDiskConfig(&c) }
    if globalContext.dhcpServer != nil  { globalContext.dhcpServer.WriteDiskConfig(config.DHCP) }
    config.Clients.Persistent = globalContext.clients.forConfig()
    // 原子写入（renameio 先写临时文件再 rename）
    buf := &bytes.Buffer{}
    enc := yaml.NewEncoder(buf)
    enc.SetIndent(2)
    enc.Encode(config)
    return maybe.WriteFile(confPath, buf.Bytes(), aghos.DefaultPermFile)
}
```

### 4.3 DNS 服务器热重载

`internal/dnsforward/dnsforward.go:848` 的 `Server.Reconfigure()` 是 DNS 运行时重配的核心：

```go
func (s *Server) Reconfigure(ctx context.Context, conf *ServerConfig) error {
    s.serverLock.Lock()
    defer s.serverLock.Unlock()
    // 1. 停止当前服务
    s.stopLocked(ctx)
    // 2. 等待 FD 释放（net.Listener.Close 是异步的）
    time.Sleep(100 * time.Millisecond)
    // 3. 关闭旧的地址处理器
    if s.addrProc != nil { s.addrProc.Close() }
    // 4. 使用新配置重新 Prepare
    if conf == nil { conf = &s.conf }
    err := s.Prepare(ctx, conf)
    // 5. 重新启动
    err = s.startLocked(ctx)
    return nil
}
```

`Reconfigure()` 的本质是 **停止 → 重建 → 启动** 的全量热重启，不是增量更新。虽然叫 "Reconfigure"，但内部实现是把整个 DNS proxy 销毁重建。

> **注释 TODO** (`dnsforward.go:650`)：`Some of these could probably be updated without a restart.` 代码作者也承认目前的实现比较"粗暴"，理论上很多配置可以做到真正的热更新而不需要重启整个 proxy。

### 4.4 DNS 监听端口与绑定地址的运行时更改

这是一个容易混淆的点：**DNS 普通端口（53）和绑定 IP 无法通过运行时 API 修改，只有 TLS 相关端口可以热更。**

#### 现状：两种端口，两种命运

| 端口类型 | 配置字段 | 能否运行时热更 | 触发方式 |
|---|---|---|---|
| 普通 DNS 端口 | `dns.port` / `dns.bind_hosts` | ❌ 不能 | 只能修改 YAML 后重启进程 |
| DoT/DoH/DoQ/DNSCrypt 端口 | `tls.port_dns_over_tls` 等 | ✅ 可以 | `POST /control/tls/configure` → `Reconfigure()` |

#### 证据：jsonDNSConfig 的字段

`internal/dnsforward/http.go:28` 的 `jsonDNSConfig` 结构体是 `/control/dns_config` API 的请求/响应格式，**完全没有** `bind_hosts`、`port` 字段：

```go
type jsonDNSConfig struct {
    Upstreams               *[]string               `json:"upstream_dns"`
    Bootstraps              *[]string               `json:"bootstrap_dns"`
    Fallbacks               *[]string               `json:"fallback_dns"`
    ProtectionEnabled       *bool                   `json:"protection_enabled"`
    Ratelimit               *uint32                 `json:"ratelimit"`
    CacheSize               *uint32                 `json:"cache_size"`
    // ... 总共 20+ 字段
    // 但没有 bind_hosts，没有 port
}
```

对应的 `setConfig()` 和 `setConfigRestartable()` 函数也只修改内存中的 `s.conf` 字段，不涉及监听地址。当 `shouldRestart` 为 true 时，调用 `Reconfigure(ctx, nil)` —— **传 nil 意味着复用 s.conf 里的监听地址**，并不会改变端口。

#### TLS 端口热更改挂载点

TLS 相关的监听端口（DoT/DoH/DoQ/DNSCrypt）走的是另一条链路：

```
POST /control/tls/configure
  │
  ├─ handleTLSConfigure() [tls.go:566]
  │   ├─ m.loadTLSConfig()       读取证书文件
  │   ├─ m.setConfig()           更新 m.extTLSConf（含各 TLS 端口）
  │   ├─ m.reconfigureDNSServer() [tls.go:292]
  │   │   └─ newServerConfig()   基于 config.DNS + m.extTLSConf 生成新 ServerConfig
  │   │       ├─ 普通 DNS 端口：从 config.DNS.Port 读（不变）
  │   │       └─ TLS 端口：从 m.extTLSConf 读（已更新）
  │   └─ dnsServer.Reconfigure(ctx, newConf)
  │       └─ 重建 dns proxy，监听新的 TLS 端口
  │
  └─ 同时重启 HTTPS Server（web 接口的 HTTPS 端口）
```

`newServerConfig()` (`dns.go:263`) 是关键挂载点 —— 它把普通 DNS 配置和 TLS 配置合并成 `dnsforward.ServerConfig`，其中：

```go
newConf := &dnsforward.ServerConfig{
    UDPListenAddrs: ipsToUDPAddrs(hosts, dnsConf.Port),  // 普通 DNS 端口
    TCPListenAddrs: ipsToTCPAddrs(hosts, dnsConf.Port),  // 普通 DNS 端口
    TLSConf: &dnsforward.TLSConfig{
        HTTPSListenAddrs: ipsToAddrPorts(addrs, extTLSConf.PortHTTPS),     // DoH
        TLSListenAddrs:   ipsToTCPAddrs(addrs, extTLSConf.PortDNSOverTLS), // DoT
        QUICListenAddrs:  ipsToUDPAddrs(addrs, extTLSConf.PortDNSOverQUIC),// DoQ
        DNSCryptConf: ...                                                  // DNSCrypt
    },
}
```

#### 为什么普通 DNS 端口不支持热更？

代码中没有明确解释，但可以推断几个原因：

1. **安全考量**：53 端口是特权端口，启动时就要获得绑定权限，运行时改端口可能涉及权限变化
2. **系统集成复杂**：很多操作系统（Linux systemd-resolved、macOS）会监听 53 端口，换端口需要配合系统级改动
3. **历史包袱**：DNS 端口和绑定 IP 在启动流程早期就确定了（`setupContext` 阶段就要检查端口占用），深耦合到整个启动流程
4. **需求少**：实际使用场景中，DNS 端口一旦设好就很少改动

### 4.5 TLS 证书文件自动热加载（DNS 端口热更的特殊场景）

`internal/home/tls.go:217` 的 `handleCertFileChange()` 通过文件系统事件监控证书变更：

```go
func (m *tlsManager) handleCertFileChange(ctx context.Context) {
    updates := m.manager.Updates(ctx)  // aghtls 文件 watcher
    for range updates {
        m.reload(ctx)  // 有文件变更时触发 reload
    }
}

func (m *tlsManager) reload(ctx context.Context) {
    // 对比证书文件 ModTime
    fi, _ := os.Stat(certPath)
    if fi.ModTime().UTC().Equal(m.certLastMod) {
        return  // 未变更则跳过
    }
    // 重新加载证书
    m.loadTLSConfig(ctx, &tlsConf, status)
    m.extTLSConf = &tlsConf
    m.certLastMod = fi.ModTime().UTC()
    // 重新配置 DNS 服务器
    m.reconfigureDNSServer(ctx)
    // 重启 HTTPS Server
    m.web.tlsConfigChanged(context.Background(), m.extTLSConf)
}
```

### 4.6 各模块配置更新的通用模式

所有模块的配置更新 HTTP Handler 都遵循同一模式：

```go
func (s *Module) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    reqData := decode(r.Body)
    validate(reqData)

    // 关键：用 defer 确保配置持久化
    defer s.configModifier.Apply(ctx)

    s.confMu.Lock()
    defer s.confMu.Unlock()

    // 修改运行时配置（立即生效）
    s.enabled = reqData.Enabled
    s.limit = reqData.Interval
    s.ignored = newEngine
}
```

典型示例：`internal/stats/http.go:227` 的 `handlePutStatsConfig()`、`internal/home/tls.go:566` 的 `handleTLSConfigure()`。

### 4.7 并发配置写入的锁保护机制

AdGuard Home 的锁设计是**多层嵌套**的，从全局 HTTP 请求级别的互斥锁，到各个模块内部的细粒度读写锁，形成了一个清晰的锁层级。

#### 锁层级全景

```
请求进入
  │
  ├─ L1: globalContext.controlLock (sync.Mutex) —— 所有 POST/PUT/DELETE 请求全局互斥
  │     挂载点: control.go:251 ensure() 中间件
  │
  ├─ 业务 Handler 执行
  │     │
  │     ├─ L2a: tlsManager.mu (sync.Mutex) —— TLS 配置读写互斥
  │     │     挂载点: tls.go:591 handleTLSConfigure()
  │     │
  │     ├─ L2b: dnsforward.Server.serverLock (sync.RWMutex) —— DNS 服务器状态
  │     │     读锁: 所有 DNS 查询处理 (process.go:161)、读配置 (http.go:148)
  │     │     写锁: setConfig()、Reconfigure()、Start()、Stop()
  │     │
  │     ├─ L2c: stats.confMu (sync.RWMutex) —— 统计配置
  │     ├─ L2d: querylog.confMu (sync.RWMutex) —— 查询日志配置
  │     └─ ... 其他模块 confMu
  │
  ├─ defer ConfigModifier.Apply() 触发配置持久化
  │     │
  │     └─ L3: configuration.Lock() (sync.RWMutex 写锁)
  │           挂载点: config.go:881 configuration.write()
  │
  └─ 响应返回
```

#### L1：全局请求级互斥锁 controlLock

`home.go:73` 定义：
```go
type homeContext struct {
    ...
    controlLock sync.Mutex
}
```

`control.go:251` 的 `ensure()` 中间件对所有数据修改请求加锁：

```go
func (web *webAPI) ensure(method string, handler ...) (wrapped http.HandlerFunc) {
    return func(w http.ResponseWriter, r *http.Request) {
        // ... 方法校验、Content-Type 校验 ...

        if modifiesData(m) {   // POST || PUT || DELETE
            globalContext.controlLock.Lock()
            defer globalContext.controlLock.Unlock()
        }

        handler(w, r)
    }
}
```

**影响范围**：
- ✅ 同一时刻只能有一个 POST/PUT/DELETE 请求在执行（包括不同模块的不同 API）
- ❌ 这是一个粗粒度锁，会阻塞并行的无关联配置修改（比如改 stats 配置和改 TLS 配置不能并发）
- ❌ GET 请求不受影响，可以并发读

**锁覆盖范围**：整个 Handler 执行期间（包括 `defer ConfigModifier.Apply()` → `config.write()`），`controlLock` 一直持有。这意味着 `L1 ⊃ L2 ⊃ L3`，外层锁总是在持有状态下获取内层锁，**不会出现死锁**（只要所有请求都通过 ensure 中间件进入）。

#### L2：模块级锁（每个模块独立）

| 锁 | 类型 | 保护对象 | 写锁场景 | 读锁场景 |
|---|---|---|---|---|
| `tlsManager.mu` | `sync.Mutex` | TLS 配置、证书状态、servePlainDNS | `handleTLSConfigure()`、`reload()`、`reconfigureDNSServer()` | 无（使用 Mutex，读写都互斥） |
| `dnsforward.Server.serverLock` | `sync.RWMutex` | DNS 服务器整体状态、conf、isRunning | `setConfig()`、`Reconfigure()`、`Start()`、`Stop()`、`handleSetProtection()` | DNS 请求处理 (`process.go:161`)、读配置 (`getDNSConfig`)、访问控制检查 |
| `stats.confMu` | `sync.RWMutex` | stats 的 limit/enabled/ignored 配置 | `handlePutStatsConfig()`、`handleResetConfig()` | `handleGetStatsConfig()`、数据写入时检查 enabled |
| `querylog.confMu` | `sync.RWMutex` | querylog 的 enabled/fileEnabled/interval 等 | `handlePutConfig()`、`handlePutAnonymizeClientIP()` | `handleGetConfig()`、日志写入时检查配置 |
| `updater.mu` | `sync.RWMutex` | 版本更新状态 | 检查更新、执行更新 | 读取更新状态 |

**关键细节 —— dnsforward.serverLock 的写锁范围**：

`Reconfigure()` (`dnsforward.go:848`) 写锁覆盖整个停止→等待→重建→启动过程（可能耗时数百毫秒），期间所有 DNS 查询被阻塞。

```go
func (s *Server) Reconfigure(ctx context.Context, conf *ServerConfig) error {
    s.serverLock.Lock()          // 写锁开始
    defer s.serverLock.Unlock()
    s.stopLocked(ctx)            // 停 DNS
    time.Sleep(100 * time.Millisecond)
    s.addrProc.Close()
    s.Prepare(ctx, conf)         // 重建 proxy
    s.startLocked(ctx)           // 启 DNS
}                                // 写锁释放
```

#### L3：全局配置写锁 configuration.RWMutex

`config.go:167`：
```go
type configuration struct {
    ...
    sync.RWMutex `yaml:"-"`
}
```

写锁仅在 `configuration.write()` (`config.go:881`) 中持有，时间很短（仅 YAML 序列化 + renameio 写入磁盘）。

```go
func (c *configuration) write(...) (err error) {
    c.Lock()              // 写锁开始
    defer c.Unlock()
    // 从各模块拉取配置 → 序列化 YAML → 原子写入
}
```

读锁分散在各处，例如 `handleHTTPSRedirect` (`control.go:377`)、`handleStatus` (`control.go:146`) 等。

#### 锁顺序与死锁防护

锁的获取顺序严格按照 **L1 → L2 → L3** 的层次：

```
controlLock (L1)  ─┬─► tlsManager.mu (L2a) ─► config.Lock (L3)
                   ├─► serverLock (L2b)    ─► config.Lock (L3)
                   ├─► stats.confMu (L2c)  ─► config.Lock (L3)
                   └─► ...
```

**反向获取永远不会发生**，因为：
1. L2 和 L3 的获取只在 HTTP Handler 内进行，而所有写请求的 Handler 都被 L1 保护
2. `config.write()` (L3) 只被 `ConfigModifier.Apply()` 调用，后者只在 Handler 的 defer 中触发（此时 L1 已持有）
3. DNS 请求处理路径只获取 `serverLock.RLock()` (L2b)，不会再获取 L1 或 L3

唯一的潜在风险是 TLS 配置更新路径中同时持有 `tlsManager.mu` 和调用 `config.Lock()`：

```go
// tls.go:585-638 handleTLSConfigure()
m.mu.Lock()                          // L2a 已持有
...
if req.ServePlainDNS != aghalg.NBNull {
    config.Lock()                     // 获取 L3
    defer config.Unlock()
    config.DNS.ServePlainDNS = ...
}
m.reconfigureDNSServer(ctx)           // 内部获取 serverLock.Lock() (L2b)
...
// defer: m.confModifier.Apply() → config.write() → config.Lock() (L3)
```

这里的 `L2a → L3` 顺序与其他模块的 `L2b → L3` 顺序一致，不会导致交叉死锁。

#### 锁保护之外的并发风险

| 风险点 | 说明 |
|---|---|
| `config` 全局变量直接赋值 | 代码中存在大量 `config.DNS.Port = ...` 这种直接写全局变量的操作，如果不在锁保护下进行，存在数据竞争。实际中靠 L1 `controlLock` 间接保护（所有写请求都持 L1） |
| `globalContext.*` 模块指针 | 这些指针在启动时初始化后不再替换，但指向的对象内部有各自的锁 |
| `firstRun` 字段 | `web.conf.firstRun` 在 finalizeInstall 中被设置为 false，只写一次且在 L1 保护下，无并发问题 |

### 4.8 配置变更通知到运行中 DNS 服务的完整代码核对

运行时修改 DNS 配置有三条入口路径，每条路径触发 DNS 服务变更通知的方式不同。

#### 路径一：POST /control/dns_config（DNS 通用配置）

```
POST /control/dns_config
  │
  ▼
handleSetConfig()  [dnsforward/http.go:539]
  │
  ├─ json.NewDecoder(r.Body).Decode(req)    解析请求
  ├─ req.validate(ctx, ...)                 校验参数
  │
  ├─ restart := s.setConfig(req)            修改内存配置 [http.go:588]
  │     ├─ 修改 s.dnsFilter 的 BlockingMode / BlockedResponseTTL / ProtectionEnabled
  │     └─ setConfigRestartable(dc)         判断是否需要重启 [http.go:652]
  │          ├─ 修改 s.conf.UpstreamDNS / BootstrapDNS / CacheSize 等
  │          └─ 返回 shouldRestart = true/false
  │
  ├─ s.conf.ConfModifier.Apply(ctx)         持久化到 YAML [http.go:576]
  │
  └─ if restart:
       s.Reconfigure(ctx, nil)              重建 DNS 服务 [http.go:579]
         ├─ s.serverLock.Lock()
         ├─ s.stopLocked(ctx)               停止 DNS proxy
         ├─ time.Sleep(100ms)               等 FD 释放
         ├─ s.Prepare(ctx, &s.conf)         用当前 s.conf 重建
         ├─ s.startLocked(ctx)              启动 DNS proxy
         └─ s.serverLock.Unlock()
```

**通知机制**：同步函数调用，`Reconfigure` 在 HTTP Handler 内阻塞直到 DNS 服务重建完成。此期间 `serverLock` 写锁持有，所有 DNS 查询被阻塞。

**setConfigRestartable 触发重启的字段** (`http.go:652-691`)：

| 字段 | 修改后是否需要重启 | 原因 |
|---|---|---|
| `UpstreamDNS` | ✅ | 上游服务器列表变更需重建 resolver |
| `BootstrapDNS` | ✅ | Bootstrap 变更需重建 resolver |
| `FallbackDNS` | ✅ | Fallback 变更需重建 resolver |
| `CacheEnabled` / `CacheSize` / `CacheMinTTL` / `CacheMaxTTL` / `CacheOptimistic` | ✅ | 缓存配置变更需重建 cache |
| `Ratelimit` | ✅ | 限速配置变更需重建 ratelimiter |
| `UpstreamTimeout` | ✅ | 超时配置变更需重建上游连接 |
| `BlockingMode` / `BlockedResponseTTL` / `ProtectionEnabled` | ❌ | 这些在 `setConfig` 中直接修改 `dnsFilter`，不需要重启 |

#### 路径二：POST /control/tls/configure（TLS 配置变更）

```
POST /control/tls/configure
  │
  ▼
handleTLSConfigure()  [tls.go:566]
  │
  ├─ m.mu.Lock()
  ├─ m.loadTLSConfig(ctx, status, req)      加载证书/私钥
  │     ├─ loadCertificateChainData()       从文件或内联加载证书
  │     ├─ loadPrivateKeyData()             从文件或内联加载私钥
  │     └─ validateCertificates()           校验证书有效性
  │
  ├─ m.setConfig(ctx, req)                  更新 m.extTLSConf
  │     └─ m.extTLSConf = req.clone()       深拷贝新配置
  │
  ├─ if req.ServePlainDNS 变更:
  │     config.Lock()                        获取 L3 锁
  │     config.DNS.ServePlainDNS = ...
  │     config.Unlock()
  │
  ├─ m.reconfigureDNSServer(ctx)            通知 DNS 服务 [tls.go:292]
  │     ├─ newServerConfig()                合并 DNS + TLS 配置 [dns.go:263]
  │     │     ├─ 普通 DNS 端口: config.DNS.Port（不变）
  │     │     ├─ DoH 端口: m.extTLSConf.PortHTTPS（已更新）
  │     │     ├─ DoT 端口: m.extTLSConf.PortDNSOverTLS（已更新）
  │     │     ├─ DoQ 端口: m.extTLSConf.PortDNSOverQUIC（已更新）
  │     │     └─ DNSCrypt: m.extTLSConf.PortDNSCrypt（已更新）
  │     └─ globalContext.dnsServer.Reconfigure(ctx, newConf)
  │           └─ 停 → 等 → 重建 → 启动
  │
  ├─ go m.web.tlsConfigChanged(...)         异步重启 HTTPS Server
  │
  └─ m.mu.Unlock()
```

**通知机制**：`reconfigureDNSServer()` 是同步调用，在 `tlsManager.mu` 保护下执行。DNS 服务重建完成后，再异步重启 HTTPS Server。

**与路径一的关键区别**：
- 路径一传 `nil` 给 `Reconfigure`，复用当前 `s.conf`
- 路径二传全新 `newConf`，因为 TLS 端口/证书已变更

#### 路径三：TLS 证书文件自动变更（文件系统 watcher）

```
文件系统事件（证书文件被替换）
  │
  ▼
handleCertFileChange()  [tls.go:217]
  │  for range m.manager.Updates(ctx):
  │      m.reload(ctx)
  │
  ▼
m.reload(ctx)  [tls.go:247]
  ├─ os.Stat(certPath).ModTime 对比        检查文件是否真的变了
  │  └─ ModTime 未变 → return（跳过）
  │
  ├─ m.loadTLSConfig(ctx, &tlsConf, status) 重新加载证书
  ├─ m.extTLSConf = &tlsConf               更新运行时配置
  ├─ m.certLastMod = fi.ModTime.UTC()      记录最新 ModTime
  ├─ m.reconfigureDNSServer(ctx)           通知 DNS 服务
  └─ m.web.tlsConfigChanged(...)            重启 HTTPS Server
```

**通知机制**：与路径二相同，但**由文件系统事件驱动**而非 HTTP 请求驱动。此路径不经过 `controlLock`（没有 HTTP 请求），但 `tlsManager.mu` 仍然保护并发安全。

#### 三条路径的对比

| 维度 | 路径一（dns_config） | 路径二（tls/configure） | 路径三（文件 watcher） |
|---|---|---|---|
| 触发方式 | HTTP POST 请求 | HTTP POST 请求 | 文件系统事件 |
| controlLock (L1) | ✅ 持有 | ✅ 持有 | ❌ 不经过 |
| tlsManager.mu (L2a) | ❌ 不持有 | ✅ 持有 | ✅ 持有 |
| serverLock (L2b) | ✅ Reconfigure 内持有 | ✅ Reconfigure 内持有 | ✅ Reconfigure 内持有 |
| config.Lock (L3) | ✅ ConfModifier.Apply 内持有 | ✅ 修改 ServePlainDNS 时持有 | ❌ 不写 config |
| Reconfigure 参数 | `nil`（复用 s.conf） | 新 `newConf` | 新 `newConf` |
| 配置持久化 | ✅ ConfModifier.Apply | ✅ defer ConfModifier.Apply | ❌ 无（下次 config.write 会拉取最新状态） |
| 影响 DNS 查询 | ✅ Reconfigure 期间阻塞 | ✅ Reconfigure 期间阻塞 | ✅ Reconfigure 期间阻塞 |
| 影响 HTTPS Server | ❌ 不影响 | ✅ 异步重启 | ✅ 异步重启 |

---

## 五、全局关系全景图

```
AdGuardHome 启动
     │
     ▼
detectFirstRun() ── 配置文件存在？
     │
     ├── YES ────────────────────────────────────┐
     │                                            │
     │   parseConfig()                            │
     │     ├─ 读 YAML                             │
     │     ├─ Migrator.Migrate(v? → v34) ◄───────┤ 版本迁移
     │     ├─ 写回升级后的 YAML                   │
     │     └─ Unmarshal → config                 │
     │                                            │
     │   runDNSServer() ─ 启动 DNS/DHCP          │
     │                                            │
     └── NO ── registerInstallHandlers() ◄───────┤ 初始化向导
                  │                               │
                  ▼                               │
           Setup Wizard (5 steps)                 │
                  │                               │
                  ▼                               │
        handleInstallConfigure()                 │
           ├─ 创建管理员用户                      │
           ├─ startMods() → 启动 DNS             │
           ├─ config.write() ── 首次写入 YAML ───┘
           └─ 切换 control handlers
                        │
                        ▼
              运行时配置修改阶段
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
 Stats API   TLS API    Filtering API ...
     │            │            │
     └────────────┼────────────┘
                  ▼
       1. 修改模块运行时状态（立即生效）
       2. dnsServer.Reconfigure()（如需）
       3. defer configModifier.Apply()
            └─ config.write() ─ 原子写入 YAML
```

---

## 六、关键代码索引

### Setup 与初始化

| 功能 | 文件 | 行号 |
|---|---|---|
| 首次运行检测 | `internal/home/home.go` | 1345 |
| 主入口 run() | `internal/home/home.go` | 757 |
| setupContext() | `internal/home/home.go` | 182 |
| Install API 注册 | `internal/home/controlinstall.go` | 644 |
| finalizeInstall() | `internal/home/controlinstall.go` | 475 |
| copyInstallSettings() 回滚函数 | `internal/home/controlinstall.go` | 374 |
| initDNSServer() 中 defer 回滚 | `internal/home/dns.go` | 159 |
| HTTP Server 地址切换循环 | `internal/home/web.go` | 262 |
| rc.Flush() 立即刷新响应 | `internal/home/controlinstall.go` | 559 |
| preInstallHandler firstRun 守卫 | `internal/home/control.go` | 338 |
| isPublicResource 免认证路由列表 | `internal/home/authhttp.go` | 313 |
| handleLogin 设置 Cookie | `internal/home/authhttp.go` | 107 |

### 版本迁移

| 功能 | 文件 | 行号 |
|---|---|---|
| parseConfig + 迁移触发 | `internal/home/config.go` | 684 |
| Migrator.Migrate() | `internal/configmigrate/migrator.go` | 45 |
| upgradeConfigSchema() 顺序迁移 | `internal/configmigrate/migrator.go` | 108 |
| LastSchemaVersion (v34) | `internal/configmigrate/configmigrate.go` | 5 |
| YAML 工具函数 fieldVal/moveVal | `internal/configmigrate/yaml.go` | 17 |
| v5 明文密码→bcrypt 迁移 | `internal/configmigrate/v5.go` | 24 |
| v34 迁移示例 | `internal/configmigrate/v34.go` | 26 |

### 敏感数据与加密存储

| 功能 | 文件 | 行号 |
|---|---|---|
| bcrypt 密码哈希 (addUser) | `internal/home/auth.go` | 204 |
| bcrypt 密码验证 (Authenticate) | `internal/aghuser/aghuser.go` | 52 |
| 用户 DB (DefaultDB) 并发安全 | `internal/aghuser/db.go` | 46 |
| DefaultDB.Create() 重复检查 | `internal/aghuser/db.go` | 127 |
| TLS 私钥内联/文件引用模式 | `internal/home/config.go` | 335 |
| CertificateChainData/PrivateKeyData 不序列化 | `internal/home/config.go` | 353 |
| loadCertificateChainData() | `internal/home/tls.go` | 361 |
| Session 存储 (bbolt) | `internal/aghuser/sessionstorage.go` | 67 |
| Session token 生成 (crypto/rand) | `internal/aghuser/session.go` | 15 |
| preInstallHandler (firstRun 守卫) | `internal/home/control.go` | 338 |

### 运行时热加载

| 功能 | 文件 | 行号 |
|---|---|---|
| ConfigModifier 接口 | `internal/agh/agh.go` | 15 |
| configuration.write() 原子持久化 | `internal/home/config.go` | 873 |
| defaultConfigModifier | `internal/home/config.go` | 977 |
| DNS Server.Reconfigure() | `internal/dnsforward/dnsforward.go` | 848 |
| DNS Server.Prepare() | `internal/dnsforward/dnsforward.go` | 483 |
| /control/dns_config 请求结构体 | `internal/dnsforward/http.go` | 28 |
| handleSetConfig (DNS 配置更新 handler) | `internal/dnsforward/http.go` | 539 |
| setConfigRestartable (判断是否需重启) | `internal/dnsforward/http.go` | 652 |
| newServerConfig() 端口合并挂载点 | `internal/home/dns.go` | 263 |
| TLS 配置更新 handler | `internal/home/tls.go` | 566 |
| TLS reconfigureDNSServer() | `internal/home/tls.go` | 292 |
| TLS 证书文件自动热加载 | `internal/home/tls.go` | 217 |
| 全局并发锁 ensure() | `internal/home/control.go` | 251 |
| Stats 配置更新示例 | `internal/stats/http.go` | 227 |

### 前端状态同步

| 功能 | 文件 | 行号 |
|---|---|---|
| openDashboard 跳转逻辑 | `client/src/install/Setup/index.tsx` | 63 |
| getWebAddress URL 生成 | `client/src/helpers/helpers.tsx` | 249 |
| checkRedirect 重试跳转 | `client/src/helpers/helpers.tsx` | 264 |
| setAllSettings Redux Action | `client/src/actions/install.ts` | 27 |
| processLogin Redux Action | `client/src/actions/login.ts` | 11 |
| Api.makeRequest 403 拦截 | `client/src/api/Api.ts` | 24 |
| App.tsx Dashboard 初始化 | `client/src/components/App/index.tsx` | 120 |
| Submit 组件 (Step 5) | `client/src/install/Setup/Submit.tsx` | 13 |
| Controls 组件 (Open Dashboard 按钮) | `client/src/install/Setup/Controls.tsx` | 82 |

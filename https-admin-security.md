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

### 2.4 ACME 与 Fallback 证书：无内置自动签发，仅被动文件监听

#### 核心结论：AdGuard Home **不内置** ACME 客户端 / 自动证书签发能力

代码库中完全不存在以下组件：
- ❌ 没有 `autocert` / `certmagic` / `lego` 等 ACME 库的引用
- ❌ 没有 `http-01` / `dns-01` / `tls-alpn-01` challenge 处理逻辑
- ❌ 没有 Let's Encrypt 相关配置项（无 `acme_server` / `email` / `agree_tos` 等字段）
- ❌ 没有预生成的自签名 fallback 证书机制

#### TLS 配置仅支持两种证书提供方式

**位置**：`internal/home/config.go:303-363` `tlsConfigSettings`

```go
type tlsConfigSettings struct {
    // 方式一：内联 PEM 字符串（通过 Web UI 粘贴）
    CertificateChain string   // yaml: certificate_chain
    PrivateKey       string   // yaml: private_key

    // 方式二：文件路径（配合外部续签工具 + FSWatcher）
    CertificatePath  string   // yaml: certificate_path
    PrivateKeyPath   string   // yaml: private_key_path
    // ...
}
```

**两种方式互斥**：配置时二选一，同时设置以 `CertificatePath` / `PrivateKeyPath` 为优先（从 `loadCertificateChainData` 和 `loadPrivateKeyData` 的加载逻辑来看）。

#### 自签名证书的特殊处理：校验放宽但不自动生成

**位置**：`internal/home/tls.go:983-1019` `validateCertificate()`

```go
func (m *tlsManager) validateCertificate(ctx, status, certChain, serverName) (ok bool, err error) {
    certs, status.ValidCert, parseErr = m.parseCertChain(ctx, certChain)
    if !status.ValidCert { return false, parseErr }

    err = m.validateCertChain(ctx, certs, serverName)
    if err != nil {
        // ⭐ 关键：自签名证书链验证失败不算错误
        // 只把错误信息放进 WarningValidation，不返回失败
        return true, err
    }

    status.ValidChain = true   // CA 签发的证书才会标记 ValidChain=true
    return true, parseErr
}
```

**行为解读**：
- `ValidCert`: 证书本身格式是否合法（能被 x509.ParseCertificate 解析）
- `ValidChain`: 证书链是否能通过系统根 CA 验证（**自签名证书此处为 false**）
- 自签名证书虽然 `ValidChain=false`，但**不影响使用** —— HTTPS 服务器照样加载，TLS 握手照样完成
- 仅前端 `WarningValidation` 字段会显示警告信息

#### 实际部署中的 ACME 工作模式（需外部工具配合）

```
┌──────────────────────────────────────────────────────────────┐
│  外部 ACME 客户端 (certbot / acme.sh / lego CLI)            │
│    ├─ 执行 ACME challenge (http-01 / dns-01)                │
│    ├─ 申请/续签证书                                          │
│    └─ 写入证书文件到指定路径                                  │
│                              │                               │
│                              ▼  文件系统写操作               │
│  AdGuard Home 进程                                          │
│    └─ FSWatcher (fsnotify) 监听文件变更                      │
│       └→ aghtlsMgr.handleEvents()                           │
│          └→ tlsManager.reload()                             │
│             └→ 重新加载证书 + 重启 HTTPS/DNS 服务器         │
└──────────────────────────────────────────────────────────────┘
```

**设计取舍**：
- **优点**：职责分离，AdGuard Home 专注于 DNS/过滤，证书管理交给专业工具；避免在核心进程中引入复杂的 ACME 状态机
- **缺点**：首次部署需要额外配置 certbot deploy hook 或依赖文件系统监听，链路较长
- **无 fallback 风险**：如果证书文件完全失效（过期 + 续签失败），HTTPS 服务器会启动失败，但 HTTP 管理后台仍然可用（前提是没开 ForceHTTPS）

#### 补充：测试用自签名证书的技术参数（非运行时 fallback）

**文件位置**：`internal/home/testdata/cert.pem`

通过 `openssl x509 -text` 解析出的完整参数：

| 参数 | 值 |
|------|----|
| **签名算法** | `sha256WithRSAEncryption` |
| **公钥算法** | RSA 1024 位（测试用，生产不推荐） |
| **公钥指数** | 65537 (0x10001) |
| **序列号** | `c4:fd:90:f5:49:74:ce:cb` |
| **Subject** | `O=AdGuard Ltd, CN=AdGuard Home` |
| **Issuer** | `O=AdGuard Ltd, CN=AdGuard Home`（自签名） |
| **Not Before** | Feb 27 09:24:23 2019 GMT |
| **Not After** | Jul 14 09:24:23 2046 GMT |
| **有效期时长** | **约 27.4 年** |
| **X509v3 扩展** | Subject Key Identifier, Authority Key Identifier (CA 标志), Basic Constraints: CA:TRUE |
| **验证结果** | `ValidCert=true`, `ValidChain=false`（自签名，系统根 CA 不认可） |

**测试用例中的验证断言** (`tls_internal_test.go:76-87`)：

```go
notBefore := time.Date(2019, 2, 27, 9, 24, 23, 0, time.UTC)
notAfter := time.Date(2046, 7, 14, 9, 24, 23, 0, time.UTC)

assert.Equal(t, "RSA", status.KeyType)
assert.Equal(t, "CN=AdGuard Home,O=AdGuard Ltd", status.Subject)
assert.Equal(t, "CN=AdGuard Home,O=AdGuard Ltd", status.Issuer)
assert.Equal(t, notBefore, status.NotBefore)
assert.Equal(t, notAfter, status.NotAfter)
assert.True(t, status.ValidPair)
assert.True(t, status.ValidCert)
assert.False(t, status.ValidChain)  // 自签名证书链验证失败是预期的
```

**重要澄清**：
- ❌ **这不是运行时自动生成的 fallback 证书**，仅用于单元测试
- ❌ 代码中**没有**在运行时调用 `x509.CreateCertificate()` 生成自签名证书的逻辑
- ❌ **没有**所谓「ACME 失败时自动切到自签名 fallback」的代码路径
- ✅ 如果启用了 TLS 但证书文件无效，唯一的结果是 HTTPS 服务器启动失败
- ✅ HTTP 管理后台不受影响（除非配置了 `ForceHTTPS=true`）

**测试中动态生成证书的代码**（仅用于测试）：

`newCertAndKey()` (`tls_internal_test.go:177-191`)：
```go
func newCertAndKey(tb testing.TB, n int64) (certDER []byte, key *rsa.PrivateKey) {
    key, _ = rsa.GenerateKey(rand.Reader, 2048)
    certTmpl := &x509.Certificate{
        SerialNumber: big.NewInt(n),
        // 注意：NotBefore / NotAfter 未设置！
        // 这意味着证书默认有效期：Now → Now+10年（x509 包默认行为）
    }
    certDER, _ = x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &key.PublicKey, key)
    return certDER, key
}
```

`newCertWithoutIP()` (`tls_internal_test.go:116-174`)：
```go
caTmpl := &x509.Certificate{
    NotBefore: now.Add(-time.Hour),   // 1小时前
    NotAfter:  now.Add(time.Hour),    // 1小时后
    IsCA:      true,
    KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
}
// 有效期仅 2 小时，用于测试过期场景
```

### 2.5 SIGHUP / systemd reload：证书重载的外部触发通道

除了文件系统自动监听，AdGuard Home 还提供了**信号触发**的证书重载路径，用于 systemd / init 系统集成。

#### 信号处理入口

**位置**：`internal/home/signal.go:20-131`

```go
type signalHandler struct {
    logger        *slog.Logger
    mu            *sync.Mutex
    clientStorage *client.Storage
    tlsManager    aghtls.Manager   // ⭐ 注意：是 aghtls.Manager 接口
                                   // 不是 home.tlsManager！
    signals       <-chan os.Signal
    cleanup       func(ctx context.Context)
}

func (h *signalHandler) handle(ctx context.Context) {
    for {
        sig := <-h.signals
        switch sig {
        case syscall.SIGHUP:
            h.reloadConfig(ctx)   // SIGHUP → 重载配置
        default:
            h.shutdown(ctx)       // 其他信号 → 优雅退出
        }
    }
}

func (h *signalHandler) reloadConfig(ctx context.Context) {
    h.mu.Lock()
    defer h.mu.Unlock()

    if h.clientStorage != nil {
        h.clientStorage.ReloadARP(ctx)
    }

    if h.tlsManager != nil {
        // ⭐ SIGHUP 触发证书 Refresh
        err := h.tlsManager.Refresh(ctx)
        // ...
    }
}
```

#### 信号 → 证书重载的完整链路

```
  外部触发源
    (systemctl reload / kill -HUP / AdGuardHome -s reload)
         │
         ▼
①  向 AdGuard Home 进程发送 SIGHUP 信号
         │
         ▼
②  signalHandler.handle() 收到信号
    位置：internal/home/signal.go:89-99
         │
         ▼  调用 reloadConfig()
③  h.tlsManager.Refresh(ctx)
    注意：此处 tlsManager 是 aghtls.Manager 接口类型
    实际对象：aghtls.DefaultManager
         │
         ▼  non-blocking send to updates channel
④  aghtls.DefaultManager.Refresh() → updates <- UpdateSignal{}
    位置：internal/aghtls/defaultmanager.go:102-114
         │
         ▼  监听 goroutine 收到信号
⑤  tlsManager.handleCertFileChange() 收到 <-updates
    位置：internal/home/tls.go:217-232
         │
         ▼  调用 reload()
⑥  tlsManager.reload()
    ├─ os.Stat() 对比文件修改时间 ⭐ 关键判定
    │   └─ 若 certLastMod 未变化 → 记录日志 + 直接返回
    │      （防抖动，与 FSWatcher 触发行为完全一致）
    └─ 若文件已变更 → loadTLSConfig + 重启 HTTPS/DNS
```

**重要特性**：SIGHUP 触发的 `Refresh()` 与 FSWatcher 触发走的是**同一条下游链路**，且都经过 `certLastMod` 时间戳防抖动检查。即使 SIGHUP 和文件变更同时到达，也不会重复加载。

#### systemd 服务集成路径

**位置**：`internal/ossvc/manager_unix.go:20-61` + `internal/ossvc/config_linux.go:40-67`

##### 路径 A：CLI 命令 `AdGuardHome -s reload`

```
$ AdGuardHome -s reload
     │
     ▼  handleServiceControlAction()
     │  位置：internal/home/service.go:150-211
     ▼  handleServiceReloadCmd()
     │  位置：internal/home/service.go:272-288
     ▼  ossvc.Manager.Reload()
     │
     ▼  查找 PID（二选一）：
     │   1. 读 /var/run/AdGuardHome.pid
     │   2. PIDByCommand() 按进程名查找
     │
     ▼  proc.Signal(syscall.SIGHUP)
        位置：internal/ossvc/manager_unix.go:55
```

##### 路径 B：systemd unit 的 ExecReload（部分可用）

systemd 模板中有条件性的 `ExecReload`：

```ini
{{if .ReloadSignal}}ExecReload=/bin/kill -{{.ReloadSignal}} "$MAINPID"{{end}}
```

**但是**：`ConfigureServiceOptions()` (`internal/ossvc/config.go:14-22`) 中**没有设置** `conf.Option["ReloadSignal"]`，因此生成的 systemd unit 文件**不包含** `ExecReload` 指令。

**实际效果**：
- ✅ `AdGuardHome -s reload` 命令可用（直接发 SIGHUP）
- ❌ `systemctl reload AdGuardHome` 默认不可用（缺少 ExecReload）
- ✅ `kill -HUP <pid>` 始终可用
- ✅ certbot 的 `--deploy-hook "systemctl reload AdGuardHome"` 模式需要额外配置 ExecReload 才能工作

##### 路径 C：certbot deploy-hook 直接调用

推荐的集成方式（绕过 systemd 限制）：

```bash
# /etc/letsencrypt/renewal-hooks/deploy/adguardhome.sh
#!/bin/bash
kill -HUP $(cat /var/run/AdGuardHome.pid)
# 或
AdGuardHome -s reload
```

#### SIGHUP 在 systemd-managed 与 Docker container 部署下的行为差异

##### 信号注册入口（统一逻辑）

**位置**：`internal/home/home.go:130-151`

```go
signals := make(chan os.Signal, 1)
signal.Notify(signals,
    syscall.SIGINT,   // Ctrl+C
    syscall.SIGTERM,  // systemd/docker stop
    syscall.SIGHUP,   // reload  ← 我们关注的
    syscall.SIGQUIT,  // core dump
)

sigHdlr := newSignalHandler(..., signals, ...)
go sigHdlr.handle(ctx)   // 启动独立 goroutine 监听信号
```

**信号分发逻辑**（`signal.go:89-98`）：
```go
for {
    sig := <-h.signals
    switch sig {
    case syscall.SIGHUP:
        h.reloadConfig(ctx)      // 仅重载证书 + ARP 表
    default:
        h.shutdown(ctx)          // 其他信号 → 优雅退出
    }
}
```

##### 部署形态 A：systemd-managed

| 维度 | 行为 |
|------|------|
| **PID 1** | systemd 是 PID 1，AdGuard Home 是子进程 |
| **信号发送者** | systemd 通过 cgroup 跟踪进程，`systemctl kill -s HUP` 直接发信号 |
| **reload 命令** | `AdGuardHome -s reload` → 读 pid 文件 → `kill -HUP <pid>` |
| **ExecReload** | 默认缺失（`ConfigureServiceOptions` 未设置 `ReloadSignal`），需手动配置 |
| **systemd 配置** | `ExecReload=/bin/kill -HUP $MAINPID` |
| **优点** | 信号可靠，cgroup 隔离，journald 日志 |
| **注意** | `ExecReload` 是**同步**的，执行完成前 systemctl 会阻塞 |

**systemd 集成完整链路**：
```
systemctl reload AdGuardHome
     │
     ▼  systemd 执行 ExecReload=
     │  /bin/kill -HUP $MAINPID
     ▼
AdGuardHome 收到 SIGHUP
     │
     ▼  signalHandler.handle()
     ▼  reloadConfig()
     ├─ clientStorage.ReloadARP()
     └─ aghtls.Manager.Refresh() → updates 通道发信号
     │
     ▼  tlsManager.handleCertFileChange()
     ▼  reload() → 检查 certLastMod → 重载证书
     │
     ▼  systemd 认为 ExecReload 执行完成（无需等待实际重载完成）
```

##### 部署形态 B：Docker container

| 维度 | 行为 |
|------|------|
| **PID 1** | `/opt/adguardhome/AdGuardHome` 是容器内 PID 1 |
| **STOPSIGNAL** | Dockerfile 中**未设置** `STOPSIGNAL`，默认 `SIGTERM` |
| **`docker stop`** | 发送 `SIGTERM`（不是 SIGHUP）→ 触发 `shutdown()` 退出 |
| **`docker restart`** | 先 SIGTERM 等 10s，再 SIGKILL → 进程完全重启 |
| **`kill -HUP 1`** | 需要 `docker exec <container> kill -HUP 1` 才能触发热重载 |
| **`docker exec`** | 可执行，但需要容器内有 `kill` 命令（Alpine 镜像默认有） |
| **信号隔离** | 宿主的信号不会透传给容器（除非 `--pid=host`） |
| **注意** | 容器内 PID 1 对信号有特殊处理（SIGINT/SIGTERM 默认忽略，除非进程显式处理） |

**Dockerfile 配置**（`docker/build.Dockerfile`）：
```dockerfile
FROM alpine:3.23

# 没有 STOPSIGNAL 指令 → 默认 SIGTERM
# 没有 HEALTHCHECK 指令

ENTRYPOINT ["/opt/adguardhome/AdGuardHome"]
CMD [ "--no-check-update",
      "-c", "/opt/adguardhome/conf/AdGuardHome.yaml",
      "-w", "/opt/adguardhome/work" ]
```

**Docker 下触发证书热重载的两种方式**：

**方式 1 — 通过 docker exec**（推荐）：
```bash
# certbot deploy-hook 中执行
docker exec adguardhome kill -HUP 1

# 或
docker exec adguardhome /opt/adguardhome/AdGuardHome -s reload
```

**方式 2 — 通过共享 pid namespace**（不推荐）：
```bash
docker run --pid=host ...
# 然后宿主上直接 kill -HUP <host_pid>
```

##### 两种部署形态的关键差异对照表

| 特性 | systemd | Docker |
|------|---------|--------|
| **SIGHUP 触发热重载** | ✅ 原生支持 | ✅ 需 `docker exec` 间接触发 |
| **`stop` 命令信号** | `SIGTERM` | `SIGTERM`（默认，可改 `STOPSIGNAL`） |
| **`reload` 命令** | ✅ `systemctl reload` | ❌ `docker reload` 不存在 |
| **PID 文件** | `/var/run/AdGuardHome.pid` | 容器内 `/var/run/...`（宿主不可见） |
| **进程重启** | `systemctl restart` | `docker restart`（冷重启，session 丢失） |
| **证书热重载对现有连接的影响** | 传输层断开，session 保留 | 同左（热重载时）；冷重启则 session 也丢 |
| **证书文件共享** | 直接读宿主文件系统 | 需 `-v` 挂载 volume 或 bind mount |

##### 代码证据：不同信号的语义差异

从 `signal.go:92-97` 可以清晰看出：
```go
switch sig {
case syscall.SIGHUP:
    h.reloadConfig(ctx)   // 只重载配置，进程不退出
default:
    h.shutdown(ctx)       // 所有其他信号 → 退出进程
}
```

这意味着：
- ✅ **SIGHUP** → 真正的热重载，零停机（仅传输层重连，session 保留）
- ❌ **SIGTERM / SIGINT / SIGQUIT** → 优雅退出，需重新启动，所有状态丢失
- ❌ **Docker 重启** → 进程冷启动，session 仍保留（因为持久化到 bbolt），但所有连接中断时间更长

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

### 3.6 Session Token 机制：纯随机不签名，无 Secret Key 旋转概念

#### 核心结论：Session Token 是**服务端存储的随机不透明令牌**，不是 HMAC 签名 Token

#### Token 生成方式

**位置**：`internal/aghuser/session.go:8-21`

```go
const SessionTokenLength = 16        // 16 字节 = 128 位熵
type SessionToken [SessionTokenLength]byte

func NewSessionToken() (t SessionToken) {
    _, _ = rand.Read(t[:])          // crypto/rand 密码学安全随机数
    return t
}
```

**关键特性**：
- ✅ 使用 `crypto/rand` 密码学安全随机数生成
- ✅ 128 位熵，暴力破解不可行
- ❌ **不是** JWT / PASETO 等自包含令牌
- ❌ **没有** secret key 用于签名 / 验证
- ❌ **没有** 过期时间编码在 token 本身中

#### 认证方式：查表法 vs 验签法

| 特性 | AdGuard Home（查表法） | JWT/HMAC（验签法） |
|------|------------------------|-------------------|
| Token 内容 | 纯随机字节（不透明） | 包含 payload + 签名 |
| 验证方式 | 查内存 map / bbolt | 用 secret key 验签 |
| 服务端存储 | 需要存储所有有效 token | 无需存储（无状态） |
| 立即吊销 | ✅ 直接删除 token 记录 | ❌ 需黑名单 / 等待过期 |
| Secret Key 旋转 | ❌ 无此概念（没有 secret key） | ✅ 旋转 key 可批量失效 |

#### 「旋转 Secret Key 会失效所有 Session」的答案：**不适用**

由于 Session Token 是查表模式而非验签模式，不存在「旋转一个 secret key 就能让所有 session 失效」的机制。

**要批量失效所有 Session，需要：**

1. **直接清空存储**：目前没有公开 API 或配置项支持「一键登出所有用户」
2. **修改 sessionTTL 配置**：只影响新创建的 session 和过期检查，不立即失效
3. **删除 bbolt 数据库文件**：极端手段，会同时丢失其他持久化数据
4. **重启进程**：如果 session 只在内存中 —— 但 AdGuard Home 会持久化到 bbolt，重启不失效

**代码证据**：`DefaultSessionStorage` 中**没有**任何与「secret key」「signing key」「hmac key」相关的字段或方法。整个 `aghuser` 包中找不到 `hmac`、`sha256`、`sign`、`verify` 等关键词。

#### 安全影响分析

**优点**：
- 完全服务端控制，可随时精确吊销单个 session
- Token 不泄露用户信息（无 payload）
- 无需管理 key 轮换策略

**缺点**：
- 无法通过「旋转密钥」快速批量失效所有 session
- 每次请求都需要查存储（内存缓存缓解了性能问题）
- 若 bbolt 数据库泄露，所有有效 session token 都可能被冒用

#### 与 TLS 证书过期的类比

| 维度 | TLS 证书 | Session Token |
|------|---------|---------------|
| 过期检查 | 连接握手时验证 NotAfter | 每次请求时检查 Expire |
| 过期后行为 | 握手失败，直接拒绝 | 返回 401，需重新登录 |
| 续签/续期 | 外部工具续签 + FSWatcher 热重载 | 不自动续期，过期后重新登录生成新 token |
| 批量失效 | 更换证书 → 所有连接需重新握手 | 无快捷方式，需遍历删除所有 session |

### 3.7 EventBus 与多实例集群：架构不支持，分布式锁无必要

#### 核心结论：AdGuard Home 是**单实例单体架构**，没有 EventBus、没有集群同步、没有分布式锁需求。

#### 代码证据一：没有 EventBus / 消息总线组件

全代码库搜索结果：
- ❌ 没有 `EventBus` / `eventbus` 类型定义
- ❌ 没有 `Publish` / `Subscribe` / `Broadcast` 等消息原语
- ❌ 没有 `pubsub` / `message queue` 相关引用
- ❌ 没有 MQTT / NATS / Redis Pub/Sub 等集成

唯一与「broadcast」相关的代码在 **DHCP 模块**（`internal/dhcpd/broadcast_*.go`）：
```go
// broadcast sends resp to the broadcast address specific for network interface.
func (c *dhcpConn) broadcast(respData []byte, peer *net.UDPAddr) (n int, err error) {
    // 这是网络层的 UDP 广播，不是进程间/实例间的消息广播
}
```

#### 代码证据二：没有集群 / 多实例部署支持

全代码库搜索结果：
- ❌ 没有 `cluster` / `replicate` / `multi-instance` 关键词
- ❌ 没有 `leader` / `election` / `raft` / `consensus` 共识算法
- ❌ 没有 `etcd` / `consul` / `redis` 分布式协调组件
- ❌ 没有 `peer` / `node` / `member` 节点概念
- ❌ 没有配置同步、状态复制、冲突解决机制

所有状态都是**进程内**的：
- Session：内存 map + 本地 bbolt 数据库（`sessions.db`）
- 配置：本地 YAML 文件 + 内存缓存
- 统计数据：本地 SQLite / bbolt 数据库
- DNS 缓存：进程内内存

#### 代码证据三：没有 Secret Key 旋转的分布式同步需求

由于 Session Token 是**查表法**而非**验签法**，不存在「多个实例共享一个 signing key」的场景，因此：
- ❌ 不需要「旋转 secret key 后广播到所有实例」
- ❌ 不需要分布式锁保护 secret key 的并发读写
- ❌ 不需要跨实例的 session 失效同步

**单实例架构下的 Session 失效方式**：
1. **过期自动失效**：每次 `FindByToken()` 时懒检查 + 启动时批量清理
2. **修改密码后失效**：当前代码**不会**自动失效该用户的其他 session（`ByLogin` 查用户后只验证密码，不校验 session 与密码修改时间）
3. **手动全量失效**：删除 `sessions.db` 文件后重启进程

#### 关于「secret 旋转需要分布式锁」的命题：伪命题

| 前提 | 是否成立 | 结论 |
|------|---------|------|
| 有 secret key 需要旋转 | ❌ 无 secret key | 不适用 |
| 多实例部署需要同步 | ❌ 不支持集群 | 不适用 |
| 分布式锁保护临界区 | ❌ 无共享资源 | 不适用 |

**如果强行做集群部署（非官方支持）**，需要解决的问题：
1. **Session 共享**：需将 bbolt 替换为 Redis / PostgreSQL 等共享存储
2. **配置同步**：需引入配置中心（etcd / Consul）
3. **证书热重载协调**：所有实例都要监听证书文件变更或接收 reload 信号
4. **统计数据聚合**：多个实例的查询统计需要集中汇总
5. **DNS 缓存一致性**：不同实例的缓存可能不一致

这些都需要**大量代码改造**，超出了当前架构的设计范围。

#### 与 TLS 证书在集群场景下的类比

| 维度 | TLS 证书 | Session Token |
|------|---------|---------------|
| 单实例 | FSWatcher + SIGHUP 热重载 | 内存 map + bbolt 本地存储 |
| 多实例（非官方） | 所有实例监听同一证书文件 / 共享存储 | 需改造成共享存储（Redis） |
| 过期检查 | 每个实例独立检查 | 每个实例独立检查（共享存储则一致） |
| 批量失效 | 所有实例同时重载证书 | 共享存储下删除即全局失效 |

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
| **证书管理器** | `internal/home/tls.go` | 35(tlsManager), 110(newTLSManager), 217(handleCertFileChange), 238(reload), 566(handleTLSConfigure), 983(validateCertificate) | TLS 配置管理、证书重载、API、证书校验 |
| **文件监控层** | `internal/aghtls/manager.go` | 24(Manager接口), 64(Updates通道) | 证书文件监控抽象 |
| **文件监控实现** | `internal/aghtls/defaultmanager.go` | 52(Set), 102(Refresh), 117(Start), 147(handleEvents) | fsnotify 集成、信号分发、手动刷新 |
| **信号处理** | `internal/home/signal.go` | 20(signalHandler), 75(handle), 93(SIGHUP case), 117(reloadConfig) | SIGHUP 信号处理、触发证书刷新 |
| **服务管理** | `internal/home/service.go` | 118(restartService), 150(handleServiceControlAction), 272(handleServiceReloadCmd) | service CLI 命令、reload 命令入口 |
| **OS服务管理器** | `internal/ossvc/manager_unix.go` | 20(reload), 24(pidFile), 55(proc.Signal SIGHUP) | UNIX 平台 reload 实现（发 SIGHUP） |
| **systemd配置** | `internal/ossvc/config_linux.go` | 12(configureOSOptions), 40(systemdScript模板), 53(ExecReload条件) | systemd unit 模板生成 |
| **服务配置入口** | `internal/ossvc/config.go` | 14(ConfigureServiceOptions) | 跨平台服务配置入口 |
| **Docker构建** | `docker/build.Dockerfile` | 23(alpine基础镜像), 62(ENTRYPOINT), 64(CMD) | Docker 镜像配置，无 STOPSIGNAL |
| **测试证书数据** | `internal/home/testdata/cert.pem` | - | 自签名测试证书：sha256WithRSAEncryption, 1024位RSA, 有效期27.4年 |
| **TLS测试辅助** | `internal/home/tls_internal_test.go` | 76(证书断言), 116(newCertWithoutIP), 177(newCertAndKey) | 测试用证书生成与校验辅助函数 |
| **启动主流程** | `internal/home/home.go` | 130(signal.Notify), 151(sigHdlr.handle goroutine), 757(run), 899(initTLS), 928(sigHdlr.addTLSManager) | 信号注册、整体初始化时序、模块装配 |
| **认证主模块** | `internal/home/auth.go` | 89(auth), 124(newAuth), 159(middleware) | 认证模块初始化、用户DB |
| **认证HTTP层** | `internal/home/authhttp.go` | 29(cookieTTL), 108(handleLogin), 202(newCookie), 375(authMiddlewareDefault), 404(Wrap), 495(userFromRequest), 538(sessionTokenFromHex) | 登录登出、Cookie 处理、鉴权中间件 |
| **Session结构** | `internal/aghuser/session.go` | 9(Token长度16字节), 17(NewSessionToken), 24(Session) | 会话对象与随机 token 生成（查表法，无签名） |
| **Session存储** | `internal/aghuser/sessionstorage.go` | 66(DefaultSessionStorage), 97(NewDefaultSessionStorage), 325(New), 380(FindByToken) | 会话持久化 + 内存缓存 |
| **用户DB** | `internal/aghuser/db.go` | 20(DB接口), 46(DefaultDB), 63(NewDefaultDB) | 用户数据内存存储 |
| **DHCP广播(非EventBus)** | `internal/dhcpd/broadcast_*.go` | 9(broadcast函数) | 网络层UDP广播，非进程间消息总线 |
| **Web服务器** | `internal/home/web.go` | 117(httpsServer), 213(tlsConfigChanged), 253(start), 334(tlsServerLoop), 398(waitForTLSReady) | HTTP/HTTPS 服务生命周期 |
| **配置结构** | `internal/home/config.go` | 180(httpConfig), 196(SessionTTL), 303(tlsConfigSettings), 462(SessionTTL默认值) | http.session_ttl + tls 配置项 |

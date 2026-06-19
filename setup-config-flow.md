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

### 2.5 测试保障

`internal/configmigrate/testdata/TestMigrateConfig_Migrate/` 目录下每个版本都有 `input.yml` 和 `output.yml` 用例，通过 `configmigrate_test.go` 驱动迁移测试，确保每个版本迁移的输入输出严格符合预期。

---

## 三、运行时配置热加载

AdGuard Home 的热加载机制分为两层：**配置持久化**（写入 YAML 文件）和 **运行时生效**（通知各模块重配）。

### 3.1 ConfigModifier 接口

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

### 3.2 配置持久化：configuration.write()

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

### 3.3 DNS 服务器热重载

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

典型的调用链（以 TLS 配置更新为例）：

```
POST /control/tls/configure
  → tlsManager.handleTLSConfigure()  [tls.go:566]
    ├─ m.loadTLSConfig() 加载/校验证书
    ├─ m.setConfig() 更新 m.extTLSConf
    ├─ m.reconfigureDNSServer()  [tls.go:292]
    │   └─ globalContext.dnsServer.Reconfigure(ctx, newConf)
    └─ go m.web.tlsConfigChanged() 异步重启 HTTPS Server
```

### 3.4 TLS 证书文件自动热加载

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

### 3.5 各模块配置更新的通用模式

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

### 3.6 并发控制

- `globalContext.controlLock` (`home.go:73`)：所有修改数据的 HTTP 请求（POST/PUT/DELETE）在进入业务 Handler 前会持有此互斥锁，确保同一时刻只有一个配置修改操作。见 `internal/home/control.go:251` 的 `ensure()` 中间件。
- `configuration.RWMutex`：全局 config 对象自身的读写锁。
- `dnsforward.Server.serverLock`：DNS 服务器重配时的写锁。
- `tlsManager.mu`：TLS 配置互斥锁。
- `configmgr.Manager.updMu`：下一代架构（internal/next）的配置管理器读写锁。

---

## 四、三者关系全景图

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

## 五、关键代码索引

| 功能 | 文件 | 行号 |
|---|---|---|
| 首次运行检测 | `internal/home/home.go` | 1345 |
| 主入口 run() | `internal/home/home.go` | 757 |
| setupContext() | `internal/home/home.go` | 182 |
| Install API 注册 | `internal/home/controlinstall.go` | 644 |
| finalizeInstall() | `internal/home/controlinstall.go` | 475 |
| HTTP Server 地址切换循环 | `internal/home/web.go` | 262 |
| parseConfig + 迁移触发 | `internal/home/config.go` | 684 |
| configuration.write() | `internal/home/config.go` | 873 |
| defaultConfigModifier | `internal/home/config.go` | 977 |
| Migrator.Migrate() | `internal/configmigrate/migrator.go` | 45 |
| upgradeConfigSchema() | `internal/configmigrate/migrator.go` | 108 |
| LastSchemaVersion | `internal/configmigrate/configmigrate.go` | 5 |
| YAML 工具函数 | `internal/configmigrate/yaml.go` | 17 |
| v34 迁移示例 | `internal/configmigrate/v34.go` | 26 |
| DNS Reconfigure() | `internal/dnsforward/dnsforward.go` | 848 |
| TLS 配置 HTTP Handler | `internal/home/tls.go` | 566 |
| TLS 证书文件自动热加载 | `internal/home/tls.go` | 217 |
| ConfigModifier 接口 | `internal/agh/agh.go` | 15 |
| 全局并发锁 ensure() | `internal/home/control.go` | 251 |
| Stats 配置更新示例 | `internal/stats/http.go` | 227 |

# qoqtun 总体架构（V1）

> 定位：高安全性开源内网穿透软件。参考 frp 的 C/S 架构、代理管理与配置体验，**禁止复制 frp 源码**。
> 优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 1. 总体架构

```
                        ┌──────────────────────────────┐
                        │          qoqtun Server        │
                        │  (cmd/server, 仅 CLI)         │
                        │                               │
   Internet 用户 ──────►│  Public Listeners (TCP/HTTP)  │
                        │  UDP Listeners                │
                        │  Control Listener (mTLS:7000) │
                        │  Enroll Listener  (mTLS*、可关)│
                        │                               │
                        │  control / session / tunnel   │
                        │  pki(CA) / auth / security    │
                        │  metrics / logging / config   │
                        └───────▲───────────▲──────────┘
                    控制连接(长连) │           │ 数据连接(按需, 每条公网连接一条)
                                │           │
        ┌───────────────────────┴───────────┴──────────────────┐
        │                   qoqtun Client                       │
        │  cmd/client (CLI)        cmd/desktop (Wails v2 GUI)   │
        │        └──────────── 共用 internal/ Go Core ────────┘ │
        │  transport / control-client / tunnel / pki / keystore │
        └──────────────────────────▲────────────────────────────┘
                                   │ 本地回环
                            Local Service (127.0.0.1:80 ...)
```

- **Server**：单一二进制，内含 Control Listener（mTLS，默认 7000）、可选独立 Enrollment Listener、每个 Tunnel 的 Public Listener。默认最小权限运行（非 root，低端口用 Linux Capability `CAP_NET_BIND_SERVICE`）。
- **Client CLI**：面向服务器/NAS/树莓派，`client run` 常驻，含重连、心跳、统计、日志。
- **Client Desktop**：Wails v2。GUI 只做表现层，**Tunnel/Transport/PKI/认证/配置/安全/连接管理/统计全部来自 Go Core**，前端永不接触私钥与 TLS。
- **Go Core**（`internal/`）：唯一实现处，CLI 与 Desktop 都只是薄壳。

## 2. V1 范围

**IN（V1 必须交付）**
- TCP、UDP、HTTP/HTTPS 转发；多 Tunnel；Tunnel 启停（`client tunnel list/start/stop`）。
- 自动重连（指数退避+Jitter+错误分类）、心跳、状态检测。
- 实时与累计流量统计、连接数统计、结构化日志。
- TOML 配置 + CLI 参数覆盖（优先级 CLI > ENV > Config > Default），`check-config`。
- 客户端唯一 ID、名称、备注；优雅关闭。
- Server 限制：端口范围、Tunnel 数、并发连接数、带宽、UDP Session 数、目标 IP/CIDR/端口白名单。
- TLS 1.3 + mTLS（唯一认证方式）；CSR Enrollment；证书续期/吊销/CA 轮换预案。
- 跨平台私钥安全存储（wincred/Keychain/Secret Service + 0600 文件降级）。
- 三平台：Windows / Linux / macOS（amd64+arm64）。

**OUT（V1 明确不做，但架构预留）**
- QUIC、连接多路复用（Mux）、P2P、Web 管理面板、Server Cluster、插件系统。
- TLS 终止式 HTTPS（L7 解密）、泛域名证书管理、ACME。
- 遥测/Analytics/任何非必要第三方外连。
- 服务端 Web UI、用户体系（多管理员 RBAC）。

## 3. 关键技术取舍（已定，不再讨论）

| 决策点 | 选择 | 理由（取舍说明） |
|---|---|---|
| 语言/工具链 | Go 1.22+，单一 go.mod | 标准库覆盖 TLS/x509/HTTP，交叉编译友好 |
| 控制面编码 | **长度前缀 + JSON**（stdlib `encoding/json`） | 控制面 QPS 极低，JSON 可读、可调试、零 codegen、天然版本化（`type`/`version` 字段）。Protobuf 引入 protoc 工具链依赖，MessagePack 可读性差且收益可忽略；数据面是纯字节流，与编码无关，性能不受影响。**禁止自研二进制协议。** |
| TLS | `crypto/tls`，MinVersion=TLS1.3，ClientAuth=RequireAndVerifyClientCert | 唯一传输；跳过校验/明文认证永远不作为生产功能 |
| 密钥算法 | **Ed25519**（CA、Server、Client 证书统一） | 密钥小、签名快、现代；两端都是 Go，兼容性无问题。预留 `key_algo` 字段以便未来支持 ECDSA P-256 |
| CA 结构 | 每 Server 实例一个 Root CA（自签，10 年），直接签发客户端证书 | V1 不需要中间 CA；CA 轮换用"新旧 CA 并行信任 + 全员续期"完成 |
| 私钥存储 | `github.com/99designs/keyring`（wincred/Keychain/Secret Service）+ 自研 0600 文件降级 | 一个库覆盖三平台系统安全存储；Windows wincred 属系统安全存储（DPAPI 体系）。文件降级由 `internal/platform/keystore` 自研：目录 0700、文件 0600、O_NOFOLLOW 防符号链接、tmp+rename 原子写 |
| CLI | `github.com/spf13/cobra` | 成熟、子命令/flag 体验对标 frp |
| 配置 | `github.com/pelletier/go-toml/v2` | TOML，严格模式（DisallowUnknownFields） |
| 日志 | stdlib `log/slog` + 自研 Redaction Handler | 零外部依赖，结构化分级 |
| 限流 | `golang.org/x/time/rate`（token bucket） | 官方扩展库，无重复造轮子 |
| Desktop | Wails v2（稳定版） | Go 后端 + Web 前端，前端不碰密钥/TLS |
| 依赖纪律 | 外部依赖 ≤ 上表 + Wails 间接依赖；新增依赖必须评审并说明理由 | 供应链安全 |

## 4. Monorepo 结构与依赖规则

```
qoqtun/
├── cmd/
│   ├── server/            # main：装配 config/logging/control/tunnel/pki/enroll
│   ├── client/            # main：CLI 子命令（cert/enroll/run/tunnel/...）
│   └── desktop/           # Wails main：只绑定 internal/coreapi
├── internal/
│   ├── coreapi/           # 【Desktop 唯一入口】面向 GUI 的窄 API 门面
│   ├── config/            # TOML schema、加载、校验、CLI>ENV>Config>Default 合并
│   ├── logging/           # slog 初始化、分级、Secret Redaction
│   ├── platform/          # 跨平台能力
│   │   └── keystore/      # 私钥安全存储（keyring + 0600 文件降级）
│   ├── pki/               # CA、CSR、签发、解析、校验、序列号、吊销列表（纯函数为主）
│   ├── auth/              # Enrollment Token 生成/哈希存储/一次性核销、mTLS 身份提取
│   ├── protocol/          # qoqtun Protocol v1：消息类型、编解码、校验、错误码
│   ├── transport/         # TLS 1.3 mTLS 拨号/监听、连接包装（超时、限读）
│   ├── control/           # Server 端控制面：握手、策略下发、Tunnel 注册仲裁
│   ├── clientcore/        # Client 端：control session、重连、心跳、优雅关闭
│   ├── session/           # 会话注册表：client_id→会话、conn_id→数据连接
│   ├── tunnel/            # Tunnel 抽象 + tcp/udp/http 三种实现、公网 Listener、回源拨号
│   ├── security/          # ACL（端口范围/目标白名单）、限速、连接/Tunnel/UDP Session 限额
│   └── metrics/           # 原子计数器、per-tunnel 实时/累计流量、连接数快照
├── examples/              # server.toml / client.toml 示例
├── docs/                  # 本规划、Protocol、Security 等
├── scripts/               # 构建/发布脚本（不存放任何密钥）
├── .gitignore             # 必含：*.key *.pem *.crt ca/ tokens* .env logs/ dist/ build/
├── README.md SECURITY.md CHANGELOG.md LICENSE
└── go.mod
```

**依赖方向（单向，禁止回边，用 `go list` 脚本检查）：**

```
platform, logging, protocol, metrics   ← 叶子层（互不依赖）
config      → logging
pki         → platform/keystore, logging
auth        → pki, crypto/rand
transport   → protocol, pki, logging
security    → config
session     → protocol, metrics
tunnel      → transport, protocol, session, security, metrics, logging
control     → 上述全部（Server 侧编排）
clientcore  → transport, protocol, tunnel, pki, auth, config（Client 侧编排）
coreapi     → clientcore, config, metrics, logging（只暴露窄接口给 GUI）
cmd/*       → coreapi 或 clientcore/control + config + logging
```

规则：
- `cmd/` 不含业务逻辑；Desktop 只 import `coreapi`。
- `protocol` 不依赖 tunnel/control，保证可独立 Fuzz。
- 不制造无意义 Interface：只在"需要 mock 测试"或"确有多实现"（keystore、Listener/Dialer）处定义接口。
- 为未来预留的方式：协议消息带 `version` 与可扩展字段、Tunnel 有 `type` 枚举、transport 抽象 `Dialer/Listener` 接口（未来 QUIC 实现同接口即可）——**只留扩展点，不提前实现**。

## 5. 数据流（TCP 为例）

1. Client 控制连接握手 → mTLS 双向验证 → `ClientHello`（client_id/version）→ Server 校验证书未吊销 → `ServerHello`（policy：端口范围/限额/心跳参数）。
2. `RegisterTunnel{name,type=tcp,remote_port}` → Server ACL 检查 → 分配 Public Listener → `RegisterTunnelResp{ok, conn 限额}`。
3. 公网用户连 `server:remote_port` → Server 生成 `conn_id` → 控制连接下发 `OpenConnection{conn_id, tunnel_id, src_addr}`。
4. Client 新开一条 mTLS **数据连接**，首帧 `OpenDataConnection{conn_id}` → Server 将数据连接与公网连接 splice。
5. Client 同时按 ACL 校验后 dial `local_ip:local_port`，双向 `io.Copy`（带超时、半关闭传播、背压）。
6. 任一侧 EOF/超时 → 半关闭 → 双侧收尾 → `CloseConnection`（统计落账）。

UDP 与 HTTP 的差异见 04-protocol-v1.md 第 6/7 节。

## 6. 安全基线（全项目恒成立）

- 无默认密码/测试证书/测试 Token/Debug 后门。
- 私钥不出设备；Token 只显一次、服务端只存 SHA-256 哈希。
- 日志统一 redaction；无遥测；除业务连接与用户配置目标外零外连。
- 所有外部输入（路径/IP/CIDR/端口/主机名/Tunnel 名）严格校验；配置永不执行 Shell。
- Server 非 root 运行；panic 不得导致进程退出（连接级 recover + 结构化日志）。

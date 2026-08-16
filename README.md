# qoqtun

> 高安全性开源内网穿透软件（C/S 架构与配置体验对标 [frp](https://github.com/fatedier/frp)，独立实现，**不复制 frp 源码**）。

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

<!-- 徽章占位：CI 状态 / 版本 / 平台矩阵等在上线后补充 -->

qoqtun 包含三个程序：**Server CLI**、**Client CLI**、**Client Desktop**（Wails v2），三者共用同一套 `internal/` Go Core。技术优先级恒定：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 特性（V1）

- TCP / UDP / HTTP / HTTPS 转发；多 Tunnel；Tunnel 启停（`client tunnel list/start/stop`）。
- 自动重连（指数退避 + Jitter + 错误分类）、心跳、状态检测。
- 实时与累计流量统计、连接数统计、结构化日志（统一脱敏）。
- TOML 配置 + CLI 参数覆盖（优先级 `CLI > ENV > Config > Default`），`check-config` 预检。
- 客户端唯一 ID、名称、备注；优雅关闭。
- Server 端强制策略：端口范围、Tunnel 数、并发连接数、带宽、UDP Session 数、目标 IP/CIDR/端口白名单。
- TLS 1.3 + mTLS（唯一认证方式）；CSR Enrollment；证书续期 / 吊销 / CA 轮换预案。
- 跨平台私钥安全存储（wincred / Keychain / Secret Service + 0600 文件降级）。
- 三平台：Windows / Linux / macOS（amd64 + arm64）。

> V1 明确不做：QUIC、连接多路复用（Mux）、P2P、Web 管理面板、Server Cluster、插件系统等。完整清单见 [docs/plan/v1-scope-freeze.md](docs/plan/v1-scope-freeze.md)。

## 架构

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
- **Client CLI**：面向服务器 / NAS / 树莓派，`client run` 常驻，含重连、心跳、统计、日志。
- **Client Desktop**：Wails v2。GUI 只做表现层，业务逻辑全部来自 Go Core，前端永不接触私钥与 TLS。

## 构建

要求：Go 1.22+（单一 go.mod）。

```sh
go build ./...                          # 构建全部程序（cmd/server、cmd/client）
scripts/check.sh                        # 一键检查：fmt → vet → build → 三平台交叉编译 → test → race
go test ./...                           # 单元测试
```

Windows / Linux / macOS × amd64/arm64 均可交叉编译（如 `GOOS=linux GOARCH=arm64 go build ./...`）。CI（GitHub Actions）在三个平台自动执行 vet/build/test，并在 ubuntu/macos 上执行 `-race`。

## 快速开始

> 全链路（`client enroll` → `client run` → Tunnel 转发）将在 Phase 3/5 完成后补齐；当前可用：

```sh
go run ./cmd/server check-config --config examples/server.example.toml   # 解析+校验+打印生效配置
go run ./cmd/client check-config --config examples/client.example.toml   # 同上（敏感值脱敏）
# 示例配置为 Linux 风格路径；Windows 部署请先修改 state_dir 为盘符绝对路径
```

初始化身份（私钥永不落明文文件、永不离开设备）：

```sh
go run ./cmd/server ca init --config server.toml --san 203.0.113.5   # 生成 Root CA + 服务器证书（幂等，--force 覆盖）
go run ./cmd/client cert init --csr-out client.csr      # 生成客户端私钥(入系统安全存储)+client_id+CSR
```

在线签发（一次性 Token + TLS 1.3 Enrollment，操作手册见 [docs/operations/enrollment.md](docs/operations/enrollment.md) 与 [docs/operations/pki.md](docs/operations/pki.md)）：

```sh
go run ./cmd/server client create-token --config server.toml   # 一次性 Token（仅打印一次，服务端只存哈希）
go run ./cmd/server enroll serve --config server.toml          # 启动 enroll/renew 监听
go run ./cmd/client enroll --server 203.0.113.5:7001 --csr client.csr   # token 走 stdin 输入
go run ./cmd/client cert status                               # 身份/到期/CA 指纹
go run ./cmd/server cert list                                 # 已签发证书
go run ./cmd/server cert revoke <serial> --reason "device lost"  # 吊销（下一握手生效）
```

TCP 穿透（Phase 5 起可用；client.toml 配置 `[[tunnels]]` 后启动 client，公网端口即 `remote_port`）：

```sh
go run ./cmd/server run --config server.toml     # 启动控制面（含公网 Tunnel 监听）
go run ./cmd/client run --config client.toml     # 注册隧道、建立数据连接并转发
# 示例：client.toml 中 tunnels.ssh{type=tcp, remote_port=22000, local=127.0.0.1:22}
# 公网访问: ssh -p 22000 user@server
```

HTTP/HTTPS 穿透（Phase 8 起可用；HTTP 多站点共享一个公网端口按 Host 路由，HTTPS 为纯 L4 透传独占端口）：

```sh
# server.toml: [listen] http_vhost_port = 28080
# client.toml:
#   [[tunnels]]  # 两个 HTTP 站点共享 28080，按 Host 路由
#   name = "siteA"; type = "http"; remote_port = 0; http_host = "a.example.com"; local_ip = "127.0.0.1"; local_port = 8080
#   [[tunnels]]  # HTTPS 独占端口（端到端 TLS 不过 Server）
#   name = "tls"; type = "https"; remote_port = 28443; local_ip = "127.0.0.1"; local_port = 8443
# 公网访问: curl -H "Host: a.example.com" http://server:28080/ ; https://server:28443/
```

行为矩阵与安全语义见 [docs/http-https.md](docs/http-https.md)。

## 文档

- 开发规划与设计文档（唯一事实来源）：[docs/plan/README.md](docs/plan/README.md)
- 安全说明与漏洞披露：[SECURITY.md](SECURITY.md)
- 变更日志：[CHANGELOG.md](CHANGELOG.md)
- 示例配置：[examples/](examples/)

## License

[Apache License 2.0](LICENSE)

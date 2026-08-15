# qoqtun V1 范围冻结清单

> 本文件是 V1 范围的**唯一权威清单**，从 [01-architecture.md](01-architecture.md) §2 提取并逐条编号冻结。
> **变更流程**：任何范围变更必须①修改本文件（新增/删除/修订条目并注明日期与理由）②同步更新 [CHANGELOG.md](../../CHANGELOG.md)。
> V1 之外的想法一律先记入 [future.md](future.md)，不得直接改本清单。

- 冻结日期：2026-08-16（Phase 0）

## A. IN（V1 必须交付）

1. **转发能力**：TCP、UDP、HTTP/HTTPS 转发；多 Tunnel；Tunnel 启停（`client tunnel list/start/stop`）。
2. **连接可靠性**：自动重连（指数退避 + Jitter + 错误分类）、心跳、状态检测。
3. **统计与日志**：实时与累计流量统计、连接数统计、结构化日志（统一脱敏）。
4. **配置**：TOML 配置 + CLI 参数覆盖（优先级 `CLI > ENV > Config > Default`），`check-config` 预检。
5. **客户端管理**：客户端唯一 ID、名称、备注；优雅关闭。
6. **Server 端限制**：端口范围、Tunnel 数、并发连接数、带宽、UDP Session 数、目标 IP/CIDR/端口白名单（Server 端强制）。
7. **身份与 PKI**：TLS 1.3 + mTLS（唯一认证方式）；CSR Enrollment；证书续期 / 吊销 / CA 轮换预案。
8. **私钥安全存储**：跨平台系统安全存储（wincred / Keychain / Secret Service）+ 0600 文件降级。
9. **三平台**：Windows / Linux / macOS（amd64 + arm64）。
10. **桌面客户端**：Client Desktop（Wails v2），coreapi 窄门面，前端永不接触私钥与 TLS（UI 以 Stitch 压缩包为唯一依据，Phase 12/13）。

## B. OUT（V1 明确不做，但架构预留扩展点）

1. QUIC、连接多路复用（Mux）、P2P、Web 管理面板、Server Cluster、插件系统。
2. TLS 终止式 HTTPS（L7 解密）、泛域名证书管理、ACME。
3. 遥测 / Analytics / 任何非必要第三方外连。
4. 服务端 Web UI、用户体系（多管理员 RBAC）。

> 预留方式（只留扩展点，不提前实现）：协议消息带 `version` 与可扩展字段；Tunnel 有 `type` 枚举；transport 抽象 `Dialer/Listener` 接口（未来 QUIC 实现同接口即可）。

## C. 已冻结的关键技术取舍（引自 01-architecture.md §3，不再讨论）

| # | 决策点 | 冻结选择 |
|---|---|---|
| C1 | 语言/工具链 | Go 1.22+，单一 go.mod |
| C2 | 控制面编码 | 长度前缀 + JSON（stdlib `encoding/json`），≤64KiB；**禁止自研二进制协议** |
| C3 | TLS | `crypto/tls`，MinVersion=TLS1.3，ClientAuth=RequireAndVerifyClientCert |
| C4 | 密钥算法 | Ed25519（CA、Server、Client 证书统一）；预留 `key_algo` 字段 |
| C5 | CA 结构 | 每 Server 实例一个自签 Root CA（10 年），直接签发客户端证书；轮换用"新旧并行信任 + 全员续期" |
| C6 | 私钥存储 | `99designs/keyring`（wincred/Keychain/Secret Service）+ 自研 0600 文件降级 |
| C7 | CLI | `spf13/cobra` |
| C8 | 配置 | `pelletier/go-toml/v2`，严格模式（DisallowUnknownFields） |
| C9 | 日志 | stdlib `log/slog` + 自研 Redaction Handler |
| C10 | 限流 | `golang.org/x/time/rate`（token bucket） |
| C11 | Desktop | Wails v2（稳定版） |
| C12 | 依赖纪律 | 外部依赖 ≤ C6/C7/C8/C10/C11 + Wails 间接依赖；新增依赖必须评审并说明理由 |

## D. 安全基线（全项目恒成立，见 01-architecture.md §6）

- 无默认密码 / 测试证书 / 测试 Token / Debug 后门。
- 私钥不出设备；Token 只显一次、服务端只存 SHA-256 哈希。
- 日志统一 redaction；无遥测；除业务连接与用户配置目标外零外连。
- 所有外部输入严格校验；配置永不执行 Shell；非测试代码禁止 `os/exec`。
- Server 非 root 运行；panic 不得导致进程退出。

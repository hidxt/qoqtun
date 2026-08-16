# Changelog

本项目的所有显著变更都将记录在此文件中。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added（Phase 3 — Enrollment、Token、签发与吊销）

- `internal/auth`：Enrollment Token（32B crypto/rand → `qen_`+base62 展示、8B token_id）；tokens.json（只存 SHA-256 哈希、0600 原子写、惰性过期清理）；`Consume` 写锁内原子核销（防双花）；`Revoke`；跨进程文件变更重载（独立 `enroll serve` 感知新 token）。
- `internal/enroll`：长度前缀+JSON 帧（4B 头 + 64KiB 上限）；EnrollServer（TLS 1.3，enroll 免客户端证书 / renew 强制 mTLS，吊销握手回调即时生效）；每 IP 限速 5/min + 失败指数封禁；EnrollClient（服务器证书指纹 TOFU/钉扎为信任锚、回验链+CN+公钥）；错误码映射（ERR_TOKEN_INVALID/EXPIRED/USED、ERR_NAME_CONFLICT、ERR_RATE_LIMITED 等）。
- CLI：`server client create-token/list/revoke-token`、`server cert list/revoke`、`server enroll serve`、`client enroll`（token 优先 stdin）、`client cert status`、`client cert renew`（mTLS）。
- `server ca init` 新增 `--san`（control_addr 为通配地址时必填，剔除 0.0.0.0/:: 并告警）。
- 测试：token 一次性/过期/吊销/并发单赢/惰性清理/文件重载；enroll 坏 CSR/CN 冲突/限速；**enroll→mTLS renew→revoke→拒绝全链路（真实 TLS）**；续期新序列号。
- 文档：[docs/operations/enrollment.md](docs/operations/enrollment.md)；01-architecture.md 目录树与依赖补 `internal/enroll`。
- 依赖：新增 `golang.org/x/time`（限速，白名单内）。

### Added（Phase 2 — PKI 与跨平台私钥安全存储）

- `internal/pki`（纯标准库）：Ed25519 自签 Root CA（128-bit 随机序列号、CertSign|CRLSign）；PKCS#10 CSR（CN=`cl_`+base32 小写 client_id、OU=name）；客户端证书签发（CSR POP 校验、仅 Ed25519、CN 格式、随机序列号、ClientAuth EKU、NotBefore-5min、NotAfter 截断到 CA 期）；服务器证书（ServerAuth + SAN IP/DNS）；解析/校验/序列化/指纹（SHA-256 冒号格式）/到期判断；吊销列表与客户端登记（原子写 + 线程安全）。
- `internal/platform/keystore`：`Store` 接口（Get/Set/Delete/List）+ 三实现——keyring（wincred/Keychain/SecretService）、file（0700 目录/0600 文件/属主校验/拒符号链接/Unix O_NOFOLLOW/原子写/并发安全）、mem（测试）；keyring 失败自动降级 file（warn 不含敏感信息）；`--keystore-backend auto|keyring|file` 偏好；Windows 仅当前用户 ACL（属主 SID 校验 + DACL）。
- CLI：`server ca init`（幂等，`--force` 覆盖并警告）、`client cert init`（私钥入 keystore、client_id、CSR 输出，`--name/--note/--csr-out/--secrets-dir/--keystore-backend`）。
- 测试：签发-解析-校验往返、篡改/错算法（RSA）/非法 CN 的 CSR 拒绝、50 张序列号唯一、NotAfter 截断、吊销持久化（0600）、keystore 契约（mem/file/keyring-file）、权限断言、符号链接攻击（Unix）、属主拒绝、keyring→file 降级。
- 文档：[docs/operations/pki.md](docs/operations/pki.md) 操作手册初稿。
- 依赖：新增 `99designs/keyring`、`golang.org/x/sys`；jose2go 提升至 v1.7.0（修复 GO-2023-2409/GO-2025-4123）。
- CI：Go 版本升至 1.26（覆盖标准库 GO-2026-5972，asn1 递归 DoS）。

### Added（Phase 1 — 项目骨架、Config、Logging、CLI 基础）

- Monorepo 骨架：`go.mod`（Go 1.22，模块 `github.com/hidxt/qoqtun`）、`cmd/server`、`cmd/client`（cobra 薄壳）、`internal/config`、`internal/logging`、`internal/platform`（占位）。
- `internal/config`：server/client 全量结构体与校验（端口范围 / CIDR / RFC1123 主机名 / tunnel 名正则 / allowed_ports 与监听端口不重叠 / local_ip 禁通配组播链路本地 / 绝对路径禁 `..` 逃逸）；严格 TOML 解析（未知字段报错）；合并器 `Resolve`（CLI flag > ENV `QOQTUN_*` > 配置文件 > 默认值，数组字段不支持 ENV）；部分文件按字段叠加默认值，显式零值（如 `enroll_addr = ""`）保留。
- `internal/logging`：slog 封装（level/format/file，0640 日志文件）；Redaction Handler（key 黑名单 + 长 hex/base64 值模式）；`Secret` 类型（`String()` → `***`）。
- CLI：`server run`（占位）、`server check-config`、`client run`（占位）、`client check-config`、`client cert/enroll/tunnel`（占位）；check-config 解析 + 校验 + 脱敏打印生效配置，退出码 0/1。
- CI 基础：[scripts/check.sh](scripts/check.sh)（fmt/vet/build/三平台交叉编译/test/race 一键）；[.github/workflows/ci.yml](.github/workflows/ci.yml)（三 OS 构建 + 测试，race 在 ubuntu/macos）。
- 测试：config 正反例表驱动（覆盖 84.1%）、redaction 单测（81.8%）、check-config 集成（示例配置通过 + 10+ 畸形配置报错）、部分文件合并与显式零值回归测试。
- 文档一致性修复：05-config-schema.md 与 examples 中 `[identity]`/`[tls]` 空表头改为注释（严格模式拒绝未知字段，空表头不可出现）。

### Added（Phase 0 — 需求冻结、架构与文档落地）

- 仓库文档骨架：`README.md`（定位 / 特性 / 架构 / License 声明）、`SECURITY.md`（威胁模型摘要、安全设计要点、漏洞披露流程占位）、`CHANGELOG.md`。
- `.gitignore`：覆盖私钥 / 证书 / CA / 状态 / Token / `.env` / 日志 / 构建产物 / IDE 杂物。
- V1 范围冻结清单：[docs/plan/v1-scope-freeze.md](docs/plan/v1-scope-freeze.md)；V1 外想法收纳处 [docs/plan/future.md](docs/plan/future.md)。
- 示例配置：[examples/server.example.toml](examples/server.example.toml)、[examples/client.example.toml](examples/client.example.toml)（敏感字段均为占位符）。
- `docs/operations/` 目录骨架（运营文档占位）。

# Changelog

本项目的所有显著变更都将记录在此文件中。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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

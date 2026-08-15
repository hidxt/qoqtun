# Changelog

本项目的所有显著变更都将记录在此文件中。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added（Phase 0 — 需求冻结、架构与文档落地）

- 仓库文档骨架：`README.md`（定位 / 特性 / 架构 / License 声明）、`SECURITY.md`（威胁模型摘要、安全设计要点、漏洞披露流程占位）、`CHANGELOG.md`。
- `.gitignore`：覆盖私钥 / 证书 / CA / 状态 / Token / `.env` / 日志 / 构建产物 / IDE 杂物。
- V1 范围冻结清单：[docs/plan/v1-scope-freeze.md](docs/plan/v1-scope-freeze.md)；V1 外想法收纳处 [docs/plan/future.md](docs/plan/future.md)。
- 示例配置：[examples/server.example.toml](examples/server.example.toml)、[examples/client.example.toml](examples/client.example.toml)（敏感字段均为占位符）。
- `docs/operations/` 目录骨架（运营文档占位）。

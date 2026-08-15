# qoqtun Phase 0 — 需求冻结、架构与文档落地（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的开发工程师。qoqtun 是高安全性开源内网穿透软件（架构对标 frp，**禁止复制 frp 源码**），三程序：Server CLI、Client CLI、Client Desktop（Wails v2），共用同一套 internal/ Go Core。技术优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 开工前必读
1. 完整阅读仓库 docs/plan/ 下全部设计文档（01-architecture.md、02-threat-model.md、03-pki-enrollment.md、04-protocol-v1.md、05-config-schema.md、06-roadmap.md）。设计文档是唯一事实来源。
2. 执行 `git status`、`git branch --show-current`、`git remote -v`，确认工作区状态。禁止破坏 Git 历史、禁止 force push。

## 全程红线
- 本阶段**不写任何 Go 生产代码**。
- 禁止遥测/非必要外连相关内容进入设计。
- 任何敏感信息（示例私钥、真实 Token）不得入库，示例一律用占位符。

## 本阶段任务（IN SCOPE）
1. 建立仓库文档骨架并落盘设计文档：
   - `README.md`：项目定位、特性清单（对照 01-architecture.md §2 V1 范围）、架构图（ASCII）、构建与快速开始占位章节、徽章占位、License 声明。
   - `SECURITY.md`：威胁模型摘要（引用 02-threat-model.md）、支持的版本、漏洞披露流程（SECURITY 联系人占位 + PGP 占位）、安全设计要点（TLS1.3+mTLS、私钥不出设备、无遥测）。
   - `CHANGELOG.md`：Keep a Changelog 格式，起始 `## [Unreleased]`。
   - 核对 `LICENSE` 存在且在 README 引用。
   - `docs/`：将 docs/plan/ 六份设计文档校对入库（修正交叉引用），另建 `docs/operations/` 空骨架占位。
   - `examples/`：`server.example.toml`、`client.example.toml`（按 05-config-schema.md 填全字段+注释，敏感字段用占位符）。
2. 编写 `.gitignore`，必须覆盖：`*.key`、`*.pem`、`*.crt`（注意 examples 里的占位文件如需保留则单独例外）、`ca/`、`state/`、`tokens*.json`、`clients.json`、`revoked.json`、`.env`、`*.log`、`logs/`、`dist/`、`build/`、`bin/`、`coverage.out`、OS 杂物（`.DS_Store`、`Thumbs.db`）、IDE 目录。
3. 输出 V1 范围冻结清单：从 01-architecture.md §2 提取为 `docs/plan/v1-scope-freeze.md`，逐条编号，后续任何范围变更必须改此文件并写 CHANGELOG。

## OUT OF SCOPE
- 任何 Go 源码、go.mod、CI 工作流（Phase 1 做）。
- Web 管理面板、QUIC、Mux、P2P 的任何实现性描述。

## 测试与验证
- 文档内所有相对链接可点通；术语统一（Tunnel/Control Connection/Data Connection/Enrollment 大小写一致）。
- 用 `git check-ignore` 验证 .gitignore 对 `ca/ca.key`、`state/tokens.json`、`.env` 生效。
- 本阶段无可执行测试，验收 = 文档评审。

## Git 要求
- Conventional Commit（如 `docs: freeze v1 scope and bootstrap project documentation`）。
- 完成后 Review 完整 `git diff`；存在 GitHub origin 则 push 当前分支，无 origin 只 commit，不得猜仓库地址。

## Definition of Done
- 上述文件全部入库；V1 范围冻结清单完成；.gitignore 验证通过；提交完成。
- 下一阶段（Phase 1）能直接基于本仓库开工。

## 风险与注意
- 范围蔓延是本项目最大风险：发现任何"V1 之外"的想法，记入 `docs/plan/future.md` 而非范围清单。

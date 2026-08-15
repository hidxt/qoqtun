# qoqtun Phase 17 — 文档、打包与 Release Candidate（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段产出 RC。

## 开工前必读
1. `docs/plan/06-roadmap.md` Phase 17；`docs/security/audit-report.md`（确认无未关闭 P0/P1）。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- 发布脚本/CI 中禁止出现任何真实密钥/Token；checksums、SBOM 必须生成。
- 版本号注入走 `-X main.version=` ldflags，不写死源码。
- 依赖白名单新增：goreleaser（构建工具，非运行时依赖）。网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. 文档定稿：
   - README：定位、特性、架构图、三端快速开始（15 分钟跑通 TCP 穿透为目标）、构建、贡献指南、安全声明链接。
   - docs/：cli-reference、configuration、operations（install/pki/enrollment/policy）、protocol、security 全部校对一致。
   - examples/：三平台可复制的完整示例。
   - CHANGELOG：v1.0.0-rc.1 条目完整。
2. 打包（goreleaser 或等效脚本）：
   - server/client：windows/linux/darwin × amd64/arm64，静态编译（CGO_ENABLED=0）；
   - desktop：三平台 Wails 产物；
   - 产物：tar.gz/zip + SHA256 checksums 文件；SBOM（`go version -m` 输出或 cyclonedx-gomod）随包归档；
   - 归档内不含任何 state/密钥/示例私钥。
3. RC 演练：
   - 干净容器/虚拟机：按 README 从零跑通（ca init→token→enroll→TCP/UDP/HTTP 穿透→desktop 启动），记录并修复任何卡点；
   - 校验和验证演示（下载→sha256sum -c）。
4. 打 tag：`v1.0.0-rc.1`（annotated tag，信息含变更摘要）；存在 origin 且 CI 全绿 → push 分支与 tag。

## OUT OF SCOPE
- 代码签名/公证（cosign/Apple notarization 列为后续任务写入 docs）；包管理器发布（homebrew/scoop 后续）。

## 测试与验证命令
全量：`gofmt -l .`、`go vet ./...`、`go test ./...`、`go test -race ./...`、`govulncheck ./...`；goreleaser release --snapshot 本地验证；最终 secret scan（含打包产物与脚本）。

## Git 与交付
- Conventional Commits + annotated tag；push 分支与 tag（仅当 origin 存在且全绿）。

## Definition of Done
- RC 产物三平台齐备、校验和可验证、干净机器演练通过、文档与实现一致、tag 已打。
- 发布说明草稿（GitHub Release body）写入 docs/release/v1.0.0-rc.1.md。

## 风险与注意
- 演练必须真实"干净环境"——开发机上跑通不算数。
- 任何演练中发现的体验问题：小的立即修，大的记入 RC 后任务清单，不阻塞但需记录。

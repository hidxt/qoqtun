# qoqtun Phase 1 — 项目骨架、Config、Logging、CLI 基础（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（架构对标 frp，**禁止复制 frp 源码**），三程序：Server CLI、Client CLI、Client Desktop（Wails v2），共用同一套 internal/ Go Core。技术优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 开工前必读
1. 完整阅读 `docs/plan/01-architecture.md`（§3 取舍表、§4 目录与依赖规则）、`docs/plan/05-config-schema.md`（本阶段核心）、`docs/plan/02-threat-model.md` T11/T12/T14。
2. `git status`、`git branch --show-current`、`git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- 依赖白名单：`spf13/cobra`、`pelletier/go-toml/v2`（本阶段）；其余一律不加。
- 非测试代码禁止 `os/exec`；配置解析严格模式（未知字段报错）；任何配置项不得触发 Shell。
- 日志必须经 redaction；禁止任何遥测/外连代码。
- 网络失败需代理时只对单条命令临时使用 `HTTP_PROXY=http://127.0.0.1:10808 HTTPS_PROXY=http://127.0.0.1:10808 ALL_PROXY=socks5://127.0.0.1:10808`，禁止改系统/Git 全局代理。

## 本阶段任务（IN SCOPE）
1. 初始化 go.mod（Go 1.22+），按 01-architecture.md §4 建立目录骨架（含空包占位 doc.go，避免过度创建文件——只建本阶段用到的：cmd/server、cmd/client、internal/config、internal/logging、internal/platform）。
2. `internal/config`：
   - 按 05-config-schema.md 定义 server/client 结构体与全部校验规则（端口范围、CIDR、主机名 RFC1123、tunnel 名 `^[a-zA-Z0-9_-]{1,64}$`、allowed_ports 与监听端口不重叠、local_ip 禁通配/组播/链路本地等，逐条落实）。
   - 合并器 `Resolve`：CLI flag > ENV（`QOQTUN_*`，数组字段不支持 ENV）> 配置文件 > 默认值，实现一处。
   - 路径校验：绝对路径要求、`filepath.Clean`、禁 `..` 逃逸。
3. `internal/logging`：slog 封装（level/format/file）、Redaction Handler（key 名黑名单：key/token/secret/password/cert_pem 等 + 值模式：长 hex/base64 串）、`Secret` 字符串类型（`String()` 输出 `***`）。
4. CLI 骨架（cobra）：`server`（run 占位、check-config）、`client`（run 占位、check-config、cert/enroll/tunnel 子命令占位，输出"not implemented yet"）。`check-config`：解析+校验+打印生效配置（敏感值脱敏），退出码 0/1。
5. CI 基础：Makefile 或 scripts/check.sh（fmt/vet/build/test/race 一键）；GitHub Actions 工作流（若存在 origin，三 OS 构建 + test）。
6. 测试：config 正反例表驱动测试（覆盖率 ≥80%）、redaction 单测（构造含密钥结构的日志断言无泄露）、check-config 集成测试。

## OUT OF SCOPE
- 任何网络/TLS/PKI 代码；keystore；tunnel；desktop。

## 测试与验证命令
`gofmt -l .`（无输出）、`go vet ./...`、`go build ./...`、`GOOS=windows go build ./...`、`GOOS=darwin go build ./...`、`go test ./...`、`go test -race ./...`。

## Git 与交付
- Review 完整 diff；secret scan（grep -rEi 'BEGIN.*PRIVATE KEY|token|password' --include='*.go' --include='*.toml' 确认无真实秘密）。
- Conventional Commit（如 `feat(config): bootstrap monorepo with config, logging and cli skeleton`）；有 origin 且测试全绿 → push 当前分支；无 origin 只 commit。

## Definition of Done
- 三平台交叉编译通过；测试全绿；`server check-config` / `client check-config` 对 examples 中示例配置通过、对 10+ 种畸形配置正确报错；README 快速开始更新为真实命令。
- 更新 CHANGELOG.md。

## 风险与注意
- 校验规则遗漏是主要风险：逐条对照 05-config-schema.md 建测试表，漏一条补一条。
- 不要为未来的 QUIC/Mux 提前建接口。

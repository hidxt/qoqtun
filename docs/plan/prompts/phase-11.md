# qoqtun Phase 11 — Client CLI 完整化（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段把 Client CLI 打磨到对标 frpc 的完整体验。

## 开工前必读
1. `docs/plan/05-config-schema.md`（CLI 覆盖规则）、`docs/plan/01-architecture.md` §2（CLI 能力清单）、`docs/plan/06-roadmap.md` Phase 11。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- CLI 一切输出脱敏；状态文件 0600；token 输入走 stdin/交互（文档警告 flag 方式会进 shell history）。
- V1 配置变更=重启生效，必须在帮助文本与文档中明示，不做热加载。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. 完整子命令树（全部真实可用）：
   - `client run`：常驻；SIGINT/SIGTERM 优雅退出（码 0），二次信号强退（码 130）；退出原因结构化日志。
   - `client cert init / enroll / renew / status`（status 显示 client_id、name、证书到期、keystore 后端、Server 地址——无敏感内容）。
   - `client tunnel list`（名称/类型/本地目标/远端端口或 host/状态/实时速率/累计流量）、`client tunnel start <name>`、`client tunnel stop <name>`、`client tunnel status <name>`。
   - `client check-config`（已有，复核覆盖新字段）。
   - 全局 flag：`--config`、`--server-addr`、`--log-level`、`--log-file` 等覆盖项按 05 文档 §3 全量接线。
2. 运行形态支持：
   - `scripts/` 或 `docs/operations/` 提供 systemd unit（非 root、ProtectSystem、CapabilityBoundingSet 示例）、launchd plist、Windows schtasks/服务说明（sc.exe 示例）。
   - `client run` 支持 `--daemon` 说明：V1 不自实现守护化，依赖 init 系统（文档说明）。
3. e2e 自动化：脚本（bash + pwsh 双版本或 Go e2e 测试）驱动完整生命周期：ca init→cert init→create-token→enroll→写 client.toml→run→起本地 echo→公网侧（127.0.0.1 模拟）验证 TCP/UDP/HTTP 转发→tunnel stop/start→优雅退出→断言日志无敏感串。
4. 补全与帮助：cobra shell completion 生成命令；每个命令的 Examples 完整。

## OUT OF SCOPE
- Desktop 任何内容（Phase 12/13）；Windows 服务自安装器（V2）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、e2e 脚本在 Linux 与 Windows 各跑通一次、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(cli): complete client command set and e2e lifecycle tests`）；有 origin 且全绿 → push。

## Definition of Done
- 三平台手工冒烟清单（init→enroll→run→转发→关停）全部通过；e2e 自动化入库且 CI 可跑（Linux 至少）；docs/cli-reference.md 完成；README 快速开始端到端可复制执行；CHANGELOG 更新。

## 风险与注意
- 平台信号/路径差异统一收敛在 internal/platform；cmd 里不出现 build tag 分支。
- e2e 稳定性：端口分配动态化，防 CI 端口冲突。

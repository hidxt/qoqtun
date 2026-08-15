# qoqtun Phase 9 — ACL、限速、连接限额、资源保护（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段把威胁模型 T6/T7/T9 的缓解全部收口为 Server 端强制策略。

## 开工前必读
1. `docs/plan/02-threat-model.md` T6/T7/T9/T10/T15（逐条对照实现）、`docs/plan/05-config-schema.md` [policy] 全部字段、`docs/plan/04-protocol-v1.md` §5 错误码。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- **Server 是唯一策略执行点**；Client 侧校验只是体验优化，Server 必须独立强制。
- fail-closed：任何限额/ACL 判断出错=拒绝；不存在"无限"默认值之外的隐式无限。
- 限额触发必须有审计日志（脱敏）+ 正确 error code。
- 依赖白名单新增：`golang.org/x/time`（rate）。其余不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/security`：
   - 连接限额：per-client / per-tunnel 并发信号量（获取失败→立即拒绝，不排队）；半开连接（未完成 mTLS/首帧）单独限额+10s 总超时。
   - 带宽限速：token bucket per-client 与 per-tunnel 双层（包装数据连接 Read/Write，统计一致）。
   - 注册频率限制：register/unregister per-client 速率；控制消息全局速率（每连接 msg/s 上限，超限 ERR_RATE_LIMITED 并断连）。
   - 每公网 IP：连接速率、并发数上限（Public Listener 前置拦截器）。
   - UDP：复核 session/包速率/包大小限额与 Phase 7 实现一致并统一进 security 包。
   - allowed_targets 复核：Server 侧在 register_tunnel 时校验声明的 local 目标是否在白名单（Client 上报），并全量审计记录；Client 侧 dial 前校验保持不变（双保险）。
2. 资源保护：
   - 启动检测 RLIMIT_NOFILE，低于推荐值（按 max_conns 估算）warn 或拒绝（配置 `server --allow-low-fdlimit` 显式放行）。
   - pprof 端点：默认关闭，开启时只绑 127.0.0.1 且需显式 flag。
   - root 检测：非容器环境以 root 运行且未 `--allow-root` → 拒绝启动并提示 capability/setcap 方案。
3. 测试（每项对应威胁模型条目）：
   - 越界端口/超 Tunnel 数/超并发/超带宽/超注册频率/超 UDP session → 正确 error code + 审计日志断言。
   - 洪泛：公网侧高速建连/高频控制消息下，已建立隧道转发仍可用（可用性测试）。
   - 限速精度：持续 10s 流量，实际速率在限额 ±10% 内。
   - root/fdlimit 检测行为测试（可注入的检测函数）。

## OUT OF SCOPE
- 分布式/集群限流；动态策略热更（policy_update 消息已定义，V1 重连生效）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(security): server-enforced ACL, rate limits and resource guards`）；有 origin 且全绿 → push。

## Definition of Done
- 威胁模型 T6/T7/T9/T10 每条都有对应自动化测试且在 -race 下全绿；docs/operations/policy.md 策略配置手册入库；CHANGELOG 更新。

## 风险与注意
- 限速粒度太粗会影响正常用户：测试包含"正常流量不受限"对照组。
- 信号量释放路径穷尽审查（err/timeout/panic 分支），泄漏=DoS 漏洞。

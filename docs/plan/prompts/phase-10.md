# qoqtun Phase 10 — 统计与日志完善（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 开工前必读
1. `docs/plan/01-architecture.md` §2（统计范围）、§4 metrics 定位；`docs/plan/02-threat-model.md` T14（日志泄密）。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- 统计只含元数据（字节数/连接数/时间戳），**绝不包含转发载荷内容**；日志默认不记录载荷。
- 所有敏感字段走 redaction（Phase 1 机制），本阶段做全链路回归。
- 禁止任何遥测上报；统计只供本地 CLI/Desktop 查询。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/metrics`：
   - 原子计数器集：per-tunnel 与 per-client 的 rx_bytes/tx_bytes、active_conns、total_conns、UDP rx/tx packets；全局汇总。
   - 实时速率：滑动窗口（1s 粒度，60s 窗口）估算当前 bps。
   - 快照 API：`Snapshot() MetricsSnapshot`（值拷贝，无锁读路径用 atomic，快照组装可短锁）。
   - 全部转发路径接线复核（TCP/UDP/HTTP、回放前缀字节不可漏计）。
2. 状态查询命令：`server status`（会话/隧道/流量概览，读 Server 本地状态——V1 为本机查询，不做远程管理通道）、`client status`（连接状态、tunnel 列表、实时/累计流量）。
3. 日志完善：
   - 关键事件审计流（enroll、握手成功/失败、注册/注销、限额触发、吊销）统一字段（event/client_id/tunnel/remote，脱敏）。
   - 防日志洪泛：同类错误采样（每 N 条/每分钟）。
   - redaction 回归测试：构造包含私钥 PEM/Token/证书内容的日志调用，断言输出被脱敏；对全部 error 路径做一次人工审查。
4. 测试：
   - 统计准确性集成测试：转发已知字节数（如 10MiB），断言 rx/tx 与实测**误差为 0**；UDP 包数同理。
   - 并发计数 -race 测试；快照一致性（无撕裂）测试。
   - 日志采样行为测试；审计事件存在性测试。

## OUT OF SCOPE
- 统计持久化/历史曲线/Prometheus 导出（V2 评估）；Web 面板。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan（重点：日志相关代码）；Conventional Commit（如 `feat(metrics): traffic/connection statistics and audit logging`）；有 origin 且全绿 → push。

## Definition of Done
- 统计准确性测试通过；`server status`/`client status` 输出完整；redaction 回归全绿；docs/metrics.md 字段字典入库；CHANGELOG 更新。

## 风险与注意
- 高并发计数热点：若基准显示争用，用分片计数（striped counters）而非互斥锁——改动需基准数据支撑。

# qoqtun Phase 6 — 重连、心跳完善、Graceful Shutdown、Connection Manager（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段把 clientcore 从"断线即退"升级为生产级连接管理。

## 开工前必读
1. `docs/plan/04-protocol-v1.md` §4（心跳与断线检测、错误分类、退避参数）、§2 shutdown 消息；`docs/plan/02-threat-model.md` T9/T10。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- **认证失败/证书吊销/过期 = 永久错误 → 停止重连并明确报错退出（非零退出码），严禁快速无限重试**；网络类错误 = 临时错误 → 退避重连。
- 退避：初始 1s ×2，上限 60s，±20% jitter；全部可配置（05-config-schema.md [reconnect]）。
- 优雅关闭不得丢失统计；Server 踢除会话必须同步释放端口与限额占位。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/clientcore` Connection Manager：
   - 状态机：Disconnected→Connecting→Online→Draining→Stopped（画图入 docs/conn-manager-state.md）。
   - 错误分类器：从 TLS 错误/协议 error code 映射永久/临时。
   - 重连循环：退避+jitter；重连成功后自动重注册全部 enabled tunnels；连续临时失败不退出但日志降频（采样）。
   - 心跳完善：miss_threshold 判定、读写 goroutine 协调、断线时主动关闭数据连接。
2. Server 侧：
   - 会话超时踢除（2×interval+timeout 无消息）；重复 client_id 上线策略：踢旧会话（新会话优先）并记审计日志。
   - `shutdown` 消息协商：Client 发起→Server 摘除 Public Listeners→drain 进行中连接（默认 30s 上限）→强关残余→双方释放。
   - Server 自身 SIGINT/SIGTERM：向所有 client 发 `shutdown`、停止 Accept、drain、落统计、退出码规范。
3. Client 侧信号处理（SIGINT/SIGTERM → 优雅退出码 0；第二次信号强退）。
4. 测试：
   - kill server 进程→client 按退避重连（注入可控时钟/缩短退避断言节奏）；恢复后 tunnels 自动重注册、转发可用。
   - 吊销证书→client 收到永久错误→停止重连→非零退出。
   - 拔网线模拟（监听强制断开）→miss_threshold 触发→重连。
   - shutdown drain：进行中的慢连接在窗口内完成；超时强关。
   - 30min 浸泡（可用缩短参数模拟）：每 30s 断一次，断言无 goroutine/FD 泄漏、日志量受控。

## OUT OF SCOPE
- UDP/HTTP、限额收口（Phase 7/8/9）；配置热加载（V1 重启生效）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(clientcore): connection manager with backoff reconnect and graceful shutdown`）；有 origin 且全绿 → push。

## Definition of Done
- 三类断线（网络/进程/吊销）行为全部符合规范且有自动化测试；优雅关闭全链路 drain 正确；浸泡测试无泄漏；docs/conn-manager-state.md 入库；CHANGELOG 更新。

## 风险与注意
- 重连风暴：多 client 同时掉线恢复时 jitter 必须真实生效（测试断言时间分布非确定值）。
- 重注册幂等：Server 侧端口仲裁要保证同一 client 重连后能拿回同端口（会话期内预留）。

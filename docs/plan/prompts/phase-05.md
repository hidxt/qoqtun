# qoqtun Phase 5 — TCP Tunnel MVP（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。Phase 4 已完成控制面，本阶段打通 TCP 数据面。

## 开工前必读
1. `docs/plan/04-protocol-v1.md` §3（TCP 完整流程，逐条实现）、§1（三种连接关系）、§5（错误码）；`docs/plan/02-threat-model.md` T3/T7/T8/T10。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- conn_id = CSPRNG 128-bit、一次性、10s 未认领即废；数据连接同样 mTLS 且证书身份==控制连接身份。
- Client 回源 dial 前必须校验 local_ip:local_port 在服务端下发的 allowed_targets 白名单内；主机名解析-校验-dial 使用同一 IP 结果（防 DNS rebinding），禁二次解析。
- 所有连接有 deadline；half-close 状态机显式实现；任何路径不得泄漏 goroutine/FD。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/tunnel`（tcp 实现）+ control/clientcore 接线：
   - `register_tunnel`/`unregister_tunnel` 处理：Server 端端口范围校验、占用仲裁（端口独占）、Tunnel 数占位校验（正式限额 Phase 9 收口，本阶段按 policy 字段执行基础检查）、起 Public Listener；Client 端本地登记。
   - 公网连接到达→生成 conn_id→占住连接（总超时）→控制面 `open_connection`。
   - Client 收到后：tunnel 存在性校验→ACL 校验→dial 本地（10s 超时）→新建 mTLS Data Connection→首帧 `open_data{conn_id,tunnel_id}`。
   - Server 认领（map[conn_id]待配对，10s 超时清理）→ splice：`io.CopyBuffer` 双向 32KiB。
   - Half-Close：一侧 EOF→对端 CloseWrite→继续读→对向 EOF 或空闲超时（默认 5min）→双关→`close_connection`（含 rx/tx 字节数，落账钩子）。
   - 异常：对端 RST、本地拨号失败（回 `close_connection{reason}`，Server 关公网连接）、控制面断开→摘除该 client 所有 Public Listener 并按优雅路径关闭进行中连接。
2. `client tunnel` 子命令先实现内部 API（list 由本地状态+server 应答组成），CLI 展示留 Phase 11。
3. 测试（全部本机回环可跑）：
   - echo 服务端到端：小消息、64MiB 大流量（校验字节完整）、并发 100 连接。
   - 半关闭：客户端 CloseWrite 后服务端仍能读完再关。
   - 对端 RST/本地服务不存在/本地服务慢（注入延迟）路径。
   - 冒领 conn_id（伪造/重放/超时未认领）拒绝。
   - 回源 ACL：白名单外目标拒绝。
   - 每测试后断言 goroutine 数回落、Listener 释放。

## OUT OF SCOPE
- UDP、HTTP/HTTPS、带宽限速与连接限额完整收口（Phase 7/8/9）、重连（Phase 6）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`（重点：并发转发测试必须在 -race 下跑）、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(tunnel): TCP tunnel MVP end-to-end`）；有 origin 且全绿 → push。

## Definition of Done
- 手工验证：server+client+ssh/redis 等真实服务穿透成功；上述自动化测试全绿（-race）；README 快速开始的 TCP 示例真实可跑。
- CHANGELOG 更新。

## 风险与注意
- goroutine 泄漏是 TCP 转发最常见 bug：统一"每转发对 2 goroutine + owner"模型，关闭路径集中在一个函数，测试断言兜底。
- 背压不要做应用层窗口，信任 TCP 流控（V1）。

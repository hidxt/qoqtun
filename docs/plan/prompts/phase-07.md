# qoqtun Phase 7 — UDP Tunnel（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 开工前必读
1. `docs/plan/04-protocol-v1.md` §6（UDP 方案：session 映射、TCP 通道封装帧、超时、上限、防滥用——逐条实现）；`docs/plan/02-threat-model.md` T6/T9/T10。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- V1 UDP 封装在 mTLS TCP 数据通道内（`[4B len][session_id 16B][payload]`），不原生 UDP-over-UDP；max_packet 默认 1500（硬上限 65507），超限丢弃并计数。
- session 上限（默认 256/tunnel）与每公网 IP 包速率限制由 **Server 端强制**；映射满→LRU 淘汰最久未活跃并记审计。
- 空闲 session 60s（policy 可调）必须回收；所有 goroutine 有 owner。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/tunnel`（udp 实现）：
   - UDP Public Listener（`net.ListenUDP`）按隧道注册创建。
   - Session 映射表：key=(tunnel_id, 对端 addr)→session{session_id, 本地 UDP conn, last_active}；每 session 一条到 local 的 UDP 套接字（dial 前过 allowed_targets 白名单）。
   - UDP 数据通道：每 client 每 tunnel 一条 mTLS TCP 通道承载全部 session 帧；通道断开→该 tunnel 全部 session 清理并自动重建通道（走 Phase 6 的重连语义）。
   - 清扫循环：空闲超时回收；容量 LRU；速率限制器（每公网 IP pps）。
   - 回包路径：本地 UDP 读到的响应按 session_id 帧发回 Server→还原到原始对端 addr。
2. 统计钩子：rx/tx 包数与字节数接入 metrics 占位（Phase 10 收口）。
3. 测试：
   - 端到端：本机 UDP echo + 类 DNS 请求/响应（小包、>512B 包、多对端并发）。
   - session 空闲超时回收断言；session 上限 LRU 淘汰断言；超大包丢弃；速率限制触发。
   - 数据通道断开重连后转发恢复；控制面断开→session 全清。
   - 洪泛浸泡（本机高速发包 60s）：CPU/内存/goroutine 平稳，无泄漏。

## OUT OF SCOPE
- QUIC/原生 UDP 传输、HTTP/HTTPS、带宽限速完整收口（Phase 8/9）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`（UDP 并发测试必须 -race）、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(tunnel): UDP tunnel with session mapping and abuse guards`）；有 origin 且全绿 → push。

## Definition of Done
- DNS/echo 端到端手工验证通过；超时/上限/速率/洪泛测试全绿（-race）；docs/udp-semantics.md（伪连接、超时、上限行为）入库；CHANGELOG 更新。

## 风险与注意
- 映射表泄漏：容量+TTL 双保险，测试断言表规模回落。
- 包乱序/重复属 UDP 语义，不做可靠性增强——文档写明。

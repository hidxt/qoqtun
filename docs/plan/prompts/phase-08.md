# qoqtun Phase 8 — HTTP/HTTPS Tunnel（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 开工前必读
1. `docs/plan/04-protocol-v1.md` §7（HTTP/HTTPS 决策：HTTP=轻量 L7 Host 路由+流式透传，HTTPS=纯 L4 Passthrough——严格按此实现，不要加戏）；`docs/plan/02-threat-model.md` T9/T10。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- Host 嗅探只读首个请求的必要头部（≤8KiB，5s 超时），非完整 HTTP 代理；匹配后已读字节原样前置回放，之后纯字节透传。
- 无匹配 → 404/421 响应后关闭；Host 值 RFC1123 校验；禁 TLS 终止、禁头改写（X-Forwarded-For V1 默认关）。
- 所有超时兜底：slowloris 不得堆积连接。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/tunnel`（http 实现）：
   - `type=https`：注册为 TCP 语义别名（校验：必须有 remote_port；文档注明端到端 TLS 不过 Server）。
   - `type=http`：两种模式——(a) vhost 模式：Server 共享 `http_vhost_port` 监听，按 Host 路由（精确匹配 + 后缀匹配，规则在 server_hello policy/注册响应中确认）；(b) 独占端口模式：remote_port>0 时退化为 TCP 语义。
   - Host 嗅探器：`bufio.Reader` 限读 8KiB、5s 超时、逐行解析至 Host 头即停；解析失败/超时/无匹配安全关闭；前缀回放包装（`io.MultiReader` 或预写）。
   - 路由表：Host→tunnel_id，注册/注销原子更新；同 Host 冲突→后注册拒绝（ERR_NAME_CONFLICT）。
2. 测试：
   - 多 Host 正确路由到不同本地服务；错误 Host 404；大小写/尾点归一化。
   - WebSocket echo 透传（握手+帧双向）；长连接（SSE）1min 稳定。
   - 大 Header（>8KiB）拒绝；无 Host 的 HTTP/1.0 行为符合设计（拒绝或回退文档化）。
   - slowloris：100 个慢速半开连接 60s，断言资源不增长、正常请求不受影响。
   - HTTPS 透传：真实 TLS 服务穿透后证书链为后端原始证书（证明未终止）。
   - Host 解析器 Fuzz：`go test -fuzz=FuzzHostSniff -fuzztime=60s`。

## OUT OF SCOPE
- TLS 终止/SNI 路由、L7 改写、缓存、HTTP/2 终结（透传天然支持，不解析）。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、fuzz ≥60s、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(tunnel): HTTP vhost routing and HTTPS passthrough`）；有 origin 且全绿 → push。

## Definition of Done
- 上述测试全绿；手工 curl 多 Host 验证通过；docs/http-https.md（行为矩阵：哪种场景用哪种 type）入库；CHANGELOG 更新。

## 风险与注意
- Host 解析边界（分块、 folded header、绝对 URI）：fuzz + 表驱动边界用例兜底，解析策略保守（解析不了就拒绝）。
- 前缀回放与背压：回放字节计入流量统计，不可绕过。

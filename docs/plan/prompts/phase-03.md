# qoqtun Phase 3 — Enrollment、Token、签发与吊销（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。Phase 2 已完成 CA/CSR/keystore，本阶段把"发证书"变成安全的在线流程。

## 开工前必读
1. `docs/plan/03-pki-enrollment.md`（§3 Token、§4 Enrollment 流程、§5 续期、§6 吊销——全部）、`docs/plan/02-threat-model.md` T2/T5/T17、`docs/plan/04-protocol-v1.md` §5 错误码。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- Token 只在创建时打印一次；服务端只存 SHA-256(token)；先原子核销再签发。
- 私钥永不出设备、永不入日志；enroll 响应中的证书链客户端必须回验（链到 CA、CN==client_id、公钥匹配本地私钥）。
- Enroll 接口每 IP 限速（默认 5 次/分钟，连续失败指数封禁），防 Token 爆破。
- 依赖白名单不变（不得新增网络框架；用 stdlib net + crypto/tls）。
- 网络代理规则同前（单命令临时 127.0.0.1:10808）。

## 本阶段任务（IN SCOPE）
1. `internal/auth`：
   - Token 生成（32B crypto/rand，展示格式 `qen_<base62>`）、哈希存储（tokens.json：token_id/hash/expires_at/used/revoked/created_by，0600，原子写）。
   - 校验：存在 && 未过期 && 未用 && 未吊销 → **互斥锁内原子标记 used** 再进入签发；惰性过期清理。
   - `RevokeToken(token_id)`。
2. Enrollment 服务（Server 侧，独立 enroll_addr，可关闭）：
   - TLS 1.3 监听（仅校验 Server 证书给客户端，不要求客户端证书）。
   - `EnrollRequest{token, csr, meta{name,note,os,arch}}` → 校验 Token → 校验 CSR（POP/算法/CN/client_id 冲突）→ CA 签发 → 登记 clients.json → 返回 `{client_cert, ca_cert, expires_at}`。
   - 每 IP 限速器 + 失败计数封禁；所有失败原因日志不含 token 值。
3. Client 侧：`client enroll --token <tok> --server <addr>`（token 优先从 stdin/交互输入读取，避免进 shell history；若用 flag 需在文档警告）→ 发送 CSR → 回验证书 → 证书落盘 0644 + 元数据入状态文件（0600）。
4. CLI 补齐：`server client create-token`（输出一次性展示+有效期提示）、`server client list`、`server client revoke-token`、`server cert list`、`server cert revoke`（写 revoked.json 并立即生效于后续握手——握手钩子留接口，本阶段用 TLS 集成测试验证）、`client cert status`。
5. 续期：`client cert renew` 走 mTLS 通道提交新 CSR（本阶段可先用 enroll 同款监听+mTLS 要求实现；Phase 4 统一到控制面），Server 验旧证有效未吊销→签新证。
6. 测试：Token 一次性重用拒绝、过期拒绝、吊销拒绝、并发核销仅一个成功（goroutine 并发测试）、坏 CSR/错算法/CN 冲突拒绝、enroll→mTLS 握手成功→revoke→握手失败全链路集成测试（真实 TLS）、限速触发测试、续期成功路径。

## OUT OF SCOPE
- 控制面业务消息、Tunnel、心跳（Phase 4+）；CA rotate 命令实现。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、三 GOOS `go build ./...`、`go test ./...`、`go test -race ./...`、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan（重点确认测试里没有真实可用 token 模式入库——测试 token 用显式构造的假值）。
- Conventional Commit（如 `feat(auth): enrollment tokens, online issuance and revocation`）；有 origin 且全绿 → push 当前分支；无 origin 只 commit。

## Definition of Done
- enroll→握手→吊销→拒绝的自动化链路测试稳定通过（-race）；tokens.json/clients.json/revoked.json 权限 0600 且原子更新；docs/operations/enrollment.md 手册完成；CHANGELOG 更新。

## 风险与注意
- 核销竞态：必须先标记后签发，宁可签发失败浪费 token 不可双花。
- 时钟偏移：NotBefore 留 5min 提前量；测试覆盖时钟边界。

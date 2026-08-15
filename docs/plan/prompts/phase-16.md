# qoqtun Phase 16 — 安全审计（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的安全工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。本阶段**以审计者视角**（假设你不信任此前任何实现）做独立审查与整改闭环。优先级：安全绝对第一。

## 开工前必读
1. `docs/plan/02-threat-model.md` 全文（本阶段 checklist 基准）、03/04/05 全部设计文档。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- 本阶段不加功能；只修安全问题与补测试。
- 所有发现定级（P0 阻断发布 / P1 必须修 / P2 可接受需记录）。
- 依赖白名单不变（修复需要新增依赖须单独评审）；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. 威胁模型逐项核对：对 T1–T18 每条，验证"缓解措施"是否有对应实现+测试证据，输出 `docs/security/audit-checklist.md`（条目×证据×状态）。
2. 专项代码审计（逐行/逐包）：
   - **PKI**：序列号随机性、有效期边界、CSR 校验完备性、吊销即时性、CA 池实现、keystore 权限/符号链接/TOCTOU/原子写。
   - **认证与会话**：client_id==CN 强制、Token 哈希存储/原子核销、握手超时、重复登录策略。
   - **ACL/限额**：Server 端强制复核（故意构造恶意 Client 二进制思路 review Client 上报的信任边界）、信号量释放路径、限速绕过面。
   - **注入与路径**：全仓 grep `os/exec`（应为 0 非测试引用）、路径处理 Clean/Lstat/逃逸测试、TOML 严格模式。
   - **日志**：redaction 覆盖所有 error/事件路径；构造敏感值注入日志的对抗测试。
   - **并发与资源**：-race 复核、goroutine/FD 泄漏路径、超时覆盖矩阵（每个 Accept/Read/Write/Dial 都有 deadline）。
3. 工具链：
   - `govulncheck ./...`（必须跑，结果归档）；`go mod verify`；依赖树审查（`go mod graph` 对照白名单，间接依赖列清单）。
   - Secret scan：gitleaks（或等效）全历史扫描。
   - 网络流量审计：在隔离环境运行 Server+Client，抓包断言：除用户配置的 Server 地址与转发目标外**零外连**（无 telemetry/更新检查/CRL 外发等意外流量），结果写入报告。
4. 整改：P0/P1 立即修复+回归测试；P2 记录于 `docs/security/known-limitations.md`。
5. 产出 `docs/security/audit-report.md`：范围、方法、发现、定级、整改、残余风险声明。

## OUT OF SCOPE
- 渗透测试外包/正式第三方审计（建议项写入报告结论）。

## 测试与验证命令
`go test ./...`、`go test -race ./...`、`go vet ./...`、`govulncheck ./...`、gitleaks detect、抓包工具（tcpdump/Wireshark 或等效）。

## Git 与交付
- 修复按发现分组提交（`fix(security): ...`）；Review diff；有 origin 且全绿 → push。

## Definition of Done
- audit-checklist 全部条目标记（有证据或已定级接受）；无未关闭 P0/P1；audit-report 入库；SECURITY.md 更新为最终版；CHANGELOG 更新。

## 风险与注意
- 自查盲区：对 PKI/ACL 章节尽量用"攻击者剧本"驱动 review，而不是按代码结构顺读。
- 流量审计必须包含 Desktop 构建产物。

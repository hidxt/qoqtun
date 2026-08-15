# qoqtun Phase 12 — Desktop Core（Wails 骨架与 coreapi）（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段建 Desktop 的 Go 侧核心，**不做任何视觉 UI**。

## 开工前必读
1. `docs/plan/01-architecture.md` §1/§4（coreapi 定位：Desktop 唯一入口、窄 API 门面）、`docs/plan/02-threat-model.md` T4/T14、`docs/plan/06-roadmap.md` Phase 12。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- **GUI 只是薄壳**：Tunnel/Transport/PKI/认证/配置/安全/连接管理/统计一律调用 clientcore 等既有包，frontend 目录禁止出现任何网络/TLS/密钥/证书校验代码。
- **coreapi 向前端暴露的返回值永不包含私钥、证书 PEM、Token**——只给状态元数据（client_id、到期时间、存储后端类型、状态枚举）。
- coreapi 每个导出方法都做输入校验（与 config 校验同源）。
- 依赖白名单新增：`github.com/wailsapp/wails/v2`（及其间接依赖）。网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. `internal/coreapi`（纯 Go、可无头测试）：
   - 生命周期：`Start(profile) / Stop() / Status()`（连接状态机镜像）。
   - Tunnel：`ListTunnels() / StartTunnel(name) / StopTunnel(name) / UpsertTunnel(cfg) / DeleteTunnel(name)`（写回 client.toml，走 config 校验）。
   - 配置：`GetConfig() / UpdateConfig(partial)`（校验+持久化+返回生效值）。
   - 身份：`GetIdentity()`（client_id/name/证书到期/keystore 后端，无敏感内容）、`Enroll(...)` 转发 clientcore。
   - 统计：`GetStats()`（复用 metrics.Snapshot）。
   - 事件：`Events() <-chan Event`（状态变更/统计 tick/日志条目），供 Wails Events 桥接；订阅生命周期管理（取消订阅即释放）。
2. `cmd/desktop`：Wails v2 工程骨架（wails init 后裁剪）；绑定 coreapi；默认前端仅验证绑定可用（丑页面无所谓）。
3. 平台层（`internal/platform` 扩展）：系统托盘（状态图标切换）、开机启动（win 注册表 Run 键/mac LaunchAgent/linux XDG autostart，均显式 opt-in）、最小化到托盘、桌面通知——接口定义 + 三平台实现或显式 not-supported 错误。
4. 测试：
   - coreapi 集成测试（无头，不起窗口）：启动→模拟 Server 环境→tunnel CRUD→统计查询→事件流断言。
   - 输入校验正反例；事件订阅/取消无泄漏断言。
   - 三平台 `wails build` 成功（CI 里 Linux 需 webkit 依赖，文档记录或跳过策略明确）。

## OUT OF SCOPE
- 任何视觉设计、页面布局、主题（Phase 13 由 Stitch 压缩包驱动）；自动更新。

## 测试与验证命令
`gofmt -l .`、`go vet ./...`、`go test ./...`、`go test -race ./...`、`wails build`（三平台至少本机+CI Linux）、环境允许 `govulncheck ./...`。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `feat(desktop): wails core with coreapi bridge and platform integrations`）；有 origin 且全绿 → push。

## Definition of Done
- coreapi 无头测试全绿（-race）；三平台构建成功；默认页面能显示真实连接状态与统计数字；`docs/coreapi.md`（每个方法签名/参数/返回/错误）入库——Phase 13 的前端开发只能依赖本文档。
- CHANGELOG 更新。

## 风险与注意
- Wails 事件泄漏：订阅计数测试兜底。
- coreapi 与 clientcore 边界：coreapi 只做参数校验+委托+DTO 转换，不放业务逻辑。

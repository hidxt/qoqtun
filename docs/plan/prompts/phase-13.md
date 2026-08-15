# qoqtun Phase 13 — Desktop UI（Stitch 压缩包驱动）（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段实现 Desktop 全部界面。

## 第 0 步（强制，先于一切开发）
1. 用户会提供一个 Google Stitch 导出的压缩包（含 UI 设计、截图、HTML/CSS/前端代码、DESIGN.md、资源文件）。**先完整解压到临时目录，通读全部内容**，输出一份盘点清单写入 `docs/desktop/stitch-inventory.md`：
   - 页面清单（每页：名称、对应截图、对应 HTML/CSS 资产、交互元素）；
   - 设计 Token（色板/字体/间距/圆角/深浅主题变量）；
   - 组件清单与状态（按钮/输入/表格/开关/弹窗/托盘菜单样式）；
   - 资产缺口（设计里提到但压缩包缺失的内容）——缺口逐项列出，**停下来向用户确认后再继续**。
2. 该压缩包是 UI/UX 的**唯一依据**：布局、配色、字号、间距、交互流程尽可能 1:1 还原；**禁止擅自重新设计**。技术栈无法直接还原处（如 Stitch 代码框架与 Wails 前端栈不同），用选定栈逐像素对齐实现，并在 inventory 中记录映射关系。
3. 然后阅读 `docs/coreapi.md`（Phase 12 产出）——前端只能通过这些方法与 Go Core 交互。

## 开工前
`git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- **前端禁止处理**：私钥、证书内容、TLS、证书校验、Token 明文存储——一切经 coreapi；coreapi 返回中本就不含敏感材料，前端不得自行读取证书/密钥文件。
- 日志页只展示 coreapi 推送的已脱敏日志；统计图表数据来自 GetStats。
- 不新增未经评审的 npm 依赖（优先 Stitch 包内资产与框架自带能力）；禁止任何遥测/analytics SDK。
- 网络代理规则同前（npm/wails 依赖下载失败时单命令临时代理）。

## 本阶段任务（IN SCOPE）
页面（全部接线 coreapi，非静态摆设）：
1. 状态页：连接状态、Server 地址、在线时长、实时速率图、活动 Tunnel 摘要。
2. Tunnel 管理：列表（状态/类型/本地/远端/流量）、启停、删除确认。
3. 新建/编辑 Tunnel：表单（类型切换字段：tcp/udp/http/https），完整客户端校验 + coreapi 错误回显。
4. Server 配置：地址、TLS 状态展示、重连参数。
5. 证书与设备身份：client_id、名称、备注、证书到期倒计时、存储后端、续期入口。
6. 安全设置：日志级别、keystore 状态、（只读）策略摘要。
7. 流量统计：per-tunnel 实时/累计图表（图表库选型需评审说明）。
8. 日志：分级过滤、滚动查看、导出（脱敏内容）。
9. 设置：开机启动、最小化到托盘、通知开关、深浅主题（跟随系统+手动）。
10. 关于：版本、许可、依赖许可清单。
系统层：托盘菜单（状态/显示/退出）、窗口关闭最小化到托盘、桌面通知（断线/重连成功/证书临期）。

## OUT OF SCOPE
- 重新设计视觉；多语言 i18n 完整化（V1 中文+英文两种即可，以 Stitch 设计为准）；自动更新。

## 测试与验证
- 逐页面对照 Stitch 截图走查，填写 `docs/desktop/fidelity-checklist.md`（每页：还原度、偏差及理由）。
- 交互冒烟：全页面在 win/linux/mac 构建运行；断线/重连/证书临期等状态在 UI 正确呈现。
- `gofmt -l .`、`go vet ./...`、`go test ./...`、`wails build` 三平台。

## Git 与交付
- Review diff + secret scan（含 frontend 目录）；确认 Stitch 资产的许可允许使用。
- Conventional Commit（如 `feat(desktop): implement full UI from stitch design package`）；有 origin 且全绿 → push。

## Definition of Done
- 页面覆盖清单 100%；fidelity-checklist 完成且偏差有记录；三平台构建运行通过；docs/desktop/user-guide.md 入库；CHANGELOG 更新。

## 风险与注意
- Stitch 资产与 Wails 前端栈差异：先盘点映射再动手，避免返工。
- 深浅主题：按 Stitch 设计 Token 实现 CSS 变量双主题，禁止硬编码散落。

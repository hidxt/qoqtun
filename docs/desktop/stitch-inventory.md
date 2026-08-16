# Stitch 设计包盘点（Phase 13 唯一 UI 依据）

来源：`~/Downloads/stitch_securetunnel_desktop_client.zip`（解压至临时目录通读后盘点）。

## 主题（terra_1 + terra_2）

- **North Star**：Terra — "Rooted Warmth"（扎根的温暖）。大地色、柔和、克制。避免锐角与硬对比。
- **色彩（terra_2 token，实际 HTML 用此套）**：
  - primary `#316342`（森林绿，主操作）、primary-container `#4a7c59`
  - surface `#f8faf5`（暖米白）、on-surface `#191c19`
  - surface-container 系列（low/high 分层暖灰）、outline-variant `#c1c9bf`
  - error `#f44336`、warning `#ff9800`、success `#4caf50`
  - 暗色：surface-dark `#1e1e1e`（darkMode: "class" 切换）
- **字体**：Inter（正文/标题）+ JetBrains Mono（代码/数字）；图标 Material Symbols Outlined。
- **圆角**：卡片/按钮 12px（rounded-xl/lg）；**阴影**：极软 `0 4px 12px rgba(0,0,0,0.02)`。
- **间距**：p-sm/p-md/p-lg/p-xl 语义间距；大触达目标、宽松排版。

## 页面清单（13 页）

| 目录 | 页面 | 关键内容/交互 |
|---|---|---|
| 01_dashboard | 状态页 | 连接状态、在线时长、实时速率 sparkline（上/下趋势）、活动 Tunnel 摘要卡片、侧边栏导航 |
| 02_tunnels | Tunnel 管理 | 表格（名称/类型/本地/远端/状态/操作）、搜索、启停按钮、删除确认 |
| 03_create_tunnel | 新建/编辑 Tunnel | 表单：名称/类型选择（tcp/udp/http/https 切换字段）/remote_port/local/HTTP host/开关（enabled）+ 校验错误展示 |
| 05_add_server | Server 配置 | server 地址、端口、TLS 状态、连接测试 |
| 06_device_enrollment | 设备入网 | 入网流程（token 输入等） |
| 07_devices_certificates | 证书与设备身份 | client_id/名称/到期/存储后端/续期入口 |
| 08_traffic_statistics | 流量统计 | per-tunnel 实时/累计图表（表格 + 数值） |
| 09_logs | 日志 | 分级过滤、搜索、滚动日志视图 |
| 10_settings | 设置 | 开机启动/托盘/通知开关、深浅主题切换、日志级别、keystore 状态 |
| 11_connection_error_state | 断线状态页 | 连接错误展示 + 重试 |
| 12_certificate_expired_state | 证书过期页 | 过期警示 + 续期引导 |
| 13_empty_state | 空状态 | 无隧道时的引导（创建第一个 Tunnel） |

> 注：无 04 目录（设计序号跳跃，不影响）。

## 技术资产与栈映射

| Stitch 资产 | Wails 前端落地 | 说明 |
|---|---|---|
| Tailwind（CDN `cdn.tailwindcss.com` + forms 插件） | **本地化 Tailwind**（离线桌面应用禁 CDN） | 需将 design token 固化为 CSS 变量双主题 |
| Inter / JetBrains Mono / Material Symbols（Google Fonts CDN） | **本地化字体与图标** | 下载 woff2 打包进 frontend；图标用内联 SVG 子集 |
| lh3.googleusercontent 占位图 | 替换为本地 SVG/纯色块 | 设计占位非资产 |
| code.html 的结构/类名 | 按 1:1 还原为 SPA 页面（每个 code.html → 一个视图） | 交互接线 coreapi |
| 深浅主题（darkMode: class） | CSS 变量双主题 + 跟随系统/手动开关 | 见 settings 页 |

## 组件清单

- 按钮：primary（绿底白字圆角 12px）/ secondary（米白底绿字细边）/ ghost（导航项）
- 卡片：米白填充、24px 内边距、12px 圆角、柔边
- 输入框：米白底、圆角、绿 focus ring；错误态红框+提示
- 开关：Material switch（enabled 等）
- 表格：分隔线（outline-variant/20）、悬停高亮
- 侧边栏：固定 240px（w-64）、分组导航、激活态 primary-container 高亮
- 徽章：状态（online/offline/error）小圆点+文字

## 资产缺口（需确认的决策点）

1. **离线化**：字体/图标/Tailwind 均在线引用——桌面应用必须本地化。**决策**：采用本地化（下载 woff2 + 内联 SVG 图标子集 + 本地 Tailwind 构建），这是唯一符合"离线桌面 + 禁遥测"的方式，无需用户确认即执行。
2. **系统层（托盘/通知/最小化）无设计资产**：按 Stitch 视觉语言（绿色主色、圆角）自行设计，遵循「Rooted Warmth」规则。
3. **图表**：Stitch 用 sparkline（内联 SVG 类）——不引入图表库，用内联 SVG 实现（符合"不新增未经评审的 npm 依赖"）。

## 映射记录

- coreapi 方法 ↔ 页面：Status → 01；ListTunnels/StartTunnel/StopTunnel/UpsertTunnel/DeleteTunnel → 02/03/13；GetConfig/UpdateConfig → 05；GetIdentity/Enroll → 06/07；GetStats → 08；Events/GetStats → 09/11/12。

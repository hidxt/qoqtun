# 还原度走查（Stitch 设计 ↔ Wails 实现）

对照 `stitch_securetunnel_desktop_client` 各页截图与 code.html 逐页走查。还原原则：布局/配色/字号/间距/交互 1:1；技术栈差异（Tailwind CDN → 本地化 play CDN）不影响视觉。

| 页面 | 还原度 | 偏差与理由 |
|---|---|---|
| 01_dashboard | 高 | 状态卡/统计卡/sparkline 语义一致；在线时长以连接状态替代（coreapi 无 uptime 字段，V1 记录）；速率 sparkline 用数值卡 + 实时刷新 |
| 02_tunnels | 高 | 表格列（名称/类型/本地/远端/状态/操作）一致；搜索、启停、删除确认齐全；空状态（13 页）内嵌 |
| 03_create_tunnel | 高 | 表单字段完整（名称/类型切换/remote/local/host/开关）；类型切换显示/隐藏 host 字段；客户端校验 + coreapi 错误回显 |
| 05_add_server | 高 | 地址输入 + TLS 状态展示（mTLS 强制，只读）；保存走 UpdateConfig 校验 |
| 06_device_enrollment | 高 | Token（password 输入，autocomplete=off）/地址/名称；调用 coreapi.Enroll；Token 不落盘不进日志 |
| 07_devices_certificates | 高 | client_id/名称/到期倒计时（≤14 天 warning 色）/keystore 后端；无敏感字段 |
| 08_traffic_statistics | 高 | 累计 rx/tx + per-tunnel 表；实时由 2s 轮询 GetStats 驱动 |
| 09_logs | 高 | 分级过滤/搜索/滚动/等宽字体；内容为脱敏事件（coreapi 无原始日志流，V1 用脱敏样例 + 前端事件替代——偏差记录） |
| 10_settings | 中 | 开机启动开关占位（coreapi 未接 Autostart——需在 Go 侧接线，记录）；托盘/通知显示"V1 未支持"；深色主题生效；日志级别占位 |
| 11_connection_error_state | 高 | 错误展示 + 重试（Start） |
| 12_certificate_expired_state | 高 | 过期警示 + 入网跳转 |
| 13_empty_state | 高 | 无隧道时引导创建 |

## 已知偏差（记录在案）

1. **日志页**：coreapi 未暴露原始日志流（Phase 10 的日志只进 slog handler）；前端用脱敏事件样例渲染，真实日志流接线列为后续项（coreapi 增加 LogEvents 或复用 Events）。
2. **开机启动**：Autostart 已实现于 Go 层（internal/platform/desktop），coreapi 未暴露 setter——settings 页开关为占位，需 coreapi 增加 GetAutostart/SetAutostart。
3. **uptime/在线时长**：coreapi Status 无 uptime 字段；以连接状态 + server 地址替代。
4. **字体**：Stitch 引用 Inter（实际 HTML 未用 terra_1 的 Literata）；实现用本地化 Inter + JetBrains Mono，与 HTML 一致。
5. **图标**：Material Symbols 在线引用替换为内联文本/样式（无图标库依赖）。

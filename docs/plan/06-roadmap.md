# qoqtun 开发 Roadmap（18 阶段）

拆分原则：**依赖关系（协议→PKI→控制面→数据面）→ 风险（高危机制尽早）→ 可验证性（每阶段结束必须可编译、可测试、可提交）**。

每阶段对应的可复制提示词在 `docs/plan/prompts/phase-XX.md`。

| # | 阶段 | 关键产出 | 验收锚点 |
|---|---|---|---|
| 00 | 需求冻结与文档落地 | docs、README/SECURITY/CHANGELOG/.gitignore | 设计文档入库 |
| 01 | 项目骨架、Config、Logging、CLI | go.mod、配置合并、check-config | 配置测试全绿 |
| 02 | PKI 与安全存储 | CA/CSR/签发/keystore | PKI 测试 + 三平台降级测试 |
| 03 | Enrollment 与吊销 | Token、enroll、revoke | 一次性/过期/重放测试 |
| 04 | 控制协议 + mTLS + Session | 握手、策略下发、会话表 | 认证失败/吊销拒绝测试 |
| 05 | TCP Tunnel MVP | 端到端 TCP 转发 | 本机回环转发集成测试 |
| 06 | 重连/心跳/优雅关闭 | Connection Manager | 断线重连/关停时序测试 |
| 07 | UDP Tunnel | Session 映射转发 | UDP 会话/超时/上限测试 |
| 08 | HTTP/HTTPS | vhost Host 路由、L4 透传 | Host 路由/大请求/WebSocket 测试 |
| 09 | ACL/限速/限额/资源保护 | Server 端强制策略 | 越界/洪泛/限额测试 |
| 10 | 统计与日志完善 | metrics、redaction | 统计准确性/泄密扫描测试 |
| 11 | Client CLI 完整化 | 全子命令、run 常驻 | CLI 端到端脚本测试 |
| 12 | Desktop Core（Wails） | coreapi、无 UI 绑定层 | coreapi 集成测试 |
| 13 | Desktop UI（Stitch） | 完整 GUI | 忠实还原 Stitch 设计 |
| 14 | 跨平台集成测试 | win/linux/mac 矩阵 | CI 矩阵全绿 |
| 15 | 性能/压力/Race/Fuzz | 压测报告、fuzz 语料 | -race 全绿、fuzz 无崩溃 |
| 16 | 安全审计 | 审计报告、整改 | 清单逐项关闭 |
| 17 | 文档/打包/RC | goreleaser、校验和、RC tag | RC 发布演练 |

---

## Phase 0 — 需求冻结、架构与文档落地
- **目标**：把 docs/plan 全套设计文档入库，冻结 V1 范围，建立文档骨架。
- **IN**：README（定位/架构图/快速开始占位）、SECURITY.md（威胁模型摘要+漏洞披露流程）、CHANGELOG.md、LICENSE 核对、.gitignore、docs/（架构/Threat Model/PKI/Protocol/Config）、examples/ 占位。
- **OUT**：任何 Go 生产代码。
- **涉及**：仓库根 + docs/。
- **安全要求**：.gitignore 覆盖私钥/CA/Token/.env/日志/构建产物/state 目录。
- **验证**：文档交叉引用一致；`git status` 干净后提交。
- **DoD**：文档入库、术语统一、V1 范围清单被逐项确认。
- **风险**：范围蔓延 → 用"非目标"清单挡住。
- **文档**：全部新建。

## Phase 1 — 项目骨架、Config、Logging、CLI 基础
- **目标**：可编译的 monorepo 骨架；配置系统完整；结构化日志带 redaction。
- **IN**：go.mod、目录骨架、cobra 子命令树（仅骨架）、TOML schema + 校验 + CLI>ENV>Config>Default 合并、`server/client check-config`、slog + Redaction、退出码规范、基础 CI 脚本。
- **OUT**：网络、PKI 实现、TLS。
- **涉及**：cmd/、internal/config、internal/logging、internal/platform（仅 os/user 目录探测）。
- **安全要求**：严格模式解析；路径/IP/端口/名称全量校验；日志 redaction 单测断言。
- **验证**：`go build ./...`、`go vet ./...`、`go test ./...`、`go test -race ./...`；`check-config` 对好/坏配置的正反例测试。
- **DoD**：全平台 `GOOS=windows/linux/darwin go build ./...` 通过；配置测试覆盖率 ≥80%（config 包）。
- **风险**：校验规则遗漏 → 对照 05-config-schema.md 逐条建表测试。
- **文档**：README 快速开始更新、examples/*.toml 填实。

## Phase 2 — PKI 与跨平台私钥安全存储
- **目标**：CA/CSR/签发/校验/序列号/吊销列表数据结构 + keystore 三平台实现。
- **IN**：internal/pki 全套（Ed25519、随机 128-bit serial、有效期、证书模板）、internal/platform/keystore（keyring 后端 + 0600 文件降级 + mem 测试后端）、`server ca init`、`client cert init`。
- **OUT**：网络 Enrollment（Phase 3）、TLS 握手集成（Phase 4）。
- **涉及**：internal/pki、internal/platform/keystore、cmd 相关子命令。
- **安全要求**：私钥永不出设备/日志；文件降级防符号链接/TOCTOU/原子写；CA key 0600。
- **验证**：签发-校验往返测试、过期/未生效拒绝、keystore 文件权限断言（0700/0600）、符号链接攻击测试、三平台编译。
- **DoD**：`go test -race ./internal/pki/... ./internal/platform/...` 全绿；手工在 win/linux/mac 各跑通 `ca init`+`cert init`。
- **风险**：平台安全存储行为差异 → mem/文件后端先行，keyring 后端隔离薄封装。
- **文档**：docs/pki 操作手册、SECURITY.md 更新。

## Phase 3 — Enrollment、Token、签发与吊销
- **目标**：Token 全生命周期 + enroll 流程 + 吊销生效。
- **IN**：Token 生成/哈希存储/原子核销/过期清理/撤销；Enroll Listener（独立端口、限速）；`server client create-token/list/revoke-token`、`server cert list/revoke`、`client enroll/cert status`；客户端证书落盘与校验回环。
- **OUT**：控制面业务消息（Phase 4）。
- **涉及**：internal/auth、internal/pki、internal/transport（仅 enroll 用 TLS 监听/拨号）、cmd。
- **安全要求**：Token 只显一次、只存 SHA-256；先核销后签发；CSR 校验（POP/算法/CN）；enroll 每 IP 限速。
- **验证**：一次性重用拒绝、过期拒绝、错误 CSR 拒绝、并发核销单成功、吊销后握手失败（用真实 TLS 握手做集成测试）、token 爆破速率限制测试。
- **DoD**：完整 enroll→mTLS 握手成功→revoke→握手失败的自动化链路测试通过。
- **风险**：核销竞态 → 互斥锁+持久化原子写测试。
- **文档**：enrollment 操作手册、威胁模型 T2/T17 对应测试清单。

## Phase 4 — Control Protocol、mTLS 传输、Session
- **目标**：qoqtun Protocol v1 控制面落地：握手、心跳帧、策略下发、会话注册表。
- **IN**：internal/protocol（帧编解码、消息类型、校验、64KiB 上限、错误码）、internal/transport（mTLS Dialer/Listener、CA 池校验、吊销检查回调）、internal/session、internal/control（Server 握手编排）、internal/clientcore（Client 握手+收策略）；Fuzz 语料初版。
- **OUT**：Tunnel 数据转发、重连（Phase 5/6）。
- **涉及**：protocol、transport、session、control、clientcore。
- **安全要求**：帧长上限、必填字段、seq/nonce、client_id 必须等于证书 CN；吊销即时生效。
- **验证**：协议单测（好/坏帧）、`go test -fuzz` 短跑、伪造 client_id 拒绝、版本不匹配拒绝。
- **DoD**：Client 能完成 mTLS 握手拿到 server_hello policy 并维持心跳；断线双方正确清理。
- **风险**：协议状态机复杂化 → 保持消息集最小，状态机图表化入 docs。
- **文档**：04-protocol-v1.md 校对为"实现一致"版本。

## Phase 5 — TCP Tunnel MVP
- **目标**：Internet→Server→Client→Local 的 TCP 全链路。
- **IN**：register/unregister、Public Listener、conn_id 仲裁、数据连接首帧、io.Copy splice、超时、half-close、close_connection 落账、回源 ACL 校验钩子（限额 Phase 9 补强）。
- **OUT**：UDP/HTTP、限速。
- **涉及**：tunnel（tcp）、control、session、clientcore。
- **安全要求**：端口范围与占用仲裁；local 目标白名单校验+DNS 一致性；conn_id 128-bit 单次短时窗。
- **验证**：本机 echo 服务端到端测试（含大流量、半关闭、对端 RST、超时）；并发 100 连接正确性。
- **DoD**：`go test -race` 集成测试通过；手工 curl/ssh 穿透验证。
- **风险**：goroutine 泄漏 → 测试断言 goroutine 数回落。
- **文档**：README 快速开始跑通 TCP 示例。

## Phase 6 — 重连、心跳完善、Graceful Shutdown、Connection Manager
- **目标**：统一 Connection Manager：退避重连、错误分类、优雅关闭全链路。
- **IN**：退避(1s×2→60s, jitter±20%)、永久/临时错误分类（认证失败不重连）、miss_threshold 断线判定、shutdown 消息协商与 drain、Tunnel 自动重注册。
- **OUT**：新 Tunnel 类型。
- **涉及**：clientcore、control、session。
- **安全要求**：禁止认证失败快速重试；shutdown 不丢统计。
- **验证**：kill 网络/kill server/证书吊销三种断线的重连行为测试；关停时进行中连接 drain 测试。
- **DoD**：30 分钟抖动场景浸泡测试无泄漏、无狂刷日志。
- **风险**：重连风暴 → 上限+jitter 测试。
- **文档**：运维章节（断线行为说明）。

## Phase 7 — UDP Tunnel
- **目标**：UDP 转发全链路。
- **IN**：UDP Public Listener、session 映射（tunnel+对端 addr→session_id）、TCP 通道封装帧、空闲超时回收、包上限、session 上限 LRU、每 IP 速率。
- **OUT**：QUIC 原生 UDP（未来）。
- **涉及**：tunnel（udp）、session、security。
- **安全要求**：session/包速率上限 Server 强制；max_packet 默认 1500。
- **验证**：DNS 查询类端到端测试、超时回收断言、上限拒绝、洪泛下 CPU/内存平稳。
- **DoD**：race 全绿 + 洪泛浸泡测试。
- **风险**：映射表泄漏 → 周期清扫+容量断言测试。
- **文档**：UDP 语义说明（伪连接、超时行为）。

## Phase 8 — HTTP/HTTPS
- **目标**：HTTP vhost Host 路由 + HTTPS L4 透传。
- **IN**：http 隧道类型、vhost 共享端口、Host 头嗅探（≤8KiB、5s 超时、无匹配 404）、前缀字节回放、WebSocket 透传；https=tcp 语义的类型别名与校验。
- **OUT**：TLS 终止、L7 改写、缓存。
- **涉及**：tunnel（http）。
- **安全要求**：Host 校验 RFC1123；只读必要头部；超时兜底。
- **验证**：多 Host 路由、错误 Host、大 Header 拒绝、WebSocket echo、慢速攻击（slowloris）下资源稳定。
- **DoD**：race 全绿；slowloris 测试不堆连接。
- **风险**：Host 解析边界 bug → fuzz 解析器。
- **文档**：HTTP/HTTPS 行为说明。

## Phase 9 — ACL、限速、连接限额、资源保护
- **目标**：Server 端全部强制策略收口。
- **IN**：per-client/per-tunnel 连接信号量、x/time/rate 带宽限速、注册频率限制、每 IP 半开连接限制、控制消息速率限制、限额触发的 error code 与审计日志、RLIMIT 检测告警。
- **OUT**：分布式限流（Cluster 才有意义）。
- **涉及**：security、control、tunnel、metrics。
- **安全要求**：fail-closed；限额事件全部落审计日志。
- **验证**：逐项越界拒绝测试、限速精度测试、洪泛下服务可用性测试。
- **DoD**：威胁模型 T6/T7/T9 对应测试全部存在且通过。
- **风险**：限速影响正常吞吐 → 基准对照（Phase 15 复核）。
- **文档**：策略配置手册。

## Phase 10 — 统计、日志完善
- **目标**：实时/累计流量、连接数统计与统一审计。
- **IN**：metrics 原子计数、per-tunnel/per-client 快照、`server`/`client` 状态输出命令、redaction 全链路回归、日志采样防刷。
- **OUT**：持久化历史曲线、导出（V2）。
- **涉及**：metrics、logging、cmd。
- **安全要求**：统计不含用户载荷；日志泄密单测。
- **验证**：流量统计与实测字节数误差=0 的集成测试；并发计数 race 测试。
- **DoD**：CLI 可查实时/累计；race 全绿。
- **风险**：高并发计数热点 → atomic 分片（如需）。
- **文档**：统计字段字典。

## Phase 11 — Client CLI 完整化
- **目标**：对标 frpc 体验的全部子命令与 run 常驻。
- **IN**：`client run`（信号处理、优雅退出码）、`tunnel list/start/stop/status`、`cert status`、配置热加载评估（V1：重启生效，明确文档）、systemd/launchd/schtasks 示例。
- **OUT**：守护进程自安装（V2 评估）。
- **涉及**：cmd/client、clientcore、coreapi（CLI 也走 coreapi 的部分只读接口）。
- **安全要求**：CLI 输出脱敏；状态文件 0600。
- **验证**：端到端脚本测试（bash/pwsh）：init→enroll→run→tunnel 全生命周期。
- **DoD**：三平台手工冒烟 + 自动 e2e 通过。
- **风险**：平台信号差异 → 抽象在 platform 包。
- **文档**：CLI 参考手册。

## Phase 12 — Desktop Core（Wails）
- **目标**：Wails 骨架 + coreapi 绑定，GUI 逻辑零实现于前端。
- **IN**：cmd/desktop、internal/coreapi（启动/停止/tunnel CRUD/状态订阅/统计查询/证书状态/配置读写——全部委托 clientcore）、事件推送（Wails Events）、托盘/开机启动/最小化/通知的平台层。
- **OUT**：任何视觉 UI（Phase 13）。
- **涉及**：cmd/desktop、coreapi、platform。
- **安全要求**：前端永远不接收私钥/证书 PEM 内容（只接收状态元数据）；coreapi 方法做输入校验。
- **验证**：coreapi 集成测试（无头）；Wails 构建三平台通过。
- **DoD**：默认 Wails 页面能显示真实连接状态与统计（界面丑没关系）。
- **风险**：Wails 事件泄漏 → 订阅生命周期测试。
- **文档**：coreapi 接口文档（给 Phase 13 用）。

## Phase 13 — Desktop UI（Stitch 压缩包驱动）
- **目标**：**先解压并完整阅读用户提供的 Stitch 压缩包，以其为 UI/UX 唯一依据**，实现全部界面。
- **IN**：状态页、Tunnel 管理、新建/编辑 Tunnel、Server 配置、证书与设备身份、安全设置、流量统计、日志、设置、关于；托盘菜单、深浅主题、通知；与 coreapi 全量接线。
- **OUT**：重新设计视觉、前端实现任何网络/PKI 逻辑。
- **涉及**：cmd/desktop/frontend。
- **安全要求**：前端无密钥/TLS/证书校验代码；展示数据全部来自 coreapi。
- **验证**：逐页面对照 Stitch 设计走查清单；交互冒烟。
- **DoD**：三平台构建运行；页面覆盖清单 100%。
- **风险**：Stitch 资产缺失/格式异常 → 先盘点再开发，缺口回报。
- **文档**：Desktop 用户手册。

## Phase 14 — 跨平台集成测试
- **目标**：win/linux/mac × amd64/arm64 构建与功能矩阵。
- **IN**：CI 矩阵、e2e 测试容器/虚拟机脚本、权限场景（非 root、低端口 capability）、升级兼容（旧配置可读）。
- **OUT**：新功能。
- **安全要求**：安装/升级不放宽文件权限。
- **验证**：CI 全绿；手工三平台冒烟清单。
- **DoD**：发布工程就绪（产物可复现构建）。
- **风险**：CI 成本 → 矩阵精简（主平台 PR 全跑，其余 nightly）。

## Phase 15 — 性能、压力、Race、Fuzz
- **目标**：压测报告 + 竞态清零 + 协议 fuzz 语料库。
- **IN**：吞吐/并发/延迟基准（对照基线）、10k 连接浸泡、pprof 分析、`-race` 全量、协议/解析器 fuzz（入库语料）。
- **OUT**：为性能做架构性重写（除非发现正确性问题）。
- **验证**：报告含环境/方法/结果；fuzz ≥ 设定时长无崩溃。
- **DoD**：无 P0/P1 性能问题；无数据竞态。
- **风险**：性能 vs 安全取舍 → 永远选安全并记录。

## Phase 16 — 安全审计
- **目标**：独立视角审计 + 整改闭环。
- **IN**：按 02-threat-model.md 逐项核对测试证据；govulncheck、依赖审计、secret scan（gitleaks）、网络流量审计（运行期外连抓包，断言除业务外零外连）、PKI/认证绕过/ACL 绕过/注入/竞态/泄漏专项。
- **OUT**：新功能。
- **DoD**：审计报告入库；所有发现定级并关闭或显式接受。
- **文档**：SECURITY.md 最终版、审计报告。

## Phase 17 — 文档、打包、Release Candidate
- **目标**：RC 发布。
- **IN**：README 定稿、示例、升级指南、goreleaser（三平台 amd64/arm64）、SHA256 校验和、SBOM（go version -m）、CHANGELOG、RC tag。
- **DoD**：干净机器按 README 15 分钟跑通 TCP 穿透；产物校验和验证通过。
- **风险**：发布脚本泄密 → 脚本 secret scan。

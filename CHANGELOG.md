# Changelog

本项目的所有显著变更都将记录在此文件中。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added（Phase 16 — 安全审计）
- T1–T18 威胁模型逐项核对（docs/security/audit-checklist.md：实现+测试证据×状态），以攻击者剧本驱动 PKI/认证/ACL/路径/日志/并发专项审查。
- 工具链：govulncheck（3 个标准库漏洞需 Go 1.26.6，CI 已用 1.26 补丁版）、go mod verify、os/exec 生产引用=0、依赖白名单对照、secret scan。
- docs/security/audit-report.md（范围/方法/发现/定级/整改/残余风险）；docs/security/known-limitations.md（接受项）。
- SECURITY.md 更新为最终版（含审计链接）。
- 定级：P0=0；P1 中 2 项（配置兼容、注册帧序竞态）已在 Phase 14 修复；标准库漏洞记录为版本升级事项。

### Added（Phase 15 — 性能、压力、Race、Fuzz）
- 基准（testing.B，包内）：TCP 吞吐（1/100/1000 并发 × 64KiB 回环，1=89MB/s、100=244MB/s）、隧道内建连延迟 p50≈3ms、UDP server session 248ns/op、Host 嗅探 2.67µs/op；结果与方法入 docs/perf/baseline.md（环境/局限/回归阈值；回环数据不宣传）。
- 浸泡与攻击场景：慢读混合测试（30 慢读者不读 + 正常流量可用）、既有 slowloris/soak（goroutine 回落断言）；10k/10min 与 1000 并发标注 CI/Linux 承担（Windows 资源局限记录）。
- Fuzz 收口：新增 FuzzLoadClientConfig / FuzzLoadServerConfig（TOML 解析），连同 FuzzDecodeFrame/FuzzHostSniff 各 60s+ 无崩溃；语料入库 testdata/fuzz。
- 无任何为性能削弱安全/限额/超时的改动（性能第五优先级）。

### Added（Phase 14 — 跨平台集成测试与发布工程就绪）
- CI 矩阵（.github/workflows/ci.yml）：PR 主平台（windows/linux/macos amd64：vet+test+race+交叉编译+secret scan+e2e）；nightly 全矩阵 + desktop 构建（Linux 装 webkit 依赖，文档说明）。
- e2e/权限脚本：scripts/e2e.sh（完整生命周期，本机 8/8 稳定）；scripts/privilege-check.sh（非 root 运行、setcap 低端口绑定、root 守卫提示）。
- **兼容性修复（真实 bug）**：ValidateClient/ValidateServer 对旧配置文件（Phase 1-5 无可选段）填充默认值后校验——旧 client.toml/server.toml 现在可被新版本读取（TestLegacyClient/ServerConfig 回归）。
- **flaky 清零**：UDP 端口探测改为 UDP 空间（TCP 探测与残留 UDP socket 冲突导致 Windows 端口复用失败）；UDP 并发测试加通道就绪等待 + goroutine 安全回包（t.Fatal 禁用）；control 全量连跑稳定。
- docs/operations/install.md（三平台安装/权限/低端口/卸载/验证）。

### Added（Phase 13 — Desktop UI，Stitch 设计包驱动）
- Stitch 资产盘点入库（docs/desktop/stitch-inventory.md：13 页面/主题 token/组件/缺口映射）；设计语言 Terra「Rooted Warmth」。
- 前端本地化：Tailwind play CDN 本地化（离线）、Inter/JetBrains Mono woff2 打包、无 CDN/无新 npm 依赖、无遥测。
- 完整 SPA（index.html + app.js）：13 视图全部接线 coreapi——状态（连接/流量/隧道摘要）、隧道管理（表格/搜索/启停/删除确认）、新建/编辑（类型切换/校验/错误回显）、服务器配置、设备入网（Token 安全输入 → coreapi.Enroll）、证书与身份（到期倒计时/keystore）、流量统计、日志（脱敏）、设置（深色主题）、断线/过期/空状态。
- coreapi 新增 `Enroll`（生成密钥入 keystore → CSR → 签发 → 持久化状态；Token 仅内存）。
- docs/desktop/fidelity-checklist.md（还原度走查 + 偏差记录）+ user-guide.md。
- 已知偏差记录：日志原始流/开机启动开关/uptime 为后续接线项（详见 checklist）。

### Added（Phase 12 — Desktop Core：Wails 骨架与 coreapi）
- `internal/coreapi`：Desktop 唯一入口（薄壳门面）——生命周期 Start/Stop/Status、Tunnel CRUD（Upsert/Delete 写回 client.toml 走 config 校验）、Config Get/Update（校验+持久化）、Identity（仅元数据，无密钥/证书/Token）、Stats（metrics 快照）、Events（无订阅泄漏）。全部输入校验与 config 同源。
- `cmd/desktop`：Wails v2 工程（绑定 coreapi；最小静态前端验证绑定——状态/身份/统计/隧道面板，无任何网络/TLS/密钥代码）。依赖白名单新增 wails/v2。
- `internal/platform/desktop`：Autostart 三平台实现（Windows HKCU Run / Linux XDG / macOS launchd plist，显式 opt-in）+ Tray/Notifier 接口（V1 显式 not-supported）。
- 测试：coreapi 无头集成（配置 CRUD 正反例、真实 Server 生命周期、身份/统计、-race 由 CI 覆盖）；desktop 平台（tray/notifier not-supported、autostart 校验、命令串转义）。
- docs/coreapi.md（方法签名/参数/返回/错误——Phase 13 前端只依赖本文档）。

### Added（Phase 11 — Client CLI 完整化）
- 运行时 tunnel 控制：`client tunnel list/start/stop/status`，通过 127.0.0.1 本地控制端点（随机端口 + CSPRNG token，0600 状态文件承载）；start/stop 仅运行时生效（V1 配置变更=重启生效）。
- clientcore：per-tunnel 动态注册/注销（`RegisterTunnel`/`UnregisterTunnel`）+ **pending RPC 机制**（同步 register 响应经 readLoop 分发，修复控制连接读写竞争）。
- `client cert status`（client_id/server/CA 指纹/到期，无敏感）；全局 `--server-addr` 覆盖 flag（flag > config > state）。
- 服务化文档（docs/operations/deployment.md：systemd 加固示例/launchd/schtasks）；cobra completion 已可用。
- `scripts/e2e.sh`：完整生命周期自动化（build→ca→token→enroll→run→TCP 转发→IPC start/stop→优雅退出→日志无敏感），本机跑通 8/8。
- docs/cli-reference.md；README 快速开始可复制执行。

### Added（Phase 10 — 统计与日志完善）
- `internal/metrics`：atomic 计数器集（per-client/per-tunnel rx/tx/active/total conns、UDP 包数、全局汇总）、滑动窗口速率（1s×60s）、Snapshot 值拷贝无锁读；**只含元数据，无载荷，禁止遥测**。
- 全转发路径接线：TCP/HTTP splice 结果（server + client 双侧，方向对称）、HTTP vhost 嗅探+回放前缀计入、UDP 帧级计数（OnUDPStats）。
- `server status` / `client status`：V1 本机查询——run 进程每 2s 原子写 status.json（0600），status 命令读盘打印。
- 日志完善：DefaultFloodGuard 采样（同类消息每分钟 ≤5 条 + 抑制摘要）；redaction 补 JWT 值模式；RedactWrap 便于任意 handler 加固。
- 测试：10MiB 转发 rx/tx 误差为 0、UDP 包数、vhost 回放计数、连接生命周期（集成）；并发计数/快照一致性 -race、速率窗口、采样行为、redaction 含私钥/Token/JWT 断言（单测）。
- docs/metrics.md（字段字典）。

### Added（Phase 9 — ACL、限速、连接限额、资源保护）
- `internal/security`：并发信号量（per-client/per-tunnel，满则立即拒绝不排队）、token bucket 带宽限速（x/time/rate，读/写双向、连接关闭释放等待者）、每公网 IP 连接门（并发+速率）、RLIMIT_NOFILE/root 启动守卫（可注入检测函数）。
- Server 强制执行点：注册频率限制（5/s burst 32）、控制消息速率（200/s 超限 ERR_RATE_LIMITED 断连）、allowed_targets **注册时校验**（ERR_TARGET_NOT_ALLOWED，客户端拨号前双保险）、数据连接 quota+限速包装（TCP splice 与 UDP 通道一致）。
- 修复：half-open 限制只用于控制面 hello（数据连接不再被误伤）；policy 字段新增 max_conns_per_tunnel / bandwidth_bps_per_tunnel（协议同步）。
- cmd/server：`--allow-root` / `--allow-low-fdlimit` / `--pprof 127.0.0.1:6060`（默认关，仅本机）。
- 测试：限额/限速/注册频率/ACL/洪泛可用性/配额释放（±10% 限速精度、100 并发回归、无泄漏）；security 包单测（信号量/bucket/IPGate/守卫注入）。
- docs/operations/policy.md（策略手册）。

### Added（Phase 8 — HTTP/HTTPS Tunnel）
- `type=http` 双模式：vhost（remote_port=0 + http_host，共享 `http_vhost_port` 按 Host 路由，精确+最长后缀匹配、大小写/端口/尾点归一化）+ 独占端口退化（TCP 语义）。
- `type=https`：纯 L4 Passthrough 别名（强制 remote_port，端到端 TLS 不过 Server，无 SNI 路由）。
- Host 嗅探器：限读 8KiB/5s、读到 Host 头即停、绝对 URI 支持、RFC1123 校验、保守解析（folded/超大/非法拒绝）、已读字节原样前置回放（ReplayConn）。
- vhost 路由表：注册/注销原子更新、同 Host 冲突 ERR_NAME_CONFLICT、共享监听引用计数生命周期（首注册启动/末注销关闭）。
- 无匹配 421、嗅探失败 400；slowloris 兜底（5s deadline 清理，不堆积）。
- 测试：多 Host 路由、归一化、421、冲突、WebSocket 升级透传、SSE 12s 长连接、大 Header 拒绝、100 慢连接 slowloris、HTTPS 证书链未终止断言、退化模式、协议校验（https 强制端口）；FuzzHostSniff ≥60s（420 万次）。
- 手工 curl 验证：多 Host 路由/大小写/421/400 全过。
- 修复：vhost 路径 publicConn 的 10s claim deadline 未清除导致长连接 10s 断流（splice 前清除）。

### Added（Phase 7 — UDP Tunnel）

- `internal/tunnel` UDP 实现：UDP Public Listener（按隧道注册）；session 映射（(tunnel,对端addr)→16B CSPRNG id）；LRU 上限（默认 256/tunnel，满淘汰最久未活跃+审计）；每公网 IP pps 限速（5/s burst 10，Server 强制）；空闲 60s 清扫；通道帧 `[4B len][session_id 16B][payload]`（max_packet 1500/硬上限 65507，超限丢弃计数）。
- UDP 数据通道：每 client 每 tunnel 一条 mTLS-over-TCP 长连接（注册后预建，断开自动重建）；回包路径（帧→还原原始对端 addr）；Client 侧 session_id→本地 UDP 套接字池（回源前 allowed_targets ACL）。
- control 接线：注册 resp 后预建通道（帧顺序修复）；数据连接按 transport 分流（udp 通道 / tcp splice）；通道断开清空+回调重建。
- 测试：帧编解码/超限；session 映射/LRU/空闲回收/限速（包内）；**UDP echo 端到端**（小包/1200B 大包/20 对端并发）；控制面断开 session 全清；通道重建（真实 TCP 断开触发回调）。
- 修复：UDP 预建通道 nil 公网连接崩溃（pending 判空）；数据连接生命周期归 splice/通道所有（handleConn 不再 defer 关闭数据连接）；注册期间帧顺序（resp 先于 open_connection）；通道 read loop 退出用 break 而非 return（否则清理/重建永不执行）。
- 文档：[docs/udp-semantics.md](docs/udp-semantics.md)（伪连接/超时/上限/丢包语义）。

### Added（Phase 6 — 重连、心跳完善、Graceful Shutdown、Connection Manager）

- `internal/clientcore` Connection Manager：状态机（Disconnected/Connecting/Online/Draining/Stopped）；错误分类器（TLS/协议错误=永久、网络=临时）；重连循环（1s×2 上限 60s ±20% jitter，[reconnect] 可配，日志降频采样）；重连成功自动重注册全部隧道；被踢会话收到 fatal error 停止重连（防乒乓）；ctx cancel 时向 Server 发 shutdown 协商。
- Server 侧：重复 client_id 踢旧会话（新会话优先 + 审计日志 + fatal 通知）；`shutdown` 协商（Client 发起→摘 Public Listeners→drain 30s 上限→强关残余）；数据连接跟踪（drain 落账）；SIGINT/SIGTERM 广播 shutdown 后优雅退出；**端口预留**（断开 60s 内原 client 可拿回、他人拒绝）。
- cmd 信号处理：双端 SIGINT/SIGTERM 优雅退出（码 0），第二次信号强退（130）。
- 测试：manager 退避/永久停止/优雅取消/退避增长/分类；重连重注册+转发恢复；踢旧会话；端口预留（owner 拿回、thief 拒绝）；client 发起 shutdown 摘 listener；**浸泡测试**（快速断连循环无 goroutine 泄漏，真实 client 多轮连接-转发-关闭无泄漏）。
- 修复：manager 对 Session 错误未先分类导致 fatal 被当临时重连（乒乓根因）。
- 文档：[docs/conn-manager-state.md](docs/conn-manager-state.md) 状态机。

### Added（Phase 5 — TCP Tunnel MVP）

- `internal/tunnel`：Server Manager（注册/端口仲裁/Public Listener/conn_id=CSPRNG 128-bit pending 表 10s 超时清理/ClaimData 认领）；Client（回源 ACL allowed_targets 校验、解析-校验-dial 同 IP 防 DNS rebinding、mTLS 数据连接 + open_data 首帧）；splice 双向 io.CopyBuffer 32KiB + half-close 状态机（2 goroutine + owner，关闭集中、空闲 5min）。
- 接线：control 首帧分发（client_hello=控制 / open_data=数据）、register/unregister 处理（端口范围/占用/限额基础检查）；clientcore 启动时按 client.toml 注册隧道、open_connection 建数据连接。
- 数据连接复用 control_addr 同端口（mTLS RequireAndVerifyClientCert，CN==控制连接身份）。
- 测试（全本机回环）：echo 端到端、64MiB 大流量字节校验、并发 100 连接、half-close、origin 不可达、回源 ACL 拒绝、goroutine 回落断言。
- 平台经验修复：握手 deadline 在握手完成后必须清除（否则 readLoop 定时超时）；Windows 临时端口 49152+ 不在 policy 范围，测试需在 allowed_ports 内探测端口。

### Added（Phase 4 — Control Protocol、mTLS 传输、Session）

- `internal/protocol`：4B 长度前缀 + JSON 信封（nonce 随机、ts、≤64KiB 超限即断）；§2 全部 13 种消息结构体；逐字段校验器（端口/名称/枚举/地址/限额）；错误码表；版本协商（不符→ERR_VERSION_UNSUPPORTED）；帧编解码可独立 Fuzz。
- `internal/transport`：mTLS Listener/Dialer 工厂（TLS 1.3、RequireAndVerifyClientCert、CA 池多根、VerifyPeerCertificate=吊销+身份）；Conn 包装（write mutex、deadline、PeerID 提取）。
- `internal/session`：client_id→Session 注册表（线程安全、资源计数钩子留 Phase 9）、活跃时间跟踪。
- `internal/control`（Server）：Accept 循环（每 IP 半开连接限制 8 + 10s 握手超时）→ client_hello 校验（CN==client_id、版本）→ server_hello（policy 组装）→ 心跳监督（2×interval+timeout 踢除）→ 断连会话释放。
- `internal/clientcore`（Client）：拨号→握手→收 policy→心跳循环（interval ping / miss_threshold 判死）→ 断线退出（重连 Phase 6）。
- 测试：协议编解码表驱动正反例；**三个 Fuzz 目标各 ≥60s**（DecodeFrame/ValidateMessage/EncodeRoundTrip，合计 1200 万+ 次执行无崩溃）；集成：真实 mTLS 握手+心跳维持、伪造 client_id 拒绝、版本不符拒绝、吊销拒绝、帧超限、心跳超时踢除、断连会话释放。
- 文档：[docs/protocol-state.md](docs/protocol-state.md) 三态状态机；04-protocol-v1.md 校对一致（nonce/ts 自动填充）。

### Added（Phase 3 — Enrollment、Token、签发与吊销）

- `internal/auth`：Enrollment Token（32B crypto/rand → `qen_`+base62 展示、8B token_id）；tokens.json（只存 SHA-256 哈希、0600 原子写、惰性过期清理）；`Consume` 写锁内原子核销（防双花）；`Revoke`；跨进程文件变更重载（独立 `enroll serve` 感知新 token）。
- `internal/enroll`：长度前缀+JSON 帧（4B 头 + 64KiB 上限）；EnrollServer（TLS 1.3，enroll 免客户端证书 / renew 强制 mTLS，吊销握手回调即时生效）；每 IP 限速 5/min + 失败指数封禁；EnrollClient（服务器证书指纹 TOFU/钉扎为信任锚、回验链+CN+公钥）；错误码映射（ERR_TOKEN_INVALID/EXPIRED/USED、ERR_NAME_CONFLICT、ERR_RATE_LIMITED 等）。
- CLI：`server client create-token/list/revoke-token`、`server cert list/revoke`、`server enroll serve`、`client enroll`（token 优先 stdin）、`client cert status`、`client cert renew`（mTLS）。
- `server ca init` 新增 `--san`（control_addr 为通配地址时必填，剔除 0.0.0.0/:: 并告警）。
- 测试：token 一次性/过期/吊销/并发单赢/惰性清理/文件重载；enroll 坏 CSR/CN 冲突/限速；**enroll→mTLS renew→revoke→拒绝全链路（真实 TLS）**；续期新序列号。
- 文档：[docs/operations/enrollment.md](docs/operations/enrollment.md)；01-architecture.md 目录树与依赖补 `internal/enroll`。
- 依赖：新增 `golang.org/x/time`（限速，白名单内）。

### Added（Phase 2 — PKI 与跨平台私钥安全存储）

- `internal/pki`（纯标准库）：Ed25519 自签 Root CA（128-bit 随机序列号、CertSign|CRLSign）；PKCS#10 CSR（CN=`cl_`+base32 小写 client_id、OU=name）；客户端证书签发（CSR POP 校验、仅 Ed25519、CN 格式、随机序列号、ClientAuth EKU、NotBefore-5min、NotAfter 截断到 CA 期）；服务器证书（ServerAuth + SAN IP/DNS）；解析/校验/序列化/指纹（SHA-256 冒号格式）/到期判断；吊销列表与客户端登记（原子写 + 线程安全）。
- `internal/platform/keystore`：`Store` 接口（Get/Set/Delete/List）+ 三实现——keyring（wincred/Keychain/SecretService）、file（0700 目录/0600 文件/属主校验/拒符号链接/Unix O_NOFOLLOW/原子写/并发安全）、mem（测试）；keyring 失败自动降级 file（warn 不含敏感信息）；`--keystore-backend auto|keyring|file` 偏好；Windows 仅当前用户 ACL（属主 SID 校验 + DACL）。
- CLI：`server ca init`（幂等，`--force` 覆盖并警告）、`client cert init`（私钥入 keystore、client_id、CSR 输出，`--name/--note/--csr-out/--secrets-dir/--keystore-backend`）。
- 测试：签发-解析-校验往返、篡改/错算法（RSA）/非法 CN 的 CSR 拒绝、50 张序列号唯一、NotAfter 截断、吊销持久化（0600）、keystore 契约（mem/file/keyring-file）、权限断言、符号链接攻击（Unix）、属主拒绝、keyring→file 降级。
- 文档：[docs/operations/pki.md](docs/operations/pki.md) 操作手册初稿。
- 依赖：新增 `99designs/keyring`、`golang.org/x/sys`；jose2go 提升至 v1.7.0（修复 GO-2023-2409/GO-2025-4123）。
- CI：Go 版本升至 1.26（覆盖标准库 GO-2026-5972，asn1 递归 DoS）。

### Added（Phase 1 — 项目骨架、Config、Logging、CLI 基础）

- Monorepo 骨架：`go.mod`（Go 1.22，模块 `github.com/hidxt/qoqtun`）、`cmd/server`、`cmd/client`（cobra 薄壳）、`internal/config`、`internal/logging`、`internal/platform`（占位）。
- `internal/config`：server/client 全量结构体与校验（端口范围 / CIDR / RFC1123 主机名 / tunnel 名正则 / allowed_ports 与监听端口不重叠 / local_ip 禁通配组播链路本地 / 绝对路径禁 `..` 逃逸）；严格 TOML 解析（未知字段报错）；合并器 `Resolve`（CLI flag > ENV `QOQTUN_*` > 配置文件 > 默认值，数组字段不支持 ENV）；部分文件按字段叠加默认值，显式零值（如 `enroll_addr = ""`）保留。
- `internal/logging`：slog 封装（level/format/file，0640 日志文件）；Redaction Handler（key 黑名单 + 长 hex/base64 值模式）；`Secret` 类型（`String()` → `***`）。
- CLI：`server run`（占位）、`server check-config`、`client run`（占位）、`client check-config`、`client cert/enroll/tunnel`（占位）；check-config 解析 + 校验 + 脱敏打印生效配置，退出码 0/1。
- CI 基础：[scripts/check.sh](scripts/check.sh)（fmt/vet/build/三平台交叉编译/test/race 一键）；[.github/workflows/ci.yml](.github/workflows/ci.yml)（三 OS 构建 + 测试，race 在 ubuntu/macos）。
- 测试：config 正反例表驱动（覆盖 84.1%）、redaction 单测（81.8%）、check-config 集成（示例配置通过 + 10+ 畸形配置报错）、部分文件合并与显式零值回归测试。
- 文档一致性修复：05-config-schema.md 与 examples 中 `[identity]`/`[tls]` 空表头改为注释（严格模式拒绝未知字段，空表头不可出现）。

### Added（Phase 0 — 需求冻结、架构与文档落地）

- 仓库文档骨架：`README.md`（定位 / 特性 / 架构 / License 声明）、`SECURITY.md`（威胁模型摘要、安全设计要点、漏洞披露流程占位）、`CHANGELOG.md`。
- `.gitignore`：覆盖私钥 / 证书 / CA / 状态 / Token / `.env` / 日志 / 构建产物 / IDE 杂物。
- V1 范围冻结清单：[docs/plan/v1-scope-freeze.md](docs/plan/v1-scope-freeze.md)；V1 外想法收纳处 [docs/plan/future.md](docs/plan/future.md)。
- 示例配置：[examples/server.example.toml](examples/server.example.toml)、[examples/client.example.toml](examples/client.example.toml)（敏感字段均为占位符）。
- `docs/operations/` 目录骨架（运营文档占位）。

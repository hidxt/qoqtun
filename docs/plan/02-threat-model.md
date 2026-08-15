# qoqtun Threat Model（V1）

## 0. 资产与信任边界

**资产**：CA 私钥、Server/Client 私钥与证书、Enrollment Token、Client 身份（client_id/名称/备注）、转发数据本身、内网拓扑信息、Server 可用性、配置文件。

**信任边界**：
1. Internet ⇄ Server Public/Control/Enroll Listener（完全不可信）
2. Server ⇄ Client 之间链路（视为可被监听/篡改，靠 mTLS 消除）
3. Client ⇄ Local Service（回环或内网，半可信——Client 本身可能被攻陷）
4. Server 管理员 ⇄ Server 本机（可信，但需防配置注入与权限提升）
5. 构建机/依赖仓库 ⇄ 发布产物（供应链边界）

**攻击者画像**：公网扫描者、能监听/篡改链路的中间人、持有泄露 Token 者、被盗设备持有者、**已认证但恶意的合法客户端**（重点！内网穿透最大威胁）、恶意 Server 运营者（对 Client 的威胁，V1 通过证书锁定 Server CA 缓解）。

---

## 1. 威胁清单（攻击面 / 影响 / 缓解 / 剩余风险）

### T1 MITM（中间人）
- **面**：Control/Data/Enroll 所有网络连接。
- **影响**：窃听转发数据、篡改流量、冒充 Server 或 Client。
- **缓解**：全链路 TLS 1.3 + mTLS；Client 钉死 Server CA（只信任本实例 CA，不用系统根证书池）；禁回退明文；`tls.Config` 显式 MinVersion、禁 Renegotiation；证书含 client_id 绑定。
- **剩余**：CA 私钥失窃则全盘失守 → 见 T16/T17 缓解（离线保存建议、轮换预案）。

### T2 重放攻击
- **面**：握手消息、Enrollment 请求、Tunnel 注册、控制指令。
- **缓解**：TLS 本身防传输层重放；Enrollment Token 一次性+短时效+服务端核销记录；控制消息含单调递增 `seq` 与随机 `nonce`，Server 拒绝重复/乱序握手；`OpenDataConnection` 的 `conn_id` 为 128-bit 随机且单次有效、10 秒未认领即废。
- **剩余**：极低（连接内重放由 TLS sequence 兜底）。

### T3 连接劫持（Data Connection 冒领）
- **面**：`OpenDataConnection{conn_id}` 被攻击者抢先/伪造提交。
- **缓解**：数据连接同样强制 mTLS（客户端证书身份必须 == 控制连接身份）；conn_id 为 CSPRNG 128-bit、一次性、短时窗；冒领者无合法证书则根本无法完成 TLS 握手。
- **剩余**：可忽略。

### T4 证书复制/盗取（设备丢失、磁盘被拷）
- **面**：Client 私钥存储、备份系统、二手设备。
- **缓解**：系统安全存储优先（wincred/Keychain/Secret Service）；文件降级 0600+0700+O_NOFOLLOW+原子写；文档引导全盘加密；失窃后 `server cert revoke <serial>` 立即吊销，Server 握手时查吊销列表；证书短有效期（默认 90 天）限制窗口。
- **剩余**：失窃到吊销之间存在窗口（分钟~小时级），由管理员响应时间决定；V2 考虑 OCSP/短 CRL 分发缩短。

### T5 客户端伪造（无证书伪造身份）
- **面**：Control 握手、Enrollment。
- **缓解**：无有效客户端证书无法完成 mTLS；client_id 从证书 CN/SAN 提取而非客户端自报；Enrollment 必须持有效一次性 Token。
- **剩余**：可忽略。

### T6 恶意合法客户端 ⭐
- **面**：合法证书持有者发起非法端口映射、SSRF、内网扫描、Tunnel Flood、UDP Flood、资源耗尽。
- **缓解（Server 端强制，不信任 Client 自律）**：
  - 端口范围 ACL：`allowed_ports` 白名单区间，越界拒绝注册；
  - Tunnel 数上限 / 每客户端并发连接上限（信号量）；
  - 带宽限速（token bucket，per-client & per-tunnel）；
  - UDP Session 数上限 + 空闲超时；
  - 目标白名单：Server 下发 `allowed_targets`（IP/CIDR/端口），**Client 侧 dial 前校验 + Server 侧记录审计**（Client 被篡改时白名单失效，但此时威胁等同 T6 已认证滥用，Server 侧的连接数/带宽/端口/流量审计仍兜底）；
  - 行为审计日志（注册/拒绝/超额事件全部落日志）。
- **剩余**：客户端只能滥用其被授权的范围（端口×带宽×连接数），无法越界；剩余风险 = 授权策略本身的宽严，属运营决策。

### T7 非法端口映射 / 端口抢占
- **面**：RegisterTunnel 请求低端口、已占用端口、他人端口。
- **缓解**：`allowed_ports` 区间校验；端口独占注册（同端口后注册者拒绝）；禁 0/通配；Server 以非 root 运行时根本绑不了 <1024（除非显式授予 capability，属管理员显式决策）。
- **剩余**：低。

### T8 SSRF / 内网扫描（经 Client 回源）
- **面**：公网用户通过 Tunnel 触达 `local_ip:local_port`；恶意 Client 配置把 Tunnel 当跳板。
- **缓解**：`local_ip` 必须是字面 IP 或显式允许的主机名（Client 侧解析后按 IP 校验白名单，防 DNS rebinding——解析-校验-dial 同一结果，禁二次解析）；默认仅允许回环与 RFC1918 显式列出的目标；禁止 0.0.0.0、链路本地、组播目标（除非白名单显式包含）；连接速率限制天然压制扫描。
- **剩余**：白名单配置过宽则风险回归运营侧。

### T9 DoS / Connection Flood / Tunnel Flood / UDP Flood
- **面**：Public Listener（未认证洪泛）、Control/Enroll Listener（半认证洪泛）。
- **缓解**：
  - 全局每 IP 连接速率限制 + 并发半开连接上限（未认证连接 10s 总超时）；
  - 每 Tunnel 并发连接信号量，满则快速拒绝（不排队）；
  - Register/Unregister 频率限制；
  - UDP：每 IP 包速率、Session 上限、单包 ≤ 配置的 max（默认 1500）；
  - 读超时/写超时/空闲超时全覆盖（无永不超时的连接）；
  - 消息大小上限（控制帧 ≤64KiB）+ 解码前长度检查。
- **剩余**：超大流量 L3/L4 洪泛超出软件能力，属上游/机房层防护范畴（文档说明）。

### T10 资源耗尽 / Goroutine / FD 泄漏
- **面**：慢连接、异常断连、半关闭悬挂、攻击者制造大量悬挂连接。
- **缓解**：每连接 goroutine 配对有 owner 与 `context` 生命周期；所有 dial/read/write 带 deadline；半关闭显式状态机，双方向 EOF 后才释放；`SetLimit`（RLIMIT_NOFILE）检测与启动告警；每个公共资源（端口、信号量、session 槽位）都有获取上限与释放路径；`go test -race` + 压力测试 + pprof 端点（默认关，绑定 127.0.0.1）。
- **剩余**：极低概率的边界泄漏由压力测试与竞态检测兜底。

### T11 配置注入（TOML 恶意字段/路径）
- **面**：server.toml/client.toml、CLI 参数、ENV。
- **缓解**：严格模式解析（未知字段报错）；所有字段类型/范围校验（端口 1-65535、CIDR 合法、隧道名 `^[a-zA-Z0-9_-]{1,64}$` 等）；配置永不拼接进 Shell；路径字段清洗并禁止穿越（见 T12）；`check-config` 在启动前暴露问题。
- **剩余**：低。

### T12 路径遍历
- **面**：证书/密钥/日志/配置/状态文件的读写路径。
- **缓解**：所有路径经 `filepath.Clean` + 禁止包含 `..` 逃逸出指定基目录（逐段校验）；打开前 `Lstat` 拒符号链接（敏感文件）；Unix 用 `O_NOFOLLOW`；写敏感文件一律 tmp+fsync+rename 原子写；不以高权限身份读用户可控路径。
- **剩余**：低。

### T13 命令注入
- **面**：本设计无任何 Shell 执行点。
- **缓解**：代码层面禁止 `os/exec`（CI 加 grep 检查：非测试代码出现 `os/exec` 即失败）。
- **剩余**：可忽略。

### T14 日志泄密
- **面**：日志中出现私钥/Token/证书 PEM/内网敏感信息。
- **缓解**：slog Redaction Handler 统一过滤（key 名黑名单 + 值模式匹配）；`Secret` 类型封装敏感值（`String()` 输出 `***`）；单元测试断言日志无泄露；默认日志不含转发的用户数据载荷。
- **剩余**：管理员把日志级调到 trace 可能记录更多元数据（仍不含密钥）——文档警示。

### T15 权限提升
- **面**：Server 进程权限、低端口绑定、文件权限。
- **缓解**：文档与 systemd unit 默认非 root 专用用户；低端口用 `setcap CAP_NET_BIND_SERVICE` 而非 root；启动时如检测到 root 且配置未显式允许则告警/拒绝；所有自写文件 0600/0640，目录 0700/0750；不使用 setuid。
- **剩余**：低。

### T16 供应链攻击
- **面**：go.mod 依赖、Wails 前端依赖、CI、发布产物。
- **缓解**：依赖白名单制度（见 01 文档取舍表）；`govulncheck ./...` 纳入阶段验收；`go mod verify`；vendor 或 GOPROXY 校验和；发布产物带 SHA256 校验和 +（后续）cosign 签名；Dependabot/Renovate 提示但人工评审升级。
- **剩余**：间接依赖 0day，靠最小依赖面+漏洞扫描缩短暴露窗。

### T17 Token / 私钥 / CA Key 泄露
- **面**：终端历史、截图、备份、git 误提交、CI 日志。
- **缓解**：Token 仅创建时打印一次，服务端存 SHA-256；`server client create-token` 输出附带"立即使用，过期 X"提示；.gitignore 预置全套敏感模式；每个阶段做 secret scan（gitleaks 或等效 grep）；CA key 0600 + 文档建议离线/加密备份；泄露响应：Token 可 `revoke`、证书可吊销、CA 泄露走 CA Rotation 预案。
- **剩余**：CA key 泄露=重建信任域，属灾难级，靠物理/备份纪律缓解。

### T18 恶意 Server 对 Client 的威胁
- **面**：Server 运营者可读全部转发明文（架构固有）；伪造 Server 诱骗 Client。
- **缓解**：Client 只信任自己的 CA 签发的 Server 证书（证书钉扎）；文档明确"内网穿透=信任 Server 运营者"的信任模型；敏感业务应在 Tunnel 之上自带端到端加密（如 HTTPS 后端）。
- **剩余**：固有，靠文档明示。

---

## 2. 全局原则
1. 服务端永远是策略执行点，客户端配置只是"申请"。
2. 失败即关闭（fail-closed）：校验不过=拒绝，不是放行。
3. 所有限额都有默认值，不存在"无限"。
4. 每个攻击面都有对应自动化测试（认证失败、越界注册、洪泛、畸形消息 Fuzz）。

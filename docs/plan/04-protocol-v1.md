# qoqtun Protocol v1

设计目标：**简单、稳定、安全、容易测试**。所有网络代码必须遵守本文档的大小限制、超时与错误处理约定。

## 0. 编码方案选型（已决策）

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| JSON (stdlib) | 可读、可调试、零工具链、map 结构天然向前兼容 | 体积大、解析慢 | ✅ **控制面采用**——消息频率极低（握手/注册/心跳/开关连接），性能无关痛痒 |
| Protobuf | 紧凑、强 schema | protoc 工具链、生成代码、调试不直观 | ❌ 引入工具链依赖，V1 不值得；未来高吞吐场景可平移（消息体抽象留出可能） |
| MessagePack | 紧凑、无 schema | 调试差、多一个依赖 | ❌ 收益小，违背少依赖原则 |

**数据面**：纯字节流直通（splice 后就是 `io.Copy`），与编码无关——所以控制面选 JSON 没有任何性能代价。
**帧格式**：`[4 字节 big-endian 长度][JSON 载荷]`，长度 **≤ 64 KiB**，超限立即关闭连接并记录。解码：`json.Decoder` + `DisallowUnknownFields=false`（未知字段忽略以向前兼容，但**必填字段缺失=协议错误**）。

## 1. 三种连接的关系

```
Client ─────────────────────────── Server
  │
  ├── 1 条 Control Connection（mTLS 长连接）
  │     用途：握手认证、策略下发、Tunnel 注册/注销、OpenConnection 通知、心跳、优雅关闭
  │
  └── N 条 Data Connection（mTLS 短连接，按需建立）
        每条对应一个"公网连接 ⇄ 本地连接"的转发对（TCP/HTTP）
        UDP 见 §6（每 client+目标 一条 UDP 数据通道内做 session 复用）

  Tunnel Connection ≠ 独立连接：Tunnel 只是控制面上的逻辑注册项（tunnel_id），
  其流量由动态建立的 Data Connection 承载。
```

- 所有连接强制 TLS 1.3 + mTLS（客户端证书身份 == 控制连接身份，Server 校验一致）。
- Control 断开 → 该 client 所有 Tunnel 的 Public Listener 摘除、进行中的 Data Connection 按优雅关闭处理。

## 2. 消息目录（控制面）

公共信封：`{"version":1, "type":"...", "seq":<uint64>, "nonce":"<16B hex>", "ts":<unix_ms>, "payload":{...}}`
- `seq`：每方向独立单调递增，防重放/乱序；`nonce`：每条消息随机。

| type | 方向 | payload 关键字段 | 说明 |
|---|---|---|---|
| `client_hello` | C→S | client_id(从证书提取校验一致性), protocol_version, name, note, capabilities[] | 握手首条消息，10s 超时 |
| `server_hello` | S→C | session_id, policy{allowed_ports, max_tunnels, max_conns, bandwidth_bps, udp{max_sessions, max_packet, session_idle_timeout}, allowed_targets[]}, heartbeat{interval_s, timeout_s, miss_threshold} | 含全部策略 |
| `register_tunnel` | C→S | name, type(tcp/udp/http/https), remote_port, local{ip,port}, 可选 http{host} | 申请注册 |
| `register_tunnel_resp` | S→C | tunnel_id, ok, error?, effective{remote_port, limits} | 拒绝附 error code |
| `unregister_tunnel` | C→S | tunnel_id | 主动下线 |
| `open_connection` | S→C | conn_id(128-bit hex), tunnel_id, src_addr, deadline_ms | 通知 client 建立数据连接 |
| `close_connection` | 双向 | conn_id, reason | 统计落账点 |
| `ping` / `pong` | 双向 | echo | 心跳（见 §4） |
| `policy_update` | S→C | policy | 运行期策略变更（V1 可仅支持重连生效，消息先定义） |
| `shutdown` | 双向 | reason, drain_timeout_ms | 优雅关闭协商 |
| `error` | 双向 | code, message, fatal | 统一错误（错误码表见 §5） |

数据面首帧（Data Connection 建立后第一条消息，同样长度前缀 JSON）：
`{"type":"open_data","conn_id":"...","tunnel_id":"..."}` —— 之后即纯字节流。

## 3. TCP Tunnel 完整流程

1. `register_tunnel(tcp, remote_port=8080)` → Server ACL 检查（端口范围/占用/Tunnel 数）→ 起 Public Listener → `register_tunnel_resp{ok}`。
2. 公网连接到达 → Server：`conn_id=rand128` → 占住连接（设置总超时）→ 控制面 `open_connection`。
3. Client：校验 tunnel_id 存在 → dial 本地目标（**先 ACL 校验 local_ip:port**；目标解析-校验-dial 一致性防 DNS rebinding）→ 建立 mTLS Data Connection → 首帧 `open_data{conn_id}`。
4. Server 匹配 `conn_id`（10s 未认领即关闭公网连接）→ splice 双向 `io.Copy`。
5. 超时：空闲读超时（默认 5min，隧道可配）、dial 超时 10s、首帧超时 10s。
6. Half-Close：一侧 EOF → 关闭对端写方向（`CloseWrite`）但继续读，直到对向也 EOF 或空闲超时 → `close_connection`（含字节数统计）。
7. 背压：`io.CopyBuffer` 32KiB buffer，TCP 流控天然传导；不做应用层窗口（V1）。
8. 优雅关闭：`shutdown` → Server 停 Public Listener（不接新）→ 等待进行中的连接 drain（默认 30s 上限）→ 强关残余。

## 4. 心跳与断线检测

- Client 每 `interval_s`（默认 15s）发 `ping`，等待 `timeout_s`（默认 10s）。
- 连续 `miss_threshold`（默认 2）次未收 `pong` → 判定断线 → 关闭控制连接 → 走重连流程（指数退避：1s 起步 ×2，上限 60s，±20% jitter）。
- Server 侧：`2×interval + timeout` 无消息即踢除会话，释放端口与限额。
- **错误分类**：认证失败/证书吊销/过期 = 永久错误 → 停止重连并明确报错（禁止快速无限重试）；网络错误 = 临时错误 → 退避重连。

## 5. 错误码（`error.code`）

```
ERR_PROTOCOL            协议错误（帧过大/字段缺失/类型错误）→ 关连接
ERR_VERSION_UNSUPPORTED 版本不支持
ERR_AUTH_FAILED         mTLS 失败后的应用层拒绝（吊销/未登记）
ERR_CERT_EXPIRED / ERR_CERT_REVOKED
ERR_TOKEN_INVALID / ERR_TOKEN_EXPIRED / ERR_TOKEN_USED
ERR_PORT_NOT_ALLOWED / ERR_PORT_IN_USE
ERR_TUNNEL_LIMIT / ERR_CONN_LIMIT / ERR_RATE_LIMITED / ERR_UDP_SESSION_LIMIT
ERR_TARGET_NOT_ALLOWED  回源目标违反白名单
ERR_NAME_INVALID / ERR_NAME_CONFLICT
ERR_INTERNAL            服务端内部错误（不含敏感细节）
```
错误消息不得包含内部路径、堆栈、密钥材料。

## 6. UDP 方案

- 每个 UDP Tunnel：Server 起 UDP Public Listener；Client 建立 **1 条 mTLS-over-TCP 的 UDP 数据通道**（V1 简化：UDP 封装在 TCP 数据通道内，长度前缀帧：`[4B len][session_id(16B)][payload]`）。未来 QUIC 版本可原生 UDP，协议字段已留 `transport`。
- Session 映射：key = `(tunnel_id, 公网对端 addr)` → `session_id`；每 session 对应一条到 `local_ip:local_port` 的 UDP "连接"。
- 超时：session 空闲 60s（policy 可调）回收；映射表满（`max_sessions`，默认 256/tunnel）→ 丢弃最久未活跃（并计数告警）。
- 包大小：`max_packet` 默认 1500（上限 65507），超限丢弃。
- 防滥用：每公网 IP 包速率限制；session 创建速率限制；全部走 Server 端强制。

## 7. HTTP/HTTPS 方案（V1 决策）

- **HTTPS = 纯 L4 Passthrough**：`type=https` 等价于 TCP Tunnel（不解密、不终止，无 SNI 路由——V1 每个 HTTPS tunnel 独占一个公网端口）。复杂度最低、最安全（端到端 TLS 不过 Server）。
- **HTTP = 轻量 L7 路由 + 流式透传**：`type=http` 支持在同一 `http_vhost_port`（Server 级一个共享端口，如 80/8080）上按 `Host` 头路由到不同 tunnel：
  - Server 解析首个请求的 HTTP/1.1 `Host`（只读必要头部，≤8KiB，非完整 HTTP 代理），匹配 tunnel 的 `http.host` 规则（精确或后缀）；
  - 匹配成功后把已读字节原样前置，转为该 tunnel 的数据连接，之后纯字节透传（WebSocket/长连接天然支持）；
  - 无匹配 → 421/404 响应并关闭；解析超时 5s。
  - **不做**：HTTP 头改写（可选 `X-Forwarded-For` 注入，V1 默认关）、缓存、压缩、HTTPS 终止。
- 这样 HTTP 复用单端口、HTTPS 独占端口，复杂度可控且满足"对标 frp 体验"的核心场景。

## 8. 版本与扩展预留

- 信封 `version` 字段 + `client_hello.protocol_version`；不兼容升级 → `ERR_VERSION_UNSUPPORTED`。
- 消息未知字段忽略；新增消息类型对端不识别 → `ERR_PROTOCOL`（可恢复）。
- 预留扩展点：`capabilities[]`、`tunnel.type` 枚举、`open_connection.transport`（tcp_mux/quic/p2p 未来值）、`policy` 可扩展字段——**只留字段，不实现逻辑**。

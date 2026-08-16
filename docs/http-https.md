# HTTP / HTTPS Tunnel 语义（Phase 8）

## 行为矩阵：什么场景用哪种 type

| 场景 | type | remote_port | http_host | 公网形态 | 说明 |
|---|---|---|---|---|---|
| 多个 HTTP 站点共用端口 | `http` | 0 | 必填 | 共享 `http_vhost_port`，按 Host 路由 | Server 级一个共享监听（默认 80/8080 类端口） |
| 单个 HTTP 服务独占端口 | `http` | >0 | 可选 | 独立 TCP 端口 | 退化为纯 TCP 语义（字节透传） |
| HTTPS / 任意 TLS 服务 | `https` | >0（必填） | 忽略 | 独立 TCP 端口 | **纯 L4 Passthrough**：端到端 TLS 不过 Server，无 SNI 路由，每 tunnel 独占端口 |
| 非 HTTP 协议（SSH/RDP/数据库） | `tcp` | >0 | 忽略 | 独立 TCP 端口 | 见 Phase 5 文档 |

## HTTP vhost 路由（type=http + remote_port=0）

- Server 在 `listen.http_vhost_port` 上共享监听；**首个** vhost tunnel 注册时启动，最后一个注销/断连时关闭（引用计数）。
- 请求进入后只做**轻量 L7 嗅探**：解析首个请求的请求行 + 头部，读到 `Host` 头即停（≤8KiB、5s 超时）。**不是完整 HTTP 代理**，不解析 body、不改写头部（V1 默认无 X-Forwarded-For）。
- Host 匹配：精确优先，其次最长后缀（`example.com` 规则命中 `www.example.com`，不命中 `badexample.com`）；大小写、`:port`、尾点均归一化。
- 匹配成功：已读字节**原样前置回放**（`ReplayConn`），之后纯字节透传 → WebSocket 升级、SSE 长连接天然支持。
- 无匹配 → `HTTP/1.1 421 Misdirected Request` 关闭；嗅探失败/超时/超大 → `400` 关闭。
- 同 Host 二次注册 → 后注册方拒绝（`ERR_NAME_CONFLICT`）。

## 嗅探的保守策略（fail-closed）

| 输入 | 行为 |
|---|---|
| 请求行/头累计 > 8KiB | 拒绝（`400`） |
| 5s 内未完成头解析（slowloris） | 连接按 deadline 清理，不堆积 |
| obs-fold 续行头 | 拒绝 |
| Host 非法（非 RFC1123 标签、IPv6 literal、空） | 拒绝 |
| 无 Host（含 HTTP/1.0 无绝对 URI） | 拒绝 |
| 请求行为绝对 URI（`GET http://host/path`） | 从 URI 提取 authority |

## HTTPS L4 透传（type=https）

- 等价 TCP Tunnel 别名：服务器只转发字节，**不终止 TLS、无 SNI 路由、无证书校验**。
- 穿透后客户端观察到的对端证书 = 后端原始证书（测试 `TestHTTPVhostHTTPSPassthrough` 断言）。
- 安全含义：Server 无法查看明文；证书信任链完全由客户端与后端自行建立。

## 安全注意

- vhost 端口对公网开放且无认证——嗅探器是唯一防线：限长、限时、保守解析、无缓冲堆积（slowloris 兜底，测试 100 并发半开连接）。
- 无 `X-Forwarded-For` 等头注入：后端无法感知穿透存在（隐私默认）。
- `https` 不允许 remote_port=0：V1 无 SNI 路由，独占端口是唯一形态。

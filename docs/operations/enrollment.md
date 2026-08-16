# qoqtun Enrollment 操作手册

> 覆盖 Token 生命周期与在线签发/续期/吊销操作；设计见 [docs/plan/03-pki-enrollment.md](../plan/03-pki-enrollment.md) §3–§6。

## 0. 前提

1. `qoqtun-server ca init --config server.toml --san <公网IP/DNS>` 已完成（SAN 必须包含客户端可访问的地址；`control_addr` 为 `0.0.0.0` 通配时必须在 `--san` 显式给出，否则 `ca init` 拒绝）。
2. `client cert init` 已生成客户端私钥（平台安全存储）与 CSR。

## 1. 一次性 Enrollment Token

```sh
qoqtun-server client create-token --config server.toml --ttl 1h --created-by admin
# Enrollment token (use once, expires in 1h):
#   qen_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- **Token 只在创建时打印一次**；服务端只保存 SHA-256 哈希。
- TTL 默认 1h，上限 24h；一次性：核销后立即失效（并发请求只放行一个）。
- 撤销：`qoqtun-server client revoke-token <token_id>`（token_id 可在 tokens.json 中查看）。
- **注意（独立 serve 形态）**：`server client create-token` 与 `server enroll serve` 是独立进程；serve 会在每次请求时感知 token 文件变化并自动加载，但**不要在 serve 运行期间并发执行 create-token 与核销**（文件级写入互斥由 Phase 4 单进程架构消除）。

## 2. 启动在线签发

```sh
qoqtun-server enroll serve --config server.toml
```

- TLS 1.3 监听 `listen.enroll_addr`（默认 7001，可关闭）。
- enroll 端点不要求客户端证书；renew 端点要求 mTLS（证书链到本 CA 且未吊销）。
- 每 IP 限速 5 次/分钟，连续失败指数封禁（5s→10s→…，上限 24h）。

## 3. 客户端在线注册

```sh
qoqtun-client enroll --server 203.0.113.5:7001 \
    --csr client.csr --token qen_XXXX              # 或用 stdin 输入 token 避免进 shell history
    # 首次连接可 --ca-fingerprint 钉扎；未提供则 TOFU 记录并提示核对
```

- 客户端回验服务端返回的证书链：链到响应中的 CA、CN==本地 client_id、公钥==本地私钥。
- 产出：`client.crt`（0644）、`ca.crt`（0644）、状态文件 `state.json`（0600，含 client_id / 服务器地址 / CA 指纹 / 到期时间）。
- 信任锚：服务器证书指纹（TOFU 首次记录，之后每次连接比对；`--ca-fingerprint` 可预置钉扎）。

## 4. 续期

```sh
qoqtun-client cert renew --csr client.csr   # mTLS 通道，自动携带现有证书
```

- 服务端校验旧证书有效且未吊销 → 签发新序列号证书 → 更新登记。
- 证书过期后无法续期：重新走 Token 注册（文档明示运维路径）。

## 5. 查看与吊销

```sh
qoqtun-server client list              # 已登记客户端（clients.json）
qoqtun-server cert list                # 证书序列号/状态/归属
qoqtun-server cert revoke <serial> --reason "device lost"
qoqtun-client cert status              # 本机身份/到期/CA 指纹
```

- 吊销写入 `revoked.json`（0600，原子更新），**对下一个 TLS 握手立即生效**（mTLS 握手回调查吊销表）。

## 6. 安全注意

- Token 是秘密：勿贴到聊天/日志/CI；服务端与日志只存哈希。
- `tokens.json` / `clients.json` / `revoked.json` 均 0600 且原子写；私钥只存在于 keystore。
- enroll 失败日志不含 token 值与内部路径。

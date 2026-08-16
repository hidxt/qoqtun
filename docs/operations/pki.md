# qoqtun PKI 操作手册

> 本文档覆盖 PKI 相关运维操作；设计细节见 [docs/plan/03-pki-enrollment.md](../plan/03-pki-enrollment.md)。私钥与证书存储布局（全部禁止进 Git）：

```
<server_state_dir>/
  ca/ca.key          # 0600，CA 私钥（最高机密）
  ca/ca.crt          # 0644
  server/server.key  # 0600
  server/server.crt  # 0644
  revoked.json       # 0600，吊销列表
  clients.json       # 0600，客户端登记
```

客户端私钥存放于平台安全存储（wincred / Keychain / Secret Service），降级路径为 `<user-config>/qoqtun/secrets/`（0700 目录、0600 文件、仅当前用户）。

## 1. 初始化服务器身份（一次性）

```sh
qoqtun-server ca init --config server.toml
```

- 生成 Ed25519 Root CA（10 年）+ 服务器证书（SAN 取自 `listen.control_addr`），写入 `state_dir`。
- **幂等保护**：已存在 CA 时拒绝，需 `--force`（覆盖会使全部现有客户端证书失效，生产慎用）。
- 完成后记录输出的 **CA 指纹**（客户端首次连接/注册时的信任锚，可后续 `client enroll` 校验）。

## 2. 客户端身份初始化

```sh
qoqtun-client cert init --name my-nas --csr-out client.csr
# 可选：--keystore-backend keyring|file（默认 auto：系统安全存储优先，失败自动降级 file）
# 可选：--secrets-dir <dir>（file 降级路径，默认 <user-config>/qoqtun/secrets）
```

- 私钥本地生成，**永不上传、永不落明文文件**，存入平台安全存储；
- 生成 `client_id`（`cl_`+26 位 base32），输出 CSR（0644，非敏感）供 `client enroll` 使用（Phase 3）。

## 3. 证书生命周期（Phase 3+ 逐步启用）

| 操作 | 命令 | 说明 |
|---|---|---|
| 在线签发 | `client enroll`（Phase 3） | 一次性短时效 Token + CSR |
| 续期 | mTLS 控制连接自动续期（Phase 6） | 有效期 2/3 处自动 |
| 吊销 | `qoqtun-server cert revoke <serial>`（Phase 3） | 写入 revoked.json，握手即时生效 |
| 列表 | `qoqtun-server cert list` / `client cert status` | 序列号/身份/到期/状态 |

## 4. 备份与灾难恢复

- **必须备份**：`<state_dir>/ca/ca.key`、`ca/ca.crt`、`clients.json`。建议离线/加密备份。
- **CA 私钥丢失** = 信任域重建：所有客户端必须重新 enroll（文档写明）。
- 客户端私钥丢失：重新 `cert init` + `enroll`，并在服务端吊销旧证书。

## 5. 安全注意

- `ca.key` / `server.key` 权限必须 0600，目录 0700；禁止复制进 Git、聊天、CI。
- 吊销列表 `revoked.json` 与登记 `clients.json` 为 0600。
- 平台降级路径做了属主校验与符号链接拒绝（Unix `O_NOFOLLOW`；Windows 属主 SID + 仅当前用户 ACL），如遇"owner mismatch"报错请检查目录是否被他人预置。

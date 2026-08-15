# qoqtun PKI 与 Enrollment 方案

原则：**私钥永远不出设备；服务端只存"可验证的东西"（证书、公钥、Token 哈希），不存秘密本身。** 全部使用 `crypto/x509`、`crypto/tls`、`crypto/rand`，禁止自研任何加密原语。

## 1. CA 结构（V1）

- 每个 Server 实例一个 **Root CA**：Ed25519 自签，有效期 10 年，`IsCA=true, KeyUsage=CertSign|CRLSign`，128-bit 随机序列号。
- CA 直接签发：Server 证书（1 张，TLS ServerAuth）、Client 证书（N 张，TLS ClientAuth）。
- 不做中间 CA（V1 复杂度控制）；CA Rotation 通过"双 CA 并行信任"完成（见 §6）。
- 存储布局（全部禁止进 Git）：
  ```
  <server_state_dir>/
    ca/ca.key        # 0600，CA 私钥
    ca/ca.crt        # 0644
    server/server.key# 0600
    server/server.crt# 0644
    certs/<serial>.crt   # 已签发客户端证书存根 0644
    revoked.json     # 吊销列表（serial + revoked_at + reason）0600
    tokens.json      # Token 哈希存储 0600（见 §3）
    clients.json     # client_id → {name, note, cert_serial, created_at} 0600
  ```

## 2. 客户端身份与密钥生成（`client cert init`）

1. 本地生成 Ed25519 私钥（`crypto/rand`），**永不上传**。
2. 生成 `client_id`：`cl_` + 16 字节随机（base32 小写无歧义字符），仅作标识符，不是秘密。
3. 私钥存入平台安全存储（见 §7）；同时收集 `name`（默认主机名）、`note`（可选备注）——将在 Enrollment 时随 CSR 提交。
4. 生成 PKCS#10 CSR：`Subject.CN = client_id`，`Organization = ["qoqtun-client"]`，Extensions 携带 name/note（自定义 OID 或直接放 `Subject.OrganizationUnit`——V1 决定：OU[0]=name 截断 64 字符，备注不入证书只入服务端登记）。CSR 自签名即"持有私钥证明"（POP）。
5. 输出 CSR 文件（0644，非敏感）供 enroll 使用；同目录不落私钥明文。

## 3. Enrollment Token（`server client create-token`）

属性：**高熵、短时效、一次性、可撤销、防重放**。

- 生成：32 字节 `crypto/rand`，展示格式 `qen_<base62(32B)>`（约 43 字符），**仅创建时在终端打印一次**。
- 存储：服务端只存 `SHA-256(token)` + `token_id`(8B 随机) + `expires_at`（默认 1 小时，上限 24h，CLI 可调）+ `max_uses=1` + `created_by` + `revoked` 标记。
- 校验：enroll 请求中 token → SHA-256 → 查表 → 存在 && 未过期 && 未用 && 未吊销 → **先原子标记 used** 再签发（防并发重用）。
- 撤销：`server client revoke-token <token_id>`；过期清理 goroutine 定期惰性清除。
- 防重放：一次性核销 + TLS 通道 + CSR 自带 POP（攻击者截获 CSR 无用，没有对应私钥过不了 mTLS）。

## 4. Enrollment 流程（`client enroll`）

```
Client                                    Server (Enroll Listener, 独立端口, 可配关闭)
  │── TLS 1.3 握手（验证 Server 证书链到指定 CA；Server 不要求客户端证书）──▶│
  │── EnrollRequest{ token, csr, client_meta{name,note,os/arch} } ─────────▶│
  │                              ① 校验 token（原子核销）                   │
  │                              ② 校验 CSR：签名合法、CN 格式、算法=Ed25519 │
  │                              ③ client_id 冲突检查（已存在则拒绝）         │
  │                              ④ CA 签发：随机 128-bit serial，            │
  │                                 NotAfter=min(now+90d, CA 期),            │
  │                                 KeyUsage=DigitalSignature,               │
  │                                 ExtKeyUsage=ClientAuth                   │
  │◀──────── EnrollResponse{ client_cert, ca_cert, expires_at } ────────────│
  │── 校验收到的证书链回 CA、CN==自己的 client_id、公钥==本地私钥对应公钥 ──   │
  │── 证书落盘 0644；记录到期时间；提示私钥位置 ──                            │
```

- Enroll Listener 默认与 Control Listener **分离端口**（如 7001），可用 `--enroll-addr` 配置、可整体关闭（关闭后只能预先签发导入——V1 可选能力，不强制实现）。
- Enroll 接口带每 IP 速率限制（防 token 暴力枚举：token 空间 256bit，叠加 5 次/分钟/IP 与失败后指数封禁）。

## 5. 证书续期（Renewal）

- 客户端在有效期 2/3 处自动续期：`RenewalRequest{ csr（同私钥或新私钥） }` 走 **mTLS 控制连接**（用现有证书认证）。
- 服务端校验旧证书有效且未吊销 → 签发新证书（新序列号）→ 旧证书到期自然失效（或选择立即吊销旧证书，默认自然失效以降低复杂度）。
- 续期失败（证书已过期）：只能重新走 Token Enrollment——文档明确此运维路径。

## 6. 吊销与 CA Rotation

- `server cert revoke <serial>`：写入 `revoked.json`（含时间/reason），**mTLS 握手回调即时检查**（`VerifyPeerCertificate` 阶段查内存吊销表，启动时从磁盘加载，变更时原子重写文件）。
- `server cert list`：序列号、client_id、name、签发/到期时间、状态。
- CA Rotation 预案（文档级 + 基础命令）：
  1. `server ca rotate`：生成新 CA，新旧 CA 证书合并为信任 bundle，Server 信任双 CA；
  2. 通知窗口期内所有客户端 renew（换绑新 CA 签发的证书）；
  3. 全员迁移后 `server ca retire <old>` 移除旧 CA。
  V1 实现要求：信任源支持"多 CA 池"，rotate/retire 命令允许后续阶段实现，**但握手校验代码必须按 CA 池设计，不得硬编码单 CA**。

## 7. 私钥安全存储矩阵（`internal/platform/keystore`）

| 平台 | 首选 | 降级 |
|---|---|---|
| Windows | wincred（系统凭据管理器，DPAPI 体系） | 0600 等效 ACL 文件（NTFS ACL 仅当前用户） |
| macOS | Keychain | 0600 文件 + 目录 0700 |
| Linux | Secret Service/libsecret（keyring） | 0600 文件 + 目录 0700 |

降级路径统一要求：
- 基目录默认 `~/.config/qoqtun/secrets/`（可被配置覆盖但需校验），目录 0700、文件 0600；
- 打开前 `Lstat` 拒符号链接，Unix 下 `O_NOFOLLOW`；写：同目录 tmp 文件 0600 → fsync → rename（原子）；
- 检测基目录属主必须是当前用户，否则拒绝（防 TOCTOU/预置攻击）；
- 接口抽象：`type Store interface { Get(id string) ([]byte, error); Set(id string, data []byte) error; Delete(id string) error }`，三实现：keyring 后端 / 文件后端 / mem（仅测试）。

## 8. 异常场景预案

| 场景 | 机制 |
|---|---|
| 证书过期 | 控制连接握手失败（错误码 `ERR_CERT_EXPIRED`）→ CLI 明确提示重新 enroll；GUI 状态页红标 |
| 设备丢失 | `server cert revoke <serial>`；吊销立即生效（连接中会话可选立即踢除——V1 默认踢除） |
| 证书泄露 | 吊销 + 排查审计日志 + 视情况 CA rotate |
| 时钟偏移 | 证书校验容忍 ±5min（文档建议 NTP）；NotBefore 留 5min 提前量 |
| 服务端重装 | 引导用户导出/备份 state 目录；丢失=重建 CA=全员重新 enroll（文档写明） |

## 9. CLI 命令清单（本域）

Server 侧：`server ca init` / `server ca rotate`(可延后) / `server client create-token` / `server client list` / `server client revoke-token` / `server cert list` / `server cert revoke`。
Client 侧：`client cert init` / `client enroll` / `client cert status`（显示身份、到期、存储后端）。

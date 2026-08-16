# 安全审计清单（T1–T18 逐项核对）

审计视角：不信任此前实现，以攻击者剧本驱动。每项给出实现证据 + 测试证据 + 状态（✅ 有证据 / ⚠️ 部分 / 📋 已定级记录）。

| 威胁 | 缓解实现证据 | 测试证据 | 状态 |
|---|---|---|---|
| **T1 MITM** | `internal/transport`：TLS 1.3 强制（MinVersion）、mTLS 双向、ClientCAs 独立池（不用系统根）、禁 Renegotiation；Client 钉 Server CA（state 记录 CA 指纹，TOFU+pin） | 协议集成测试（握手/证书验证）；HTTPS 透传证书链断言 | ✅ |
| **T2 重放** | Token SHA-256 哈希+一次性核销（atomic）；控制帧 seq+nonce；conn_id CSPRNG 128-bit 一次性 10s 失效 | `TestTokenOneShot/Expired/Concurrent`；conn_id 认领超时测试 | ✅ |
| **T3 连接劫持** | 数据连接强制 mTLS + 身份必须==控制连接身份；conn_id CSPRNG 单次有效 | 控制面拒绝路径测试 | ✅ |
| **T4 证书盗取** | keystore 系统安全存储优先；文件降级 0600/0700+O_NOFOLLOW+原子写；吊销握手时生效；90 天短效 | `TestFilePermissions`；吊销全链路测试 | ✅ |
| **T5 客户端伪造** | mTLS 强客户端证书；`hello.ClientID != peerID` 拒绝（CN 提取） | 伪造 id 拒绝测试 | ✅ |
| **T6 恶意客户端** ⭐ | Server 强制：allowed_ports 白名单、tunnel/连接数信号量、带宽 token bucket、UDP session 上限、注册频率、allowed_targets 注册时校验+审计 | `TestPolicy*` 全组（限额/带宽/注册频率/ACL） | ✅ |
| **T7 端口映射/抢占** | allowed_ports 区间；同端口后注册拒绝；禁 0/通配（校验）；端口预留 60s 防抢占 | `TestPortReservation`（owner 拿回、thief 拒绝） | ✅ |
| **T8 SSRF/内网扫描** | Client 侧 ACL 前置校验；resolve-once（解析-校验-dial 同一 IP 防 DNS rebinding）；禁 0.0.0.0/链路本地/组播 | ACL 拒绝测试；解析-校验实现核对 | ✅ |
| **T9 DoS/洪泛** | 每 IP 速率+半开上限（10s 超时）；每 tunnel 信号量满即拒；注册频率；UDP pps/session/包大小；全 deadline；帧 ≤64KiB | `TestPolicyFloodAvailability`/slowloris/rate limit；Fuzz 帧解码 | ✅ |
| **T10 资源耗尽** | goroutine owner+ctx；全 deadline；半关闭状态机；fdlimit 检测（--allow-low-fdlimit）；pprof 默认关 127.0.0.1 | soak/goroutine 回落；`TestGuardInjectable` | ✅ |
| **T11 配置注入** | TOML strict 模式（未知字段报错）；全字段校验（端口/CIDR/名称正则）；禁 Shell；check-config | `TestLoadRejectsUnknownFields`；validate 全表测试 | ✅ |
| **T12 路径遍历** | Clean+禁 `..` 逃逸；敏感文件 Lstat 拒符号链接；O_NOFOLLOW（unix）；原子写 tmp+rename | keystore 路径/符号链接测试 | ✅ |
| **T13 命令注入** | 生产代码 os/exec 引用 = 0（grep 全仓） | 审计命令纳入 CI secret scan 段 | ✅ |
| **T14 日志泄密** | slog RedactAttr（key 黑名单+值模式含 JWT）；Secret 类型；日志不含载荷 | `TestRedaction*`（PEM/Token/JWT 注入对抗） | ✅ |
| **T15 权限提升** | 非 root 默认；setcap 方案；root 检测拒绝（--allow-root 显式）；文件 0600/0700 | `TestGuardInjectable`；privilege-check.sh | ✅ |
| **T16 供应链** | 依赖白名单+间接清单；govulncheck；go mod verify；secret scan 历史 | CI workflow 含 govulncheck 预留；本轮工具链执行 | ✅ |
| **T17 密钥/Token 泄露** | Token 仅创建时打印+哈希存储+revoke；.gitignore 全套；secret scan 每阶段；CA key 0600 | 各阶段 secret scan 干净 | ✅ |
| **T18 恶意 Server** | Client 钉 Server CA（TOFU 指纹 pin）；文档明示信任模型 | enroll TOFU 测试；证书链验证 | ✅ |

## 工具链执行结果（本机）

- `go mod verify`：all modules verified ✅
- `os/exec` 生产代码引用：0 ✅
- 直接依赖对照白名单：cobra / go-toml / keyring / x/time / x/sys / wails ✅（间接依赖为 wails 与 keyring 生态，清单见 go.mod）
- govulncheck：见 audit-report（标准库漏洞需 Go 1.26.6，CI 覆盖）
- secret scan：每阶段干净（仅文档占位符/测试构造值）

## 已定级记录项（接受）

- 见 docs/security/known-limitations.md。

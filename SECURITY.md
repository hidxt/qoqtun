# Security Policy

qoqtun 是高安全性开源内网穿透软件。本文档汇总安全模型、受支持版本与漏洞披露流程。

## 安全设计要点

- **传输**：全链路 TLS 1.3 + mTLS（`crypto/tls`，MinVersion=TLS1.3，ClientAuth=RequireAndVerifyClientCert），是唯一认证方式；无 insecure 选项、无明文认证、无跳过证书校验的生产路径。
- **身份**：Ed25519 证书；Client 钉死实例 CA（不用系统根证书池）；client_id 从证书 CN/SAN 提取，而非客户端自报。
- **私钥不出设备**：私钥/Token/Secret 一律经系统安全存储（wincred / Keychain / Secret Service，0600 文件降级），禁止进日志、Git、前端。
- **策略强制在 Server**：端口范围、Tunnel 数、并发连接数、带宽、UDP Session 数、目标 IP/CIDR/端口白名单均由 Server 端强制，Client 只是申请方。
- **fail-closed**：校验失败 = 拒绝；不存在隐式无限；所有网络操作有超时。
- **无遥测**：禁止遥测 / Analytics / 非必要第三方外连；除业务连接与用户配置目标外零外连。
- **日志脱敏**：统一走 `internal/logging` Redaction；敏感值以 `***` 呈现。

## 威胁模型摘要

完整威胁模型见 [docs/plan/02-threat-model.md](docs/plan/02-threat-model.md)（资产、信任边界、T1–T18 逐项的攻击面 / 影响 / 缓解 / 剩余风险）。核心威胁概览：

| 类别 | 威胁（T#） | 主要缓解 |
|---|---|---|
| 传输安全 | T1 MITM / T2 重放 / T3 连接劫持 | TLS 1.3 + mTLS、CA 钉扎、一次性随机 conn_id、序列号+nonce |
| 身份与密钥 | T4 证书盗取 / T5 客户端伪造 / T17 Token·密钥泄露 | 系统安全存储、即时吊销、Token 一次性+SHA-256 存储、secret scan |
| 滥用与资源 | T6 恶意合法客户端 ⭐ / T7 端口抢占 / T8 SSRF / T9 DoS / T10 资源耗尽 | Server 端强制 ACL、限额、限速、超时全覆盖、连接级 recover |
| 配置与输入 | T11 配置注入 / T12 路径遍历 / T13 命令注入 | 严格模式解析、全字段校验、路径清洗、禁止 `os/exec` |
| 运营与供应链 | T14 日志泄密 / T15 权限提升 / T16 供应链 / T18 恶意 Server | Redaction、非 root 运行、依赖白名单 + govulncheck、CA 钉扎 |

每一条缓解都必须有实现 + 自动化测试证据（阶段验收强制）。

## 安全审计

- 威胁模型逐项核对：[docs/security/audit-checklist.md](docs/security/audit-checklist.md)
- 审计报告（范围/方法/发现/定级/整改/残余风险）：[docs/security/audit-report.md](docs/security/audit-report.md)
- 已定级接受项：[docs/security/known-limitations.md](docs/security/known-limitations.md)

## 受支持的版本

> 占位：V1.0.0 发布后填写（例如"仅支持最新稳定版；旧版本安全修复以变更日志为准"）。

## 漏洞披露流程

> 占位：请在此填写安全联系人邮箱与 PGP 公钥指纹。正式发布前建议：
>
> 1. 安全相关问题请**不要**公开提交 GitHub Issue，请私信联系维护者（联系方式占位）。
> 2. 请在邮件中包含：受影响版本、漏洞描述、复现步骤、影响评估；可选附 PGP 加密的细节（PGP 公钥指纹占位）。
> 3. 维护者承诺：确认后 48 小时内响应，修复计划与 CVE 编号将同步到 [CHANGELOG.md](CHANGELOG.md) 与 GitHub Security Advisories（占位）。
> 4. 遵循协调披露（Coordinated Disclosure）：修复发布前不公开细节。

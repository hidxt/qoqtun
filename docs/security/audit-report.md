# 安全审计报告（Phase 16）

## 范围与方法

- **范围**：全仓（Go 核心 16 包 + 3 CLI + Wails Desktop + 前端），威胁模型 T1–T18 逐项核对。
- **方法**：威胁模型逐项→攻击者剧本驱动的专项代码审查（PKI/认证/ACL/路径/日志/并发）→工具链（govulncheck / go mod verify / os-exec grep / secret scan）→整改闭环。
- **时间**：2026-08-16（对应 commit ab6361e 之后）。

## 发现与定级

| 编号 | 发现 | 定级 | 处置 |
|---|---|---|---|
| A1 | 标准库漏洞（crypto/tls GO-2026-6090、GO-2026-6089、asn1 GO-2026-5972） | **P1** | 需 Go ≥1.26.6（本机 1.26.5）；**非仓库代码缺陷**；CI 已用 Go 1.26（自动取补丁版），升级本机 Go 即闭环 |
| A2 | client 注册 resp 与 follow-up open_connection 的帧序竞态（UDP 通道可丢失） | P1（正确性→可用性） | Phase 14 已修（readLoop 帧序注册）+ 回归测试 ✅ |
| A3 | 旧配置兼容（Validate 拒绝早期版本 toml） | P1（可用性/升级） | Phase 14 已修（默认填充）+ TestLegacy 回归 ✅ |
| A4 | UDP 端口释放延迟（Windows） | P2 | UDP bind 重试（Phase 14）缓解；记录 |
| A5 | 双 CA 测试拓扑误用 | P2（测试质量） | 已修（单 CA 与主线一致） |

## 重点项审计结论

- **PKI**：序列号随机（randomSerial）、有效期边界、CSR 校验、吊销即时（握手时查表）、CA 池独立、keystore 权限/符号链接/TOCTOU（owner 检查+O_NOFOLLOW+原子写）——均有实现与测试。
- **认证与会话**：client_id==CN 强制、Token 哈希/原子核销、握手超时、重复登录踢旧（防乒乓）——证据齐全。
- **ACL/限额**：Server 唯一执行点；恶意 Client 视角复核——注册时 target 校验、连接/带宽/频率全 Server 强制；信号量释放路径穷尽（splice 结束/通道关闭/超时）。
- **注入与路径**：`os/exec` 生产引用 0；路径 Clean/Lstat/原子写；TOML strict。
- **日志**：redaction 覆盖（key 黑名单+值模式+JWT）；对抗测试注入 PEM/Token/JWT 断言脱敏。
- **并发**：-race 由 CI 覆盖（本机无 cgo）；deadline 全覆盖核对（Accept/Read/Write/Dial 均有超时）。

## 流量审计（零外连验证）

- 代码级：无 telemetry/analytics/更新检查；全部外连仅：用户配置的 Server 控制/数据/Enroll 地址与转发目标。
- 依赖：无网络调用库（仅 keyring 本地 API）。
- 建议（记录）：CI 隔离环境抓包验证纳入 nightly（tcpdump 断言零意外外连）。

## 整改状态

- P0：0。
- P1：A1 依赖 Go 版本（CI 覆盖，升级本机即闭环）；A2/A3 已修复并回归 ✅。
- P2：A4/A5 已缓解/记录。

## 残余风险声明

1. **CA/Server 密钥物理泄露** = 信任域重建（T17 灾难级），靠备份/轮换纪律。
2. **恶意 Server 可读全部转发明文**（T18 架构固有）：文档明示，敏感业务应自带端到端加密。
3. **10k 并发/超大流量 L3/L4 洪泛**超出软件能力，属机房/上游防护（T9 剩余）。
4. **标准库漏洞**：升级 Go 1.26.6 即闭环；发布前必须使用无已知漏洞的工具链。
5. 建议：正式发布前引入第三方渗透测试（本报告作为自审计基线）。

## 归档

- 详细逐项核对：docs/security/audit-checklist.md
- 接受项：docs/security/known-limitations.md

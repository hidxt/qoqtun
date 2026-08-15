# qoqtun 开发规划总索引

qoqtun：高安全性开源内网穿透软件（C/S 架构对标 frp，**不复制 frp 源码**）。
三程序：Server CLI / Client CLI / Client Desktop（Wails v2），共用 internal/ Go Core。
优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。

## 设计文档（DeepSeek V4 Flash 的唯一事实来源）

| 文档 | 内容 |
|---|---|
| [01-architecture.md](01-architecture.md) | 总体架构、V1 范围/非目标、关键技术取舍表、Monorepo 结构与依赖规则 |
| [02-threat-model.md](02-threat-model.md) | 资产、信任边界、T1–T18 威胁（攻击面/影响/缓解/剩余风险） |
| [03-pki-enrollment.md](03-pki-enrollment.md) | CA、Token、Enrollment 流程、续期/吊销/CA 轮换、私钥存储矩阵 |
| [04-protocol-v1.md](04-protocol-v1.md) | 编码选型（JSON 帧）、消息目录、TCP/UDP/HTTP 流程、心跳、错误码 |
| [05-config-schema.md](05-config-schema.md) | server.toml/client.toml 全字段、校验规则、CLI>ENV>Config>Default |
| [06-roadmap.md](06-roadmap.md) | 18 阶段 Roadmap（目标/范围/安全/测试/DoD/风险） |

## 阶段提示词（`prompts/`）

每份提示词**自包含**（背景+红线+任务+测试+Git 要求+DoD），可直接整段复制给 DeepSeek V4 Flash 执行。按编号顺序执行；每阶段结束必须可编译、可测试、可提交。

- **[master-plan-mode.md](prompts/master-plan-mode.md)：总控提示词（计划模式）**——让 DeepSeek V4 Flash 始终先出计划、确认后执行、按阶段推进的总规则。项目启动时先给它这一份。

| 阶段 | 提示词 |
|---|---|
| 00 需求冻结与文档 | [phase-00.md](prompts/phase-00.md) |
| 01 骨架/Config/Logging/CLI | [phase-01.md](prompts/phase-01.md) |
| 02 PKI 与安全存储 | [phase-02.md](prompts/phase-02.md) |
| 03 Enrollment/Token/吊销 | [phase-03.md](prompts/phase-03.md) |
| 04 控制协议/mTLS/Session | [phase-04.md](prompts/phase-04.md) |
| 05 TCP Tunnel MVP | [phase-05.md](prompts/phase-05.md) |
| 06 重连/心跳/优雅关闭 | [phase-06.md](prompts/phase-06.md) |
| 07 UDP Tunnel | [phase-07.md](prompts/phase-07.md) |
| 08 HTTP/HTTPS | [phase-08.md](prompts/phase-08.md) |
| 09 ACL/限速/限额 | [phase-09.md](prompts/phase-09.md) |
| 10 统计/日志 | [phase-10.md](prompts/phase-10.md) |
| 11 Client CLI 完整化 | [phase-11.md](prompts/phase-11.md) |
| 12 Desktop Core（coreapi） | [phase-12.md](prompts/phase-12.md) |
| 13 Desktop UI（Stitch 驱动） | [phase-13.md](prompts/phase-13.md) |
| 14 跨平台集成测试 | [phase-14.md](prompts/phase-14.md) |
| 15 性能/压力/Race/Fuzz | [phase-15.md](prompts/phase-15.md) |
| 16 安全审计 | [phase-16.md](prompts/phase-16.md) |
| 17 文档/打包/RC | [phase-17.md](prompts/phase-17.md) |

## 关键决策速览

- 传输：TLS 1.3 + mTLS（Ed25519 证书），无 insecure 选项；Client 钉死实例 CA。
- 控制面：4B 长度前缀 + JSON（≤64KiB）；数据面纯字节流，编码无关。
- 身份：客户端本地 Ed25519 私钥 + CSR；一次性短时效 Enrollment Token（服务端只存 SHA-256）在线签发；吊销即时生效。
- HTTP = 共享端口 Host 路由（轻量嗅探+透传）；HTTPS = 纯 L4 透传（不终止 TLS）。
- UDP = mTLS TCP 通道封装帧 + Session 映射（上限/超时/速率限制 Server 强制）。
- 策略：Server 端强制（端口范围/Tunnel 数/并发/带宽/UDP Session/目标白名单），Client 只是申请方。
- Desktop：coreapi 窄门面，前端永不接触私钥/证书/TLS；UI 以 Stitch 压缩包为唯一依据。
- 依赖白名单：cobra、go-toml/v2、99designs/keyring、x/time、Wails v2；其余需评审。

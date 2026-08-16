# qoqtun UDP Tunnel 语义（Phase 7）

> 设计见 docs/plan/04-protocol-v1.md §6。本页记录 V1 UDP 的"伪连接"、超时、上限与丢包行为，供运维与排障参考。

## 1. 传输模型

- **不原生 UDP-over-UDP**：V1 将 UDP 封装在 **1 条 mTLS-over-TCP 数据通道**内（每 client 每 tunnel 一条，长连接）。
- 通道帧：`[4B 大端长度][session_id 16B][payload]`，payload ≤ `max_packet`（默认 1500，硬上限 65507）。
- 通道随隧道注册**预建**（Server 发 `open_connection{transport:"udp"}`）；通道断开后自动重建（`OnUDPChannelClosed` → 重新预建，走 Phase 6 重连语义）。

## 2. 伪连接（Session）

| 概念 | 说明 |
|---|---|
| session_id | 每条公网对端会话 16B CSPRNG 随机；用于通道内区分对端 |
| 会话键 | Server 侧 `(tunnel_id, 公网对端 addr)`；Client 侧 `session_id → 本地 UDP 套接字` |
| 生命周期 | 首个数据包创建；空闲超时回收；控制面断开全清 |

## 3. 超时与上限（Server 强制）

| 项 | 默认 | 行为 |
|---|---|---|
| session 空闲 | 60s | 超时回收（每秒清扫） |
| session 上限 | 256/tunnel | 满则 **LRU 淘汰最久未活跃**并记审计 |
| max_packet | 1500（上限 65507） | 超限包**静默丢弃**并计数 |
| 每公网 IP pps | 5/s（burst 10） | 超速丢弃并计数（防滥用，T6） |

## 4. 丢包与乱序（UDP 语义）

- 通道未就绪 / 会话表满 / 超速 / 超限：**静默丢弃**（UDP 语义，不做重传或可靠增强）。
- **乱序、重复、丢失属 UDP 固有语义**：不对上层做保序/去重/重传。
- 回源 ACL：Client 对本地目标按 `allowed_targets` 校验，白名单外拒绝（fail-closed）。

## 5. 运维提示

- UDP 应用的超时/重传由应用自己负责；隧道只提供等价于"本地 UDP 直连"的体验。
- 洪泛场景下 Server 的 pps 限速会优先丢弃，客户端观察为丢包率升高（这是预期保护）。
- 数据通道重建期间（秒级）UDP 包被丢弃；长连接 UDP 应用（如 QUIC、VoIP）建议应用层容错。

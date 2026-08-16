# qoqtun 控制连接状态机（Protocol v1）

> 控制面单连接生命周期（04-protocol-v1.md §1/§2/§4）。数据连接状态机见 Phase 5。

## 三态总览

```
        mTLS 握手完成
   ┌─────────────────────┐
   ▼                     │
[握手] ──client_hello──▶ [在线] ──shutdown/断连/心跳超时──▶ [关闭]
   │ 校验失败/超时           │ 心跳维持                     │
   └──错误/断开───────────▶  │ ◀──错误(非fatal)──────────────┘
                            └──────────▶ 资源释放（session 注销）
```

## 状态与转移

| 状态 | 进入条件 | 出口 |
|---|---|---|
| **握手** | mTLS 握手成功（TLS 1.3 + RequireAndVerifyClientCert + CA 池 + 吊销检查） | 10s 内收到合法 `client_hello`（seq 起始、CN==client_id、版本匹配）→ 发 `server_hello`（policy+heartbeat）→ **在线**；校验失败/超时 → 发 `error`(fatal) 并关闭 |
| **在线** | server_hello 已发出 | 收到 `shutdown`（对端优雅关闭）→ **关闭**；断连/心跳超时（Server 侧 2×interval+timeout 无消息）→ **关闭**；收到 fatal `error` → **关闭** |
| **关闭** | 任一出口 | session 从 Registry 注销、half-open 计数释放、连接 Close（资源完全回收） |

## 并发模型（代码约定）

- **写**：控制连接统一 `write mutex`（`transport.Conn.WriteFrame` 内部加锁）。消息频率极低（握手/心跳/注册），单锁足够且无单写 goroutine 的背压问题。
- **读**：每连接单读循环（`control.readLoop` / `clientcore.readLoop`），收到消息即 `session.Touch()` 更新活跃时间。
- **心跳监督**：Server 每 1s 检查 `2×interval+timeout` 无活动 → 关闭连接（踢除）；Client 每 `interval_s` 发 ping，`miss_threshold` 次未收 pong → 本地退出。

## 超时与限额（fail-closed）

| 项 | 值 | 说明 |
|---|---|---|
| 握手总超时 | 10s | client_hello 未到即关 |
| 帧大小 | ≤64KiB | 超限关连接（ERR_PROTOCOL） |
| 每 IP 半开连接 | 8（可配） | 未认证连接防资源耗尽（T5） |
| 心跳超时 | 2×interval+timeout | Server 踢除并释放会话 |
| 所有 IO | 均有 deadline | 无永不超时的连接 |

## 错误分类

- **fatal**（客户端停止，不自动重连）：ERR_PROTOCOL、ERR_VERSION_UNSUPPORTED、ERR_AUTH_FAILED、ERR_CERT_EXPIRED/REVOKED。
- **非 fatal**：运行期错误（Phase 5 的 ERR_PORT_NOT_ALLOWED 等），连接保持。

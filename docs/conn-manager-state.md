# qoqtun 客户端 Connection Manager 状态机

> clientcore 连接管理（04-protocol-v1.md §4）。Server 侧控制连接状态见 docs/protocol-state.md。

## 状态图

```
                首次/重连拨号
   ┌─────────────────────────────┐
   ▼                             │
[Disconnected] ──▶ [Connecting] ──▶ [Online] ──断线(临时错误)──▶ [Disconnected] ─┐
      ▲                 │           │                              ▲             │
      │                 │           ├──永久错误─────────────────────┤             │
      │                 │           └──Server shutdown──▶ [Draining] ─┐          │
      │                 └──ctx cancel/永久错误───────────────────────────┼──────────┘
      └──────────────────────▶ [Stopped] ◀──────────────────────────────┘
```

| 状态 | 进入 | 出口 |
|---|---|---|
| **Disconnected** | 初始；临时错误后 | 拨号 → Connecting；ctx cancel/永久 → Stopped |
| **Connecting** | 每次拨号 | 握手成功 → Online；失败 → 分类：永久→Stopped，临时→Disconnected（退避后重试） |
| **Online** | server_hello 已收、策略/隧道已注册 | 断线（IO/心跳 miss）→ Disconnected；收到 fatal error → Stopped；收到 Server shutdown / ctx cancel → Draining→Stopped |
| **Draining** | 收到 shutdown / 本地优雅关闭 | 发 shutdown 协商、等数据连接 drain → Stopped |
| **Stopped** | 终止 | —（终端态） |

## 错误分类（永久 vs 临时）

| 类别 | 判定 | 行为 |
|---|---|---|
| **永久** | TLS 证书/链/吊销/过期、ERR_AUTH_FAILED、ERR_VERSION_UNSUPPORTED、协议违规、被新会话顶替（kick） | **停止重连**，Run 返回错误（调用方非零退出） |
| **临时** | 网络 IO、EOF、超时、心跳 miss、连接被强制断开 | 退避重连（初始 1s ×2，上限 60s，±20% jitter，[reconnect] 可配）；连续失败日志降频（每 5 次采样） |

## 重连行为

- 重连成功后**自动重注册全部 enabled tunnels**；Server 侧端口预留（60s TTL）保证同一 client 拿回原端口，其他 client 无法抢占。
- 被踢的旧会话收到 **fatal error**（"replaced by a newer session"）→ 永久停止，**避免双活进程踢来踢去的乒乓**。
- 重连风暴防护：jitter 真实生效，多 client 同时恢复时退避时间分散。

## 优雅关闭（shutdown 协商）

- **Client 发起**：SIGINT/SIGTERM（或 ctx cancel）→ 发 `shutdown{reason, drain_timeout_ms}` → Server 摘除 Public Listeners → 等活跃数据连接 drain（默认 30s 上限）→ 强关残余 → 双方释放，退出码 0。
- **Server 发起**（SIGINT/SIGTERM）：向所有 client 广播 `shutdown` → 停止 Accept → drain → 落统计 → 退出。
- 第二次信号 → 立即强退（退出码 130）。

## 资源保证

- 控制连接断开 → 主动关闭全部数据连接（splice 终止）→ 无 goroutine/FD 泄漏（浸泡测试断言）。
- 所有 IO 有 deadline；心跳 miss_threshold 判定由 Client 本地计数、Server 侧 2×interval+timeout 兜底。

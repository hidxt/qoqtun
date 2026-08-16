# 策略配置手册（Policy / 限额 / 资源保护）

Server 是唯一策略执行点（fail-closed：判断出错即拒绝）。所有限额都有默认值；触发时输出脱敏审计日志与对应错误码。威胁模型对照：T6（目标白名单）、T7（限速）、T9（洪泛/限额）、T10（资源保护）。

## [policy] 字段与默认值（server.toml）

| 字段 | 默认 | 作用 | 错误码 |
|---|---|---|---|
| `allowed_ports` | `["20000-29999"]` | 公网端口白名单（单端口/范围） | ERR_PORT_NOT_ALLOWED |
| `max_tunnels_per_client` | 16 | 每客户端 Tunnel 数上限 | ERR_TUNNEL_LIMIT |
| `max_conns_per_client` | 256 | 每客户端并发数据连接 | ERR_CONN_LIMIT |
| `max_conns_per_tunnel` | 128 | 每 Tunnel 并发数据连接 | ERR_CONN_LIMIT |
| `bandwidth_bps_per_client` | 0（不限） | 每客户端带宽（token bucket，读/写双向） | —（限速不拒连） |
| `bandwidth_bps_per_tunnel` | 0（不限） | 每 Tunnel 带宽（与 per-client 双层叠加） | — |
| `allowed_targets` | `["10.0.0.0/8:*"]` | 回源目标白名单（IP/CIDR:端口/范围/*），**注册时即校验** | ERR_TARGET_NOT_ALLOWED |
| `udp_max_sessions_per_tunnel` | 256 | UDP session 数（LRU 淘汰） | ERR_UDP_SESSION_LIMIT |
| `udp_max_packet` | 1500 | UDP 单包上限 | 丢弃+计数 |
| `udp_session_idle_timeout` | 60s | UDP 空闲回收 | — |

## 限额语义

- **并发连接（per-client / per-tunnel）**：信号量非阻塞获取，满则**立即拒绝**（不排队）——洪泛不会堆积 goroutine。
- **带宽**：`golang.org/x/time/rate` token bucket；数据连接包装读/写两侧，per-client 与 per-tunnel 双层叠加；连接关闭立即释放等待者。精度：持续流量实测速率在限额 ±10% 内。
- **注册频率**：每客户端 register/unregister ≤ 5 次/s（burst 32，兼容重连批量注册）；超限 → ERR_RATE_LIMITED。
- **控制消息速率**：每控制连接 ≤ 200 帧/s；超限 → ERR_RATE_LIMITED 并断连（防控制面洪泛）。
- **每公网 IP**（Public Listener 前置）：并发连接 ≤ 16、新建连接 ≤ 20/s；超限连接直接丢弃（T9 第一道防线）。
- **控制面半开**：每 IP 未完成 hello 的 mTLS 连接 ≤ 8（10s 总超时）；数据连接不受此限（已认证）。

## allowed_targets 双保险

1. **Server 注册时校验**：client 声明的 `local` 目标必须在白名单，否则拒绝注册（审计日志）。
2. **Client 拨号前校验**：dial local 前再次检查（解析后的 IP），防止配置漂移。

主机名声明：Server 端 ACL 只识别 IP/CIDR，hostname 会被拒绝（客户端拨号时才解析并校验实际 IP）。

## 资源保护（T10，`server run` 启动守卫）

| 检查 | 行为 | 放行 |
|---|---|---|
| root/administrator | 拒绝启动并提示 capability（`setcap 'cap_net_bind_service=+ep'`） | `--allow-root` |
| RLIMIT_NOFILE 低于估算 | 拒绝启动（估算 = 16 + 64 客户端 × max_conns×2 + 256） | `--allow-low-fdlimit` |
| pprof 端点 | 默认关闭；`--pprof 127.0.0.1:6060` 显式开启，**只允许绑定 127.0.0.1** | — |

```
qoqtun-server run --config server.toml \
    [--allow-root] [--allow-low-fdlimit] [--pprof 127.0.0.1:6060]
```

## 审计日志

所有限额触发记 WARN（脱敏，不含 client_id 之外的身份信息）：
`register rate limited` / `connection quota exceeded` / `target not allowed` / `control message rate exceeded` / `public conn per-IP limit` / `half-open limit exceeded`。

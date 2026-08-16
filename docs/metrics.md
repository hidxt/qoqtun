# 统计字段字典（metrics）

统计**只含元数据**（字节数/连接数/时间戳），绝不包含转发载荷内容；统计只供本地 CLI 查询（`server status` / `client status`），**禁止任何遥测上报**。

## 采集路径

| 路径 | 计数字段 | 位置 |
|---|---|---|
| TCP/HTTP 数据连接 | rx/tx bytes、active/total conns | server 侧 `handleDataConn` splice 结果；client 侧 `tunnel.Client` splice 结果 |
| HTTP vhost | 同上（**嗅探+回放前缀字节计入**，无绕过） | 同上（ReplayConn 读前缀走 splice 计数） |
| UDP 通道 | rx/tx packets（帧级） | server 侧 `Manager.OnUDPStats`（公网收=rx、公网发=tx） |
| 全局汇总 | GlobalRxBytes/TxBytes/Conns + 实时速率 | Registry 滚动累加 |

## 方向语义（重要）

- **rx** = 从公网侧接收的字节（client 发出的请求 / 公网打入的数据）。
- **tx** = 发送到公网侧的字节（origin 返回的响应）。
- Server 与 Client 统计互为镜像（同一连接在两端方向相反）。

## Snapshot 结构（status.json 输出）

```json
{
  "GlobalRxBytes": 79, "GlobalTxBytes": 127, "GlobalConns": 1,
  "RateBPS": 0,          // 瞬时速率（最近 1s）
  "AvgRateBPS": 3,       // 60s 平均
  "Clients": [{
    "ClientID": "...",
    "RxBytes": 79, "TxBytes": 127,
    "ActiveConns": 0, "TotalConns": 1,
    "Tunnels": [{
      "TunnelID": "t_1",
      "RxBytes": 79, "TxBytes": 127,
      "ActiveConns": 0, "TotalConns": 1,
      "UDPRxPackets": 0, "UDPTxPackets": 0
    }]
  }]
}
```

| 字段 | 含义 |
|---|---|
| `ActiveConns` | 当前打开的数据连接（quota acquire/release 同步） |
| `TotalConns` | 累计打开的连接数 |
| `RateBPS` / `AvgRateBPS` | 滑动窗口速率（1s 粒度 × 60s 深度；短突发会被平滑） |
| `UDPRxPackets` / `UDPTxPackets` | UDP 帧计数（UDP-in-TCP 通道逐帧） |

## 查询命令

```sh
qoqtun-server status --config server.toml   # 读 state_dir/status.json（server run 每 2s 原子写）
qoqtun-client status --state state.json     # 读 state.json.status.json
```

V1 为本机查询（无远程管理通道）：status 文件 0600、原子写；运行中进程退出后文件保留最后一次快照。

## 精度保证

- 计数器为 atomic int64，快照为值拷贝（无撕裂）。
- 集成测试：10MiB 转发 rx/tx **误差为 0**；UDP 包数逐一核对；vhost 回放前缀计入。
- 高并发热点：当前 atomic 计数足够（契约约定：仅当基准显示争用才引入分片计数）。

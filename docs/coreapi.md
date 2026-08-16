# coreapi 参考（Desktop 唯一入口）

`internal/coreapi` 是 Desktop 前端唯一可调用的 Go 门面（01-architecture §4）。**GUI 是薄壳**：网络/TLS/PKI/认证/配置/安全/连接管理/统计全部委托给既有包；`frontend/` 禁止出现任何网络/证书/密钥代码。

**返回值永不包含私钥、证书 PEM、Token**——只给状态元数据。

## 生命周期

### `Start(profile string) error`
- 加载身份（state.json + keystore）与配置（client.toml），启动隧道客户端（异步）。
- 参数：`profile` V1 保留（"" = 默认配置）。
- 错误：未入网（无 state）→ "identity: ..."；配置无效 → "invalid config"。
- 事件：`{type:"state", data:Status{running:true,state:"connecting"}}`。

### `Stop() error`
- 优雅停止（ctx 取消；客户端先向 Server 发 shutdown 并 drain）。幂等。

### `Status() Status`
```json
{ "running": bool, "state": "stopped|connecting|online", "client_id": "...", "server_addr": "..." }
```

## Tunnel（运行时）

| 方法 | 说明 | 错误 |
|---|---|---|
| `ListTunnels() []TunnelInfo` | 运行中隧道（name/type/local/remote/tunnel_id） | — |
| `StartTunnel(name)` | 启动配置中的隧道（仅运行时，不持久化） | 未运行 / 不在配置 |
| `StopTunnel(name)` | 停止运行中的隧道 | 未运行 / 未启动 |
| `UpsertTunnel(cfg)` | 新增/替换 client.toml 中的隧道（持久化 + 校验） | 校验失败 / 持久化失败 |
| `DeleteTunnel(name)` | 从 client.toml 删除隧道 | 不存在 |

`UpsertTunnel` 的 `cfg` 字段：`name/type/remote_port/local_ip/local_port/http_host/enabled`（校验与 config 同源）。

## Config

| 方法 | 说明 |
|---|---|
| `GetConfig() map[string]any` | 生效配置（server_addr + tunnels；无敏感字段） |
| `UpdateConfig(partial map[string]any)` | 合并 server_addr/tunnels → 校验 → 持久化 → 返回生效值 |

## Identity

### `GetIdentity() IdentityInfo`
```json
{ "client_id": "...", "name": "...", "server_addr": "...", "expires_at": "RFC3339", "keystore": "auto|keyring|file", "enrolled": true }
```
无敏感内容（不含指纹以外的任何密钥材料）。

## Stats

### `GetStats() metrics.Snapshot`
复用 `internal/metrics` 快照（rx/tx bytes、conns、速率）——见 docs/metrics.md。

## Events

### `Events() <-chan Event`
事件流（容量 128，无人读时丢弃，无订阅泄漏）：
- `{type:"state", data:Status}`：连接状态变更
- `{type:"tunnel", data:name}`：隧道增删
- `{type:"stats", data:Snapshot}`：统计 tick（V1 由前端轮询 GetStats）

## 边界

- coreapi **只做**参数校验 + 委托 + DTO 转换；不放业务逻辑。
- 所有输入校验与 `config.ValidateClient` 同源（fail-closed）。
- 并发安全：方法内部互斥；事件发送非阻塞。

## 测试

`go test ./internal/coreapi/`（无头，不起窗口）：配置 CRUD 正反例、真实 Server 生命周期（在线/隧道注册/身份/统计）。

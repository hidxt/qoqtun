# CLI 参考（client）

## 全局

```
qoqtun-client --help                     # 帮助
qoqtun-client completion bash|zsh|fish|powershell   # shell 补全
```

配置覆盖优先级：**命令行 flag > config 文件 > 默认值**。V1 配置变更=重启生效（不做热加载）。

## run（常驻）

```
qoqtun-client run [--config client.toml] [--state state.json]
                  [--ca ca.crt] [--secrets-dir DIR] [--keystore-backend auto|keyring|file]
                  [--server-addr host:port]
```

- SIGINT/SIGTERM：优雅退出（通知 server 摘端口、drain，码 0）；二次信号强退（码 130）。
- 启动本地控制端点（127.0.0.1 随机端口 + CSPRNG token，写入 `state.json.status.json`，0600）。

## cert（身份）

```
qoqtun-client cert init  [--name NAME] [--csr-out client.csr] ...    # 私钥入安全存储，生成 CSR
qoqtun-client enroll     --token qen_... [--server host:port] ...    # token 走 stdin（推荐）或 --token（警告：会进 shell history）
qoqtun-client cert renew [--csr client.csr] ...                      # mTLS 续期
qoqtun-client cert status [--state state.json]                       # client_id / server / CA 指纹 / 到期（无敏感内容）
```

## tunnel（运行时控制，通过本地控制端点）

```
qoqtun-client tunnel list [--state state.json] [--json]
qoqtun-client tunnel start <name> --remote-port N --local IP:PORT [--type tcp|udp|http|https] [--http-host HOST]
qoqtun-client tunnel stop <name>
qoqtun-client tunnel status [--state state.json]
```

- start/stop 仅运行时生效，**不写配置**（重启恢复 config 定义）。
- 端点信息从 0600 状态文件读取；命令与 `run` 必须使用同一 `--state`。

## 其他

```
qoqtun-client check-config [--config client.toml]   # 校验配置
qoqtun-client status [--state state.json]           # 本地统计快照（流量/连接）
```

## server 端

```
qoqtun-server run --config server.toml [--allow-root] [--allow-low-fdlimit] [--pprof 127.0.0.1:6060]
qoqtun-server status --config server.toml
qoqtun-server ca init [--force] [--san ...]
qoqtun-server client create-token / list / revoke-token
qoqtun-server cert list / revoke <serial>
qoqtun-server enroll serve
```

完整生命周期示例见 README「快速开始」与 `scripts/e2e.sh`。

# qoqtun 配置 Schema（V1）

- 格式：TOML（`pelletier/go-toml/v2`，**严格模式**：未知字段报错）。
- 优先级：**CLI flag > 环境变量（`QOQTUN_*`）> 配置文件 > 内置默认值**。
- 任何配置项都不得触发 Shell 执行；所有 Path/IP/CIDR/Port/Hostname/Tunnel Name 在加载期校验。
- `server check-config` / `client check-config`：解析+校验+打印生效值（敏感值脱敏），exit code 0/1。

## 1. server.toml

```toml
# ===== 必填（无默认值）=====
state_dir = "/var/lib/qoqtun"          # CA/证书/吊销/Token/客户端登记所在目录；校验：绝对路径、存在或可由当前用户创建

# ===== 网络监听 =====
[listen]
control_addr = "0.0.0.0:7000"          # mTLS 控制+数据入口
enroll_addr  = "0.0.0.0:7001"          # Enrollment；设 "" 关闭
enroll_enabled = true
http_vhost_port = 0                    # HTTP Host 路由共享端口；0=禁用（HTTP Tunnel 退化为独占端口）

# ===== 客户端策略（全局默认，可作 per-client 覆盖的基础）=====
[policy]
allowed_ports = ["20000-29999"]        # 允许注册的公网端口区间；禁止包含 control/enroll 端口
max_tunnels_per_client = 16            # 1..1024
max_conns_per_client   = 256           # 并发转发连接 1..100000
max_conns_per_tunnel   = 128
bandwidth_bps_per_client = 0           # 0=不限（文档建议显式设置）
bandwidth_bps_per_tunnel = 0
allowed_targets = ["10.0.0.0/8:*"]     # Client 回源目标白名单 "CIDR:port或区间"；默认仅示例，部署必须显式配置
udp_max_sessions_per_tunnel = 256
udp_max_packet = 1500                  # ≤65507
udp_session_idle_timeout = "60s"

# ===== 心跳 =====
[heartbeat]
interval_s = 15                        # 5..300
timeout_s  = 10
miss_threshold = 2

# ===== 证书 =====
[pki]
ca_validity_years = 10
client_cert_validity_days = 90         # 1..825
token_ttl = "1h"                       # ≤24h

# ===== 日志 =====
[logging]
level = "info"                         # debug/info/warn/error
format = "json"                        # json/text
file = ""                              # ""=stderr；写文件时 0640 + 目录校验
```

校验要点：`allowed_ports` 区间合法且与监听端口不重叠；`allowed_targets` 每条为合法 CIDR + 合法端口/区间；hostname 仅允许在 enroll/control 地址类字段出现且须通过 RFC1123 校验。

## 2. client.toml

```toml
# ===== 必填 =====
server_addr = "tunnel.example.com:7000"   # hostname 或 IP + 端口；hostname 须 RFC1123
ca_fingerprint = ""                       # 可选：钉扎 CA 证书 SHA-256（首次 enroll 可 --trust-on-first-use 显式确认）

# identity / tls 无配置字段，仅注释说明（严格模式拒绝未知字段，空表头不可出现）：
#   [identity]  # client_id 由 cert init 生成并持久化于安全状态文件，不在此手写
#   [tls]       # 无 insecure 选项 —— 设计上不存在

[reconnect]
initial_backoff = "1s"
max_backoff = "60s"                      # ≤10min
jitter = 0.2

[heartbeat]                              # 以 server 下发为准，此处仅客户端下限保护
enabled = true

[logging]
level = "info"
format = "text"
file = ""

# ===== Tunnel 定义（可多条）=====
[[tunnels]]
name = "ssh"                             # ^[a-zA-Z0-9_-]{1,64}$，全局唯一
type = "tcp"                             # tcp|udp|http|https
remote_port = 22000                      # 须在服务端 allowed_ports 内（注册时由 server 仲裁）
local_ip = "127.0.0.1"                   # 字面 IP 或白名单主机名；禁 0.0.0.0
local_port = 22
enabled = true
idle_timeout = "5m"

[[tunnels]]
name = "web"
type = "http"
http_host = "blog.example.com"           # type=http 时使用；RFC1123 域名
remote_port = 0                          # http 走 vhost 时可为 0
local_ip = "127.0.0.1"
local_port = 8080
enabled = true
```

校验要点：name 正则；type 枚举；端口范围；local_ip 非通配/组播/链路本地（除非白名单显式允许）；tunnels 内 name 去重；type=http 必须有 http_host 或 remote_port。

## 3. CLI 覆盖与 ENV 映射

- 每个配置键对应长 flag：`--server-addr`、`--logging-level`……
- ENV：`QOQTUN_SERVER_ADDR`、`QOQTUN_LOGGING_LEVEL`（大写、`.`→`_`、`[]` 不支持 ENV 覆盖——数组类只能走配置文件，避免歧义）。
- 合并顺序实现一处（`internal/config.Resolve`），CLI 与 Desktop 共用。

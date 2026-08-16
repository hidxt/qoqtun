# 安装与部署（三平台）

qoqtun 是**解压即用**的静态二进制（无运行时依赖）。安装 = 放置二进制 + 初始化 + 托管运行。

## 1. 获取与放置

| 平台 | 放置 | 备注 |
|---|---|---|
| Linux | `/usr/local/bin/qoqtun-server`、`qoqtun-client`（`install -m 0755`） | 配置放 `/etc/qoqtun/`，状态放 `/var/lib/qoqtun/` |
| macOS | `/usr/local/bin/`（或 `~/Applications`） | 配置 `~/Library/Application Support/qoqtun/` |
| Windows | `C:\Program Files\qoqtun\` | 配置 `%APPDATA%\qoqtun\` |

桌面版：`qoqtun-desktop`（Wails 打包产物）直接双击运行，首次启动自动写默认配置。

## 2. 文件权限（红线：不放松）

```
state/           0700  (server 状态：CA/密钥/证书)
state/ca/*.key   0600
secrets/         0700  (client keystore 目录)
*.toml           0600
state.json       0600
```

## 3. 初始化（一次性）

```sh
# server（需一次）：CA + 服务器证书 + 管理员 Token
qoqtun-server ca init --config server.toml --san your-domain.com
qoqtun-server client create-token --config server.toml

# client（每设备）：
qoqtun-client cert init --name my-laptop --csr-out client.csr
qoqtun-client enroll --server your-domain.com:7001 --csr client.csr ...   # token 走 stdin
```

## 4. 运行托管

- Linux：systemd unit（非 root、ProtectSystem 等加固）→ `docs/operations/deployment.md`
- macOS：launchd plist → 同上
- Windows：schtasks / NSSM → 同上

## 5. 低端口绑定（Linux，可选）

非 root 绑定 <1024 端口：**不要用 root 运行**，给二进制最小能力：

```sh
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/qoqtun-server
# 之后以普通用户运行即可绑定 443/80 等低端口
```

无权限时错误提示：`server run` 会明确报错（`--allow-root`/`--allow-low-fdlimit` 是显式放行开关，见 docs/operations/policy.md）。

## 6. 卸载

- 停止服务（systemctl disable/stop 或 launchctl unload 或 schtasks /Delete）。
- 删除二进制与配置目录（**含密钥**，请先备份）。
- client 侧可在 server 吊销设备：`qoqtun-server cert revoke <serial>`。

## 7. 验证安装

```sh
qoqtun-server check-config --config server.toml   # 配置预检
bash scripts/e2e.sh                               # 完整生命周期冒烟
```

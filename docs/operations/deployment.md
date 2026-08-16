# 服务化部署（systemd / launchd / Windows）

`qoqtun` 不自实现守护化（V1）：`run` 是前台常驻命令，由操作系统 init 系统托管。SIGINT/SIGTERM 触发优雅退出（码 0），二次信号强退（码 130）。

## Linux（systemd）

`/etc/systemd/system/qoqtun-client.service`（非 root、最小能力）：

```ini
[Unit]
Description=qoqtun client tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 用专用非 root 用户运行
User=qoqtun
Group=qoqtun
ExecStart=/usr/local/bin/qoqtun-client run --config /etc/qoqtun/client.toml
Restart=on-failure
RestartSec=5
# 加固
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# 日志
StandardOutput=journal
StandardError=journal
# 状态目录（client 身份/密钥/状态文件）
ReadWritePaths=/var/lib/qoqtun
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now qoqtun-client
journalctl -u qoqtun-client -f
```

Server 同理（`qoqtun-server run --config server.toml`），另需：
- `AmbientCapabilities=CAP_NET_BIND_SERVICE`（若绑定 <1024 端口）或直接使用 `setcap 'cap_net_bind_service=+ep' /usr/local/bin/qoqtun-server`（优先，避免 root）。
- 首次部署：`qoqtun-server ca init` + 创建 token 以 root 一次性完成，随后用 `qoqtun` 用户运行（state 目录属主 `qoqtun`）。

## macOS（launchd）

`~/Library/LaunchAgents/com.qoqtun.client.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.qoqtun.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/qoqtun-client</string>
    <string>run</string>
    <string>--config</string>
    <string>/usr/local/etc/qoqtun/client.toml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>/var/log/qoqtun-client.log</string>
  <key>StandardErrorPath</key><string>/var/log/qoqtun-client.log</string>
</dict>
</plist>
```

```sh
launchctl load ~/Library/LaunchAgents/com.qoqtun.client.plist
```

## Windows

用计划任务（无需管理员，登录会话内运行）：

```powershell
schtasks /Create /TN "qoqtun-client" /TR "\"C:\Program Files\qoqtun\qoqtun-client.exe\" run --config C:\qoqtun\client.toml" /SC ONSTART /RU %USERNAME% /F
schtasks /Run /TN "qoqtun-client"
```

或用 `sc.exe` 注册为 Windows 服务（需管理员，可用 NSSM 包装，V2 再评估官方服务安装器）：

```powershell
# 需要服务包装器（如 NSSM）；裸 Go 二进制不自注册为服务
nssm install qoqtun-client "C:\Program Files\qoqtun\qoqtun-client.exe" run --config C:\qoqtun\client.toml
```

## 说明

- 未实现 `--daemon`：V1 依赖 init 系统托管（文档决策）。
- 本地控制端点（`client tunnel ...`）默认可用；在多用户服务器上可通过文件权限限制 status.json（0600）访问。

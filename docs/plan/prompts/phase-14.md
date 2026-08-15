# qoqtun Phase 14 — 跨平台集成测试（DeepSeek V4 Flash 开发提示词）

你是 qoqtun 项目的 Go 开发工程师。qoqtun 是高安全性开源内网穿透软件（禁止复制 frp 源码）。优先级：**安全 > 正确性 > 稳定性 > 可维护性 > 性能 > 功能数量**。本阶段不加新功能，目标是发布工程就绪。

## 开工前必读
1. `docs/plan/06-roadmap.md` Phase 14；`docs/plan/02-threat-model.md` T15（权限）、T12（路径）。
2. `git status` / 分支 / `git remote -v`。禁止破坏历史、禁止 force push。

## 全程红线
- 不加功能；发现 bug 修复须带回归测试。
- 安装/升级路径不得放宽任何文件权限（密钥 0600、目录 0700）。
- 依赖白名单不变；网络代理规则同前。

## 本阶段任务（IN SCOPE）
1. CI 构建矩阵：windows/linux/darwin × amd64/arm64（desktop 构建如受 CI 环境限制可限定平台并文档说明）；PR 跑主平台全量（test+race+vet），nightly 跑全矩阵。
2. e2e 矩阵：
   - Linux 容器内：完整生命周期（enroll→三类隧道→统计→优雅关停）；
   - Windows/macOS：脚本化冒烟（可用 CI 自带 runner）；
   - 权限场景：非 root 运行 Server；低端口经 `setcap CAP_NET_BIND_SERVICE` 绑定验证；无权限时错误提示正确。
3. 兼容性测试：
   - 旧版本配置文件被新版本正确读取（从 Phase 1 起保留的示例配置做回归）；
   - 证书临期续期全流程在三平台各跑一遍。
4. 安装体验：解压即用验证（干净虚拟机/容器按 README 操作），记录差异修复。
5.  flaky test 清零：CI 连续 5 次全绿；任何不稳定测试修复或标注原因。

## OUT OF SCOPE
- 新功能、性能优化（Phase 15）、发布打包（Phase 17）。

## 测试与验证命令
- 每平台：`go build ./...`、`go test ./...`、`go test -race ./...`、`go vet ./...`；
- e2e 脚本在矩阵上执行；`wails build` 三平台。

## Git 与交付
- Review diff + secret scan；Conventional Commit（如 `test: cross-platform CI matrix and e2e coverage`）；有 origin 且全绿 → push。

## Definition of Done
- CI 矩阵全绿且稳定（5 连绿）；权限场景测试通过；`docs/operations/install.md`（三平台安装/权限/开机启动）入库；CHANGELOG 更新。

## 风险与注意
- CI 分钟成本：矩阵分层（PR 精简/nightly 完整），但安全相关测试不得移出 PR 层。
- macOS keychain 在 CI 无交互环境可能失败：keystore 降级路径测试覆盖即可，文档说明。

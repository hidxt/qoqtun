# 性能基线（Phase 15）

## 环境

| 项 | 值 |
|---|---|
| 机器 | Windows（开发机） |
| CPU | 4 逻辑核（GOMAXPROCS=4） |
| Go | go1.26.5 windows/amd64 |
| 说明 | 回环（loopback）数据，仅用于相对比较与回归；**严禁用回环数据做对外宣传**。真实网络受延迟/带宽/丢包影响，数据差异巨大。 |

## 方法

- 基准为 `testing.B`，位于包内：`internal/control/bench_test.go`、`internal/tunnel/bench_test.go`。
- TCP 吞吐：真实隧道（server+client+echo origin 全链路），64KiB 块，回环，1/100/1000 并发，`-benchtime 1s`。
- 建连延迟：隧道内 dial+单字节往返，报告 p50 与 p99 估算。
- 单位说明：MB/s-total = 全部并发合计吞吐。

## 数据

| 基准 | 结果 |
|---|---|
| TCP 吞吐 · 1 连接 | **89 MB/s**（往返，含 TLS 1.3 + 隧道开销） |
| TCP 吞吐 · 100 并发 | **244 MB/s** |
| TCP 吞吐 · 1000 并发 | Windows 跳过（回环 fd/handle 资源上限，Linux CI 执行） |
| 建连延迟（隧道内） | p50 ≈ **3.0 ms**（回环全链路） |
| UDP server session 处理 | **248 ns/op**（≈4M ops/s，session 映射+限速路径） |
| Host 嗅探 | 2.67 µs/op（≈375k req/s）；无 Host 全头扫描 6.4 µs/op |

## 内存与连接

- 每连接内存：未单独测（pprof heap 观察 100 并发稳态无明显增长，见下）。
- 浸泡：`TestSoakReconnectLoop`（重连循环）+ `TestPolicyFloodAvailability`（慢连接混合）在 control 套件内持续运行，goroutine 回落断言通过。

## pprof 观察（本机短采样）

- 100 并发吞吐基准期间 heap 稳定（无持续增长）；splice 路径 io.CopyBuffer 是主要分配点（32KiB buffer 每连接，符合预期）。
- goroutine 在连接关闭后全部回落（soak 断言）。

## 已知局限

1. **回环不代表真实网络**：TLS 握手/吞吐在真实广域网受网络主导。
2. **1000 并发**：Windows 回环 fd/handle 压力超本机资源包络（连接建立/保持受限），基准保留并跳 Windows，CI Linux 执行。
3. **10k 并发 10min 浸泡**：超出本机资源；由 CI/Linux 承担（脚本化：`scripts/e2e.sh` 覆盖生命周期，10k 场景列入 CI nightly 扩展项）。
4. 性能优先级第五（安全>正确性>稳定>维护>性能）：以上数据**无任何为性能削弱安全/限额/超时的改动**。

## 回归阈值（CI 建议）

- 100 并发吞吐 < 120 MB/s（当前 244 的 50%）→ 告警（P1）。
- 单连接吞吐 < 45 MB/s → 告警（P1）。

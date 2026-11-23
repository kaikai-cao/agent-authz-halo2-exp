# EXP-D2-A — Private Authorization Path Proof with Halo2

独立实验仓，验证“多授权来源 + 部分撤销 + 剩余有效路径”能否变成 Halo2 中可验证的关系。
不修改 D1-E、Orchard 或 Agent MVP。

## 固定设置

- 电路域：pallas::Base；承诺曲线 vesta；IPA；`halo2_proofs 0.4.0` / `halo2_gadgets 0.6.0` / `halo2_poseidon 0.2.0`
- Poseidon：`P128Pow5T3`，width 3 / rate 2
- Grant Tree / Revocation Tree：16 槽位、深度 4、域分离 `D_GRANT` / `D_REVOKE` / `D_NODE`
- Halo2 `k = 12`（domain size 4096，不等于实际约束行数）
- 公共输入：`(GR, RR, policyTag, epoch, Dq)`，共 5 个

## 目录

- `src/reference.rs`：独立 off-circuit 授权判定（不调用电路代码）
- `src/poseidon_hash.rs`：标签→域元素、域分离标签、off-circuit Poseidon
- `src/registry.rs`：16 槽位双树、membership / revocation path、构建校验
- `src/circuit.rs`：两级路径电路、8-bit range check、scope/时间/委托约束、请求摘要
- `src/public_inputs.rs`：instance 布局与 Dq 计算
- `src/bin/benchmark.rs`：真实证明性能采样，输出 `results/bench_*.json` / `raw_results.json`
- `tests/`：12 项固定测试矩阵 + Poseidon 一致性 + 参考模型 + 真实 proof 往返
- `tools/export_results.py`：从基准 JSON 与测试日志生成 CSV 与报告

## 复现

```bash
cargo test --locked
cargo test --locked > results/test_log.txt 2>&1
RAYON_NUM_THREADS=1 cargo run --release --bin benchmark
RAYON_NUM_THREADS=8 cargo run --release --bin benchmark
python tools/export_results.py
```

`cargo test` 中 `test_proof_roundtrip.rs` 的 T1/T3 使用真实
`Params::new → keygen_vk → keygen_pk → create_proof → verify_proof`，
其余负向项用 `MockProver` 做约束调试。

## 交付物

- `results/experiment_report.md`：含 12 项结果、性能表、研究问题回答与边界
- `results/raw_results.json`：两组线程设置 × 4 种记录数的原始采样与统计
- `results/summary.csv`：12 项测试 + 性能指标汇总
- `results/test_log.txt`：完整 `cargo test` 日志

## 明确边界

- ALLOW 证明不等于 DENY 证明；不存在路径时 Gateway fail-closed，不是电路给出不存在性结论。
- 电路内不验证 Ed25519 签发者签名；注册表构建前验证签发者是外部假设。
- Poseidon `GR/RR` 与 D1-E 的 `state_root/log_root` 是不同承诺；本轮不声称已获 quorum 认证。
- 外部 freshness、D2-B `ZkStateAnchor`、可变委托深度均不在本轮范围。
- 性能数字只是本机 Halo2 原型微基准，不代表生产吞吐量或硬件安全结论。

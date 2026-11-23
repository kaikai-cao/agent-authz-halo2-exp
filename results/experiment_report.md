# EXP-D2-A 实验报告

Private Authorization Path Proof with Halo2

> 实验性质：**Halo2 电路原型 + 真实证明成本测量**。不是完整授权系统，不是 DENY/不存在性证明，
> 不是 D1-E checkpoint 的链上锚定，也不验证 Ed25519 签发者签名。

## 1. 固定参数

| 参数 | 值 |
| --- | --- |
| 曲线 / 域 | Pallas 标量域（电路域），IPA 承诺曲线 vesta |
| Halo2 | halo2_proofs 0.4.0 / halo2_gadgets 0.6.0 / halo2_poseidon 0.2.0 |
| Poseidon | P128Pow5T3，width=3，rate=2 |
| Grant / Revocation Tree | 16 槽位，深度 4，域分离 D_GRANT / D_REVOKE / D_NODE |
| Halo2 k / domain size | 12 / 4096（域大小不是实际约束行数） |
| 公共输入数 | 5，顺序 (GR, RR, policyTag, epoch, Dq) |
| 授权路径 | 固定两级：g0 根授权 + g1 子授权 |
| 权限掩码 | read=001, write=010, invoke=100 |
| 采样 | 预热 1 次 + 测量 10 次/指标 |

## 2. 证明关系

公共输入 x = (GR, RR, policyTag, epoch, Dq)，私有 witness 包含两条 Grant 记录、
两套 Merkle opening、撤销状态位以及请求字段。电路约束：

- 两条记录各自重算到公开 GR；对应槽位各自重算到公开 RR 且 revoked=0；
- g0.parent=0，g1.parent=g0.id，g1.issuer=g0.subject，g1.subject=request.agent；
- resource 一致；子权限逐位包含于父权限且覆盖请求动作；
- 请求时间落在两条授权区间内，子区间嵌套于父区间（8-bit 差值非负 + 8-bit range check）；
- 电路内用 Poseidon 重算 Dq 并绑定到 instance。

**ALLOW ≠ DENY**：本实验只证明一条具体路径存在。没有 ALLOW proof 时 Gateway fail-closed，
但不等于证明整个授权图不存在其他有效路径。

## 3. 固定数据集

| Grant | issuer → subject | scope | 有效期 | parent | 索引 |
| --- | --- | --- | --- | --- | --- |
| g1 | Root-1 → Agent-A | read | 2–20 | 0 | 1 |
| g2 | Root-2 → Agent-B | read | 2–20 | 0 | 2 |
| g3 | Agent-A → Agent-C | read | 2–20 | g1 | 3 |
| g4 | Agent-B → Agent-C | read | 2–20 | g2 | 4 |
| g5 | Agent-A → Agent-C | write | 2–20 | g1 | 5 |
| g6 | Agent-B → Agent-C | read | 2–9（时间 10 已过期） | g2 | 6 |

统一请求：Agent-C / tool:translate / read / time=10 / policy-v1 / epoch=8。
撤销场景：撤销 g1 后 g1+g3 失效，g2+g4 仍可生成有效证明。

## 4. 14 项测试结果

| 编号 | 场景 | 预期 | MockProver |
| --- | --- | --- | --- |
| T1 | 撤销前 g1+g3 | 通过 | PASS |
| T2 | 撤销 g1 后仍用 g1+g3 | 拒绝 | PASS |
| T3 | 撤销 g1 后改用 g2+g4 | 通过 | PASS |
| T4 | 子授权 parent_id 被篡改 | 拒绝 | PASS |
| T5 | issuer 不等于父授权 subject | 拒绝 | PASS |
| T6 | 子权限超出父权限 | 拒绝 | PASS |
| T7 | 请求动作不在 scope 中 | 拒绝 | PASS |
| T8 | 授权过期 | 拒绝 | PASS |
| T9 | 请求时间早于生效时间 | 拒绝 | PASS |
| T10 | Grant Merkle path 被篡改 | 拒绝 | PASS |
| T11 | Revocation path 或状态位被篡改 | 拒绝 | PASS |
| T12 | requestDigest 被篡改 | 拒绝 | PASS |
| T13 | 撤销后 Registry 的 g1+g3 真实 witness + 对应 roots | 拒绝 | PASS |
| T14 | 撤销后 Registry 的 g2+g4 真实 witness + 对应 roots | 通过 | PASS |

T1 与 T3 另各自完成一次**真实 proof**：`Params::new` → `keygen_vk` → `keygen_pk` →
`create_proof` → `verify_proof`，并且同一 proof 在篡改后的 Dq instance 下被拒绝。
T13 另完成一次真实负向证明构造（见第 5 节 R1 说明）。
MockProver 只用于约束调试与负向验证，不计入真实证明结论。

## 5. R1 安全修正：电路强制未撤销（Enforce Non-Revocation）

### R0 缺陷

R0 电路中，撤销状态 `g0_revoked` / `g1_revoked` 仅通过 `assign_bool` 做布尔约束，
然后作为撤销树叶子 `Poseidon(D_REVOKE, id, revoked)` 的输入重算到公开 RR。
但电路**没有约束 revoked = 0**。因此 R0 只证明“某个撤销状态包含在公开 RR 中”，
并不证明该状态是“未撤销”。本地诊断实证：用撤销后 Registry 的真实 g1（revoked=1）
与 g3 witness、以及同一 Registry 的 GR/RR 作为公开输入，MockProver 错误返回 `Ok(())`。

原 T2/T11 未能发现此问题：它们的 witness 来自撤销前 Registry，却配撤销后的根，
失败原因是 Merkle 根不匹配，而非撤销语义，属于弱测试。

### R1 修复（电路级）

在 `src/circuit.rs` 新增专用 advice 列 `no_revoke_col` 与选择器 `q_no_revoke`，
新增 gate `not-revoked`: q_no_revoke · revoked = 0；在 witness region 中把两条撤销状态
cell 通过 equality 绑定到该列并启用选择器。keygen 与 proving 的电路结构一致
（`without_witnesses` 同样启用该 gate），撤销树 membership 检查完整保留。
约束在电路中，不在 reference model 或 witness 构造函数中。

### T13 / T14 关键验收

- **T13**：从撤销后 Registry 取 g1+g3 的真实 witness 与对应 GR/RR，opening 自检通过；
  电路拒绝，且失败原因精确来自 `not-revoked` gate（`cell_values` 中 revoked=1），
  不是根不匹配——直接覆盖上述漏洞。
- **T14**：同一撤销后 Registry 的独立路径 g2+g4 仍通过，修复未误伤独立授权来源。

### T13 真实负向证明构造（如实记录）

用撤销后 g1+g3 witness 与匹配 roots 执行 `create_proof`：本机 Halo2 0.4 的 prover
**未做约束自检，仍生成了 proof**；随后 `verify_proof` 在相同 instance 下拒绝该 proof。
因此结论是“撤销路径无法产生可通过验证的 proof”，而非“create_proof 因约束失败”。
这是 Halo2 prover 的行为事实，不写成 verifier 拒绝了一个有效 proof。

### 电路结构与性能

R1 相对 R0 新增 1 个 advice 列、1 个 selector、1 个 gate（not-revoked），并在 witness region
增加 2 处 copy_advice 与 2 处 selector enable；门结构因此改变。本轮按要求未做完整性能重测，
第 6 节的性能数字仍为 R0 采集的原型微基准。R1 已验证至少一次 T1/T3 真实 proof roundtrip
与一次 T13 真实负向构造均成功执行。

## 6. 性能结果（release，预热 1 次 + 10 次采样）

### RAYON_NUM_THREADS=1

| 记录数 | 参数生成 mean | keygen mean | 证明生成 mean / median / P95 | 验证 mean / median / P95 | proof_bytes |
| --- | --- | --- | --- | --- | --- |
| 4 | 2932.631 | 1604.345 | 2104.510 / 2101.429 / 2131.144 | 47.247 / 47.105 / 48.090 | 5824 |
| 6 | 2927.333 | 1610.135 | 2120.783 / 2111.021 / 2195.163 | 47.370 / 47.231 / 49.353 | 5824 |
| 8 | 2904.618 | 1608.606 | 2091.131 / 2095.394 / 2119.997 | 46.586 / 46.730 / 47.780 | 5824 |
| 12 | 2918.199 | 1573.013 | 2045.339 / 2043.186 / 2118.003 | 46.703 / 45.354 / 55.779 | 5824 |

### RAYON_NUM_THREADS=8

| 记录数 | 参数生成 mean | keygen mean | 证明生成 mean / median / P95 | 验证 mean / median / P95 | proof_bytes |
| --- | --- | --- | --- | --- | --- |
| 4 | 2921.848 | 1624.010 | 2105.132 / 2100.511 / 2150.682 | 49.154 / 47.463 / 59.625 | 5824 |
| 6 | 2875.222 | 1591.086 | 2072.016 / 2066.240 / 2186.815 | 47.044 / 46.379 / 54.258 | 5824 |
| 8 | 2907.844 | 1581.092 | 2061.342 / 2062.838 / 2106.386 | 47.115 / 46.310 / 51.934 | 5824 |
| 12 | 2928.284 | 1595.562 | 2060.224 / 2068.176 / 2118.736 | 46.433 / 45.829 / 53.457 | 5824 |

## 7. 研究问题：授权来源越多，证明成本是否必然越高？

固定深度 4、固定路径 g2+g4，仅改变登记记录数 4 / 6 / 8 / 12：

| 线程设置 | 4 条 mean | 6 条 mean | 8 条 mean | 12 条 mean |
| --- | --- | --- | --- | --- |
| threads_1 | 2104.510 | 2120.783 | 2091.131 | 2045.339 |
| threads_8 | 2105.132 | 2072.016 | 2061.342 | 2060.224 |

观察：证明电路只打开固定长度的两条路径，记录数变化不改变门结构与列布局；
变化的是公开根 GR/RR 与 prover 的路径选择。上述数字是**本原型在本机**的实测，
不能外推为所有授权图规模下的渐近结论；判断“是否必然更高”仍需更大容量与更宽记录区间。

## 8. 边界与未证明事项

- 不证明 DENY / 不存在性；fail-closed 是 Gateway 策略，不是电路结论。
- 不在电路内验证 Root / 委托者 Ed25519 签名；注册表构建前验证签发者是外部假设。
- Poseidon GR/RR 与 D1-E 的 state_root / log_root 是不同承诺；本轮不声称已获 quorum 认证。
- D2-B 的 ZkStateAnchor 尚未实现，公共输入的可信来源仍是独立问题。
- k=12 是域参数，2^12 是域大小，不代表实际约束行数。
- 所有毫秒数为 Halo2 原型微基准，不含网络、序列化 I/O 与生产硬件差异。

## 9. 复现

```bash
cargo test --locked
RAYON_NUM_THREADS=1 cargo run --release --bin benchmark
RAYON_NUM_THREADS=8 cargo run --release --bin benchmark
python tools/export_results.py
```

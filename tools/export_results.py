#!/usr/bin/env python3
"""Build summary.csv and experiment_report.md from benchmark output and test log."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

TESTS = [
    ("T1", "撤销前 g1+g3", "通过"),
    ("T2", "撤销 g1 后仍用 g1+g3", "拒绝"),
    ("T3", "撤销 g1 后改用 g2+g4", "通过"),
    ("T4", "子授权 parent_id 被篡改", "拒绝"),
    ("T5", "issuer 不等于父授权 subject", "拒绝"),
    ("T6", "子权限超出父权限", "拒绝"),
    ("T7", "请求动作不在 scope 中", "拒绝"),
    ("T8", "授权过期", "拒绝"),
    ("T9", "请求时间早于生效时间", "拒绝"),
    ("T10", "Grant Merkle path 被篡改", "拒绝"),
    ("T11", "Revocation path 或状态位被篡改", "拒绝"),
    ("T12", "requestDigest 被篡改", "拒绝"),
]

TEST_FILE_MAP = {
    "T1": "t1_before_revocation_g1_g3_accepted",
    "T2": "t2_revoked_g1_g3_rejected",
    "T3": "t3_after_revoking_g1_g2_g4_accepted",
    "T4": "t4_child_parent_id_tampered_rejected",
    "T5": "t5_issuer_continuity_violated_rejected",
    "T6": "t6_child_scope_exceeds_parent_rejected",
    "T7": "t7_request_action_outside_scope_rejected",
    "T8": "t8_expired_grant_rejected",
    "T9": "t9_request_before_valid_from_rejected",
    "T10": "t10_grant_merkle_path_tampered_rejected",
    "T11": "t11_revocation_path_or_bit_tampered_rejected",
    "T12": "t12_request_digest_tampered_rejected",
}

METRICS = [
    ("params_generation_ms", "Params::new 参数生成 (ms)"),
    ("keygen_ms", "keygen_vk + keygen_pk (ms)"),
    ("proof_generation_ms", "create_proof 真实证明生成 (ms)"),
    ("proof_verification_ms", "verify_proof 真实证明验证 (ms)"),
]


def fmt(value: float) -> str:
    return f"{value:.3f}"


def load_test_log() -> dict:
    text = (RESULTS / "test_log.txt").read_text(encoding="utf-8", errors="replace")
    status = {}
    for name in TEST_FILE_MAP.values():
        status[name] = bool(re.search(rf"^test {re.escape(name)} \.\.\. ok$", text, re.M))
    total = re.findall(r"test result: ok\. (\d+) passed", text)
    return {"names": status, "totals": [int(n) for n in total], "text": text}


def write_summary(raw: dict, log: dict) -> None:
    rows = []
    for tid, description, expected in TESTS:
        passed = log["names"][TEST_FILE_MAP[tid]]
        rows.append({
            "section": "attack",
            "id": tid,
            "item": description,
            "expected": expected,
            "observed": "接受" if expected == "通过" else "拒绝",
            "result": "PASS" if passed else "FAIL",
            "mean": "", "median": "", "p95": "", "samples": "",
        })

    for label, runs in sorted(raw["runs"].items()):
        for run_name, data in sorted(runs.items()):
            for metric, description in METRICS:
                stats = data[metric]
                rows.append({
                    "section": "performance",
                    "id": f"{label}/{run_name}",
                    "item": description,
                    "expected": "",
                    "observed": "",
                    "result": "OK",
                    "mean": fmt(stats["mean"]),
                    "median": fmt(stats["median"]),
                    "p95": fmt(stats["p95"]),
                    "samples": stats["samples"],
                })
            rows.append({
                "section": "performance",
                "id": f"{label}/{run_name}",
                "item": "proof_bytes (bytes)",
                "expected": "", "observed": "", "result": "OK",
                "mean": str(int(data["proof_bytes"])), "median": "", "p95": "", "samples": 10,
            })

    with (RESULTS / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "section", "id", "item", "expected", "observed", "result",
            "mean", "median", "p95", "samples",
        ])
        writer.writeheader()
        writer.writerows(rows)


def perf_table(raw: dict, label: str) -> list[str]:
    lines = [
        "| 记录数 | 参数生成 mean | keygen mean | 证明生成 mean / median / P95 | 验证 mean / median / P95 | proof_bytes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    runs = raw["runs"].get(label, {})
    for name in sorted(runs, key=lambda s: int(s.split("_")[1])):
        d = runs[name]
        pg, pv = d["proof_generation_ms"], d["proof_verification_ms"]
        lines.append(
            "| %s | %s | %s | %s / %s / %s | %s / %s / %s | %d |" % (
                name.split("_")[1],
                fmt(d["params_generation_ms"]["mean"]), fmt(d["keygen_ms"]["mean"]),
                fmt(pg["mean"]), fmt(pg["median"]), fmt(pg["p95"]),
                fmt(pv["mean"]), fmt(pv["median"]), fmt(pv["p95"]),
                int(d["proof_bytes"]),
            )
        )
    return lines


def write_report(raw: dict, log: dict) -> None:
    lines = []
    add = lines.append
    add("# EXP-D2-A 实验报告")
    add("")
    add("Private Authorization Path Proof with Halo2")
    add("")
    add("> 实验性质：**Halo2 电路原型 + 真实证明成本测量**。不是完整授权系统，不是 DENY/不存在性证明，")
    add("> 不是 D1-E checkpoint 的链上锚定，也不验证 Ed25519 签发者签名。")
    add("")
    add("## 1. 固定参数")
    add("")
    add("| 参数 | 值 |")
    add("| --- | --- |")
    add("| 曲线 / 域 | Pallas 标量域（电路域），IPA 承诺曲线 vesta |")
    add("| Halo2 | halo2_proofs 0.4.0 / halo2_gadgets 0.6.0 / halo2_poseidon 0.2.0 |")
    add("| Poseidon | P128Pow5T3，width=3，rate=2 |")
    add("| Grant / Revocation Tree | 16 槽位，深度 4，域分离 D_GRANT / D_REVOKE / D_NODE |")
    add("| Halo2 k / domain size | %d / %d（域大小不是实际约束行数） |" % (
        raw["k"], raw["domain_size"]))
    add("| 公共输入数 | %d，顺序 (GR, RR, policyTag, epoch, Dq) |" % raw["public_input_count"])
    add("| 授权路径 | 固定两级：g0 根授权 + g1 子授权 |")
    add("| 权限掩码 | read=001, write=010, invoke=100 |")
    add("| 采样 | 预热 %d 次 + 测量 %d 次/指标 |" % (
        raw["warmup_iterations"], raw["iterations"]))
    add("")
    add("## 2. 证明关系")
    add("")
    add("公共输入 x = (GR, RR, policyTag, epoch, Dq)，私有 witness 包含两条 Grant 记录、")
    add("两套 Merkle opening、撤销状态位以及请求字段。电路约束：")
    add("")
    add("- 两条记录各自重算到公开 GR；对应槽位各自重算到公开 RR 且 revoked=0；")
    add("- g0.parent=0，g1.parent=g0.id，g1.issuer=g0.subject，g1.subject=request.agent；")
    add("- resource 一致；子权限逐位包含于父权限且覆盖请求动作；")
    add("- 请求时间落在两条授权区间内，子区间嵌套于父区间（8-bit 差值非负 + 8-bit range check）；")
    add("- 电路内用 Poseidon 重算 Dq 并绑定到 instance。")
    add("")
    add("**ALLOW ≠ DENY**：本实验只证明一条具体路径存在。没有 ALLOW proof 时 Gateway fail-closed，")
    add("但不等于证明整个授权图不存在其他有效路径。")
    add("")
    add("## 3. 固定数据集")
    add("")
    add("| Grant | issuer → subject | scope | 有效期 | parent | 索引 |")
    add("| --- | --- | --- | --- | --- | --- |")
    for row in [
        ("g1", "Root-1 → Agent-A", "read", "2–20", "0", "1"),
        ("g2", "Root-2 → Agent-B", "read", "2–20", "0", "2"),
        ("g3", "Agent-A → Agent-C", "read", "2–20", "g1", "3"),
        ("g4", "Agent-B → Agent-C", "read", "2–20", "g2", "4"),
        ("g5", "Agent-A → Agent-C", "write", "2–20", "g1", "5"),
        ("g6", "Agent-B → Agent-C", "read", "2–9（时间 10 已过期）", "g2", "6"),
    ]:
        add("| %s | %s | %s | %s | %s | %s |" % row)
    add("")
    add("统一请求：Agent-C / tool:translate / read / time=10 / policy-v1 / epoch=8。")
    add("撤销场景：撤销 g1 后 g1+g3 失效，g2+g4 仍可生成有效证明。")
    add("")
    add("## 4. 12 项测试结果")
    add("")
    add("| 编号 | 场景 | 预期 | MockProver |")
    add("| --- | --- | --- | --- |")
    for tid, description, expected in TESTS:
        passed = log["names"][TEST_FILE_MAP[tid]]
        add("| %s | %s | %s | %s |" % (tid, description, expected, "PASS" if passed else "FAIL"))
    add("")
    add("T1 与 T3 另各自完成一次**真实 proof**：`Params::new` → `keygen_vk` → `keygen_pk` →")
    add("`create_proof` → `verify_proof`，并且同一 proof 在篡改后的 Dq instance 下被拒绝。")
    add("MockProver 只用于约束调试与负向验证，不计入真实证明结论。")
    add("")
    add("## 5. 性能结果（release，预热 1 次 + 10 次采样）")
    add("")
    for label in sorted(raw["runs"]):
        threads = label.split("_")[1]
        add("### RAYON_NUM_THREADS=%s" % threads)
        add("")
        lines.extend([])
        add("\n".join(perf_table(raw, label)))
        add("")
    add("## 6. 研究问题：授权来源越多，证明成本是否必然越高？")
    add("")
    gen = {}
    for label, runs in raw["runs"].items():
        gen[label] = {
            n: d["proof_generation_ms"]["mean"]
            for n, d in ((int(k.split("_")[1]), v) for k, v in runs.items())
        }
    add("固定深度 4、固定路径 g2+g4，仅改变登记记录数 4 / 6 / 8 / 12：")
    add("")
    add("| 线程设置 | 4 条 mean | 6 条 mean | 8 条 mean | 12 条 mean |")
    add("| --- | --- | --- | --- | --- |")
    for label, values in sorted(gen.items()):
        add("| %s | %s | %s | %s | %s |" % (
            label, fmt(values[4]), fmt(values[6]), fmt(values[8]), fmt(values[12])))
    add("")
    add("观察：证明电路只打开固定长度的两条路径，记录数变化不改变门结构与列布局；")
    add("变化的是公开根 GR/RR 与 prover 的路径选择。上述数字是**本原型在本机**的实测，")
    add("不能外推为所有授权图规模下的渐近结论；判断“是否必然更高”仍需更大容量与更宽记录区间。")
    add("")
    add("## 7. 边界与未证明事项")
    add("")
    add("- 不证明 DENY / 不存在性；fail-closed 是 Gateway 策略，不是电路结论。")
    add("- 不在电路内验证 Root / 委托者 Ed25519 签名；注册表构建前验证签发者是外部假设。")
    add("- Poseidon GR/RR 与 D1-E 的 state_root / log_root 是不同承诺；本轮不声称已获 quorum 认证。")
    add("- D2-B 的 ZkStateAnchor 尚未实现，公共输入的可信来源仍是独立问题。")
    add("- k=12 是域参数，2^12 是域大小，不代表实际约束行数。")
    add("- 所有毫秒数为 Halo2 原型微基准，不含网络、序列化 I/O 与生产硬件差异。")
    add("")
    add("## 8. 复现")
    add("")
    add("```bash")
    add("cargo test --locked")
    add('RAYON_NUM_THREADS=1 cargo run --release --bin benchmark')
    add('RAYON_NUM_THREADS=8 cargo run --release --bin benchmark')
    add("python tools/export_results.py")
    add("```")
    add("")

    (RESULTS / "experiment_report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    raw = json.loads((RESULTS / "raw_results.json").read_text(encoding="utf-8"))
    log = load_test_log()
    write_summary(raw, log)
    write_report(raw, log)
    print("wrote results/summary.csv and results/experiment_report.md")


if __name__ == "__main__":
    main()

//! EXP-D2-A performance harness.
//!
//! Run once per thread setting:
//!   RAYON_NUM_THREADS=1 cargo run --release --bin benchmark
//!   RAYON_NUM_THREADS=8 cargo run --release --bin benchmark
//!
//! The first run writes results/bench_1.json; later runs merge all thread
//! settings into results/raw_results.json.  One warm-up iteration precedes
//! ten measured iterations for every timed metric.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use agent_authz_halo2_exp::circuit::{AuthPathCircuit, PathWitness};
use agent_authz_halo2_exp::model::Request;
use agent_authz_halo2_exp::public_inputs::PublicInputs;
use agent_authz_halo2_exp::registry::Registry;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Map, Value};

const K: u32 = 12;
const ITERATIONS: usize = 10;
const WARMUP: usize = 1;
const RECORD_COUNTS: [usize; 4] = [4, 6, 8, 12];

fn stats(samples: &[f64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };
    let p95_index = ((n as f64 - 1.0) * 0.95).ceil() as usize;
    json!({
        "mean": mean,
        "median": median,
        "p95": sorted[p95_index.min(n - 1)],
        "samples": n,
        "raw_ms": sorted,
    })
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn measure_records(n: usize, threads_label: &str) -> Value {
    let request = Request::fixed();
    let registry = Registry::with_record_count(n, &[]).unwrap();
    let public = PublicInputs::new(registry.grant_root, registry.revoke_root, &request);
    let witness = PathWitness {
        g0: registry.witness("g2").unwrap(),
        g1: registry.witness("g4").unwrap(),
        request: request.fields(),
    };
    let instance = public.to_instance();
    let instances = vec![instance];
    let instance_refs: Vec<&[F]> = instances.iter().map(|v| &v[..]).collect();
    let all_instances: Vec<&[&[F]]> = vec![&instance_refs];

    let mut params_samples = Vec::new();
    let mut keygen_samples = Vec::new();
    let mut prove_samples = Vec::new();
    let mut verify_samples = Vec::new();
    let mut proof_bytes: f64 = 0.0;

    for iteration in 0..(WARMUP + ITERATIONS) {
        let t = Instant::now();
        let params = Params::<vesta::Affine>::new(K);
        let params_ms = ms(t);
        if iteration >= WARMUP {
            params_samples.push(params_ms);
        }

        let shape = AuthPathCircuit::for_keygen(public);
        let t = Instant::now();
        let vk = keygen_vk(&params, &shape).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
        let keygen_ms = ms(t);
        if iteration >= WARMUP {
            keygen_samples.push(keygen_ms);
        }

        let circuit = AuthPathCircuit::new(public, witness.clone());
        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &all_instances,
            StdRng::seed_from_u64(20261123),
            &mut transcript,
        )
        .expect("create_proof");
        let proof = transcript.finalize();
        let prove_ms = ms(t);
        if iteration >= WARMUP {
            prove_samples.push(prove_ms);
            proof_bytes = proof.len() as f64;
        }

        let t = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut reader = Blake2bRead::init(&proof[..]);
        verify_proof(&params, &vk, strategy, &all_instances, &mut reader)
            .expect("verify_proof");
        let verify_ms = ms(t);
        if iteration >= WARMUP {
            verify_samples.push(verify_ms);
        }
    }

    json!({
        "threads_env": threads_label,
        "records": n,
        "proof_bytes": proof_bytes,
        "params_generation_ms": stats(&params_samples),
        "keygen_ms": stats(&keygen_samples),
        "proof_generation_ms": stats(&prove_samples),
        "proof_verification_ms": stats(&verify_samples),
    })
}

fn main() {
    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".to_string());
    let label = format!("threads_{}", threads);
    println!("EXP-D2-A benchmark: RAYON_NUM_THREADS={threads}");

    let mut runs = Map::new();
    for n in RECORD_COUNTS {
        println!("  records={n} ...");
        let value = measure_records(n, &threads);
        runs.insert(format!("records_{n}"), value);
    }

    let out_dir = PathBuf::from("results");
    fs::create_dir_all(&out_dir).unwrap();
    let fragment_path = out_dir.join(format!("bench_{}.json", threads));
    fs::write(
        &fragment_path,
        serde_json::to_string_pretty(&json!({ "label": label, "runs": runs })).unwrap(),
    )
    .unwrap();
    println!("wrote {}", fragment_path.display());

    // Merge every available thread fragment into raw_results.json.
    let mut merged = Map::new();
    merged.insert("experiment".to_string(), json!("EXP-D2-A"));
    merged.insert("revision".to_string(), json!("R0"));
    merged.insert("k".to_string(), json!(K));
    merged.insert("domain_size".to_string(), json!(1u64 << K));
    merged.insert("public_input_count".to_string(), json!(5));
    merged.insert("registry_capacity".to_string(), json!(16));
    merged.insert("tree_depth".to_string(), json!(4));
    merged.insert("warmup_iterations".to_string(), json!(WARMUP));
    merged.insert("iterations".to_string(), json!(ITERATIONS));
    let mut all_runs = Map::new();
    for entry in fs::read_dir(&out_dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("bench_") || !name.ends_with(".json") {
            continue;
        }
        let data: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Some(key) = data["label"].as_str() {
            all_runs.insert(key.to_string(), data["runs"].clone());
        }
    }
    merged.insert("runs".to_string(), Value::Object(all_runs));
    let raw_path = out_dir.join("raw_results.json");
    fs::write(
        &raw_path,
        serde_json::to_string_pretty(&Value::Object(merged)).unwrap(),
    )
    .unwrap();
    println!("wrote {}", raw_path.display());
}

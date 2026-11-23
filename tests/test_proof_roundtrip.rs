//! Real Halo2 proof generation and verification for T1 and T3.
//!
//! MockProver is never used in this file: every acceptance claim here is backed
//! by `Params::new` / `keygen_vk` / `keygen_pk` / `create_proof` / `verify_proof`.

use agent_authz_halo2_exp::circuit::{AuthPathCircuit, PathWitness};
use agent_authz_halo2_exp::model::Request;
use agent_authz_halo2_exp::public_inputs::PublicInputs;
use agent_authz_halo2_exp::registry::Registry;
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

const K: u32 = 12;

fn build_proof(public: PublicInputs, witness: PathWitness) -> Vec<u8> {
    build_proof_result(public, witness).expect("create_proof")
}

/// Like `build_proof` but returns the raw `create_proof` result so negative
/// tests can record the exact Halo2 error without panicking.
fn build_proof_result(
    public: PublicInputs,
    witness: PathWitness,
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    let params = Params::<vesta::Affine>::new(K);
    let shape = AuthPathCircuit::for_keygen(public);
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &shape).expect("keygen_pk");

    let circuit = AuthPathCircuit::new(public, witness);
    let instance = public.to_instance();
    let instances = vec![instance];
    let instance_refs: Vec<&[F]> = instances.iter().map(|v| &v[..]).collect();
    let all_instances: Vec<&[&[F]]> = vec![&instance_refs];

    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &all_instances,
        StdRng::seed_from_u64(20261123),
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

fn verify(public: PublicInputs, proof: &[u8]) -> bool {
    let params = Params::<vesta::Affine>::new(K);
    let shape = AuthPathCircuit::for_keygen(public);
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let instance = public.to_instance();
    let instances = vec![instance];
    let instance_refs: Vec<&[F]> = instances.iter().map(|v| &v[..]).collect();
    let all_instances: Vec<&[&[F]]> = vec![&instance_refs];
    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::init(proof);
    verify_proof(&params, &vk, strategy, &all_instances, &mut reader).is_ok()
}

#[test]
fn t1_real_proof_before_revocation() {
    let reg = Registry::fixed(&[]).unwrap();
    let request = Request::fixed();
    let public = PublicInputs::new(reg.grant_root, reg.revoke_root, &request);
    let witness = PathWitness {
        g0: reg.witness("g1").unwrap(),
        g1: reg.witness("g3").unwrap(),
        request: request.fields(),
    };
    let proof = build_proof(public, witness);
    assert!(!proof.is_empty());
    assert!(verify(public, &proof));
}

#[test]
fn t3_real_proof_after_revoking_g1() {
    let reg = Registry::fixed(&["g1"]).unwrap();
    let request = Request::fixed();
    let public = PublicInputs::new(reg.grant_root, reg.revoke_root, &request);
    let witness = PathWitness {
        g0: reg.witness("g2").unwrap(),
        g1: reg.witness("g4").unwrap(),
        request: request.fields(),
    };
    let proof = build_proof(public, witness);
    assert!(verify(public, &proof));

    // The same proof must be rejected under a different public request digest.
    let mut altered = public;
    altered.request_digest += F::ONE;
    assert!(!verify(altered, &proof));
}

/// T13 real-proof negative construction.  Uses the after-revocation registry's
/// real g1+g3 witnesses with matching public roots.  We record the RAW Halo2
/// outcome: either `create_proof` fails on the unsatisfied `not-revoked`
/// constraint, or a proof is produced but `verify_proof` rejects it.  We never
/// describe a verifier rejection as "a valid proof was rejected".
#[test]
fn t13_real_proof_revoked_path_cannot_yield_valid_proof() {
    let reg = Registry::fixed(&["g1"]).unwrap();
    let request = Request::fixed();
    let public = PublicInputs::new(reg.grant_root, reg.revoke_root, &request);
    let witness = PathWitness {
        g0: reg.witness("g1").unwrap(), // revoked = true
        g1: reg.witness("g3").unwrap(),
        request: request.fields(),
    };
    assert!(witness.g0.revoked);

    match build_proof_result(public, witness) {
        Err(err) => {
            // Halo2 refused at proof construction: record the exact error.
            eprintln!("T13 create_proof error (raw): {}", err);
            let msg = format!("{}", err);
            assert!(
                !msg.is_empty(),
                "expected a non-empty constraint error for the revoked path"
            );
        }
        Ok(proof) => {
            // Halo2 produced a proof despite the unsatisfied witness; the
            // authoritative check is then verifier rejection.
            eprintln!("T13 create_proof succeeded; falling back to verifier check");
            assert!(!proof.is_empty());
            assert!(
                !verify(public, &proof),
                "a proof for a revoked path must not verify"
            );
        }
    }
}

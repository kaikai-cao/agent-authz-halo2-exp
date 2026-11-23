//! T1-T12: fixed MockProver acceptance matrix.
//!
//! T1 and T3 are additionally proved with real Halo2 proofs in
//! `test_proof_roundtrip.rs`; here all twelve cases use MockProver.

use agent_authz_halo2_exp::circuit::{AuthPathCircuit, PathWitness};
use agent_authz_halo2_exp::model::{Request, SCOPE_WRITE};
use agent_authz_halo2_exp::public_inputs::PublicInputs;
use agent_authz_halo2_exp::registry::Registry;
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

pub const K: u32 = 12;

pub fn circuit_for(registry: &Registry, id0: &str, id1: &str, request: &Request) -> AuthPathCircuit {
    let public = PublicInputs::new(registry.grant_root, registry.revoke_root, request);
    let witness = PathWitness {
        g0: registry.witness(id0).unwrap(),
        g1: registry.witness(id1).unwrap(),
        request: request.fields(),
    };
    AuthPathCircuit::new(public, witness)
}

pub fn mock_accepts(circuit: &AuthPathCircuit) -> bool {
    let instance = circuit.public.to_instance().to_vec();
    match MockProver::run(K, circuit, vec![instance]) {
        Ok(prover) => prover.verify().is_ok(),
        Err(err) => {
            eprintln!("synthesize failed: {:?}", err);
            false
        }
    }
}

#[test]
fn t1_before_revocation_g1_g3_accepted() {
    let reg = Registry::fixed(&[]).unwrap();
    assert!(mock_accepts(&circuit_for(&reg, "g1", "g3", &Request::fixed())));
}

#[test]
fn t2_revoked_g1_g3_rejected() {
    let before = Registry::fixed(&[]).unwrap();
    let after = Registry::fixed(&["g1"]).unwrap();
    let request = Request::fixed();
    let public = PublicInputs::new(after.grant_root, after.revoke_root, &request);
    let witness = PathWitness {
        g0: before.witness("g1").unwrap(),
        g1: before.witness("g3").unwrap(),
        request: request.fields(),
    };
    assert!(!mock_accepts(&AuthPathCircuit::new(public, witness)));
}

#[test]
fn t3_after_revoking_g1_g2_g4_accepted() {
    let reg = Registry::fixed(&["g1"]).unwrap();
    assert!(mock_accepts(&circuit_for(&reg, "g2", "g4", &Request::fixed())));
}

#[test]
fn t4_child_parent_id_tampered_rejected() {
    let mut grants = agent_authz_halo2_exp::model::fixed_grants();
    grants[2].parent = "g2".into();
    let reg = Registry::build(grants, &[]).unwrap();
    assert!(!mock_accepts(&circuit_for(&reg, "g1", "g3", &Request::fixed())));
}

#[test]
fn t5_issuer_continuity_violated_rejected() {
    let mut grants = agent_authz_halo2_exp::model::fixed_grants();
    grants[2].issuer = "Agent-B".into();
    let reg = Registry::build(grants, &[]).unwrap();
    assert!(!mock_accepts(&circuit_for(&reg, "g1", "g3", &Request::fixed())));
}

#[test]
fn t6_child_scope_exceeds_parent_rejected() {
    let mut grants = agent_authz_halo2_exp::model::fixed_grants();
    grants[2].scope = SCOPE_WRITE;
    let reg = Registry::build(grants, &[]).unwrap();
    assert!(!mock_accepts(&circuit_for(&reg, "g1", "g3", &Request::fixed())));
}

#[test]
fn t7_request_action_outside_scope_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    let mut request = Request::fixed();
    request.action = SCOPE_WRITE;
    assert!(!mock_accepts(&circuit_for(&reg, "g1", "g3", &request)));
}

#[test]
fn t8_expired_grant_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    assert!(!mock_accepts(&circuit_for(&reg, "g2", "g6", &Request::fixed())));
}

#[test]
fn t9_request_before_valid_from_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    let mut request = Request::fixed();
    request.time = 1;
    assert!(!mock_accepts(&circuit_for(&reg, "g2", "g4", &request)));
}

#[test]
fn t10_grant_merkle_path_tampered_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    let mut circuit = circuit_for(&reg, "g2", "g4", &Request::fixed());
    circuit.witness.as_mut().unwrap().g1.grant_path[0].0 += F::ONE;
    assert!(!mock_accepts(&circuit));
}

#[test]
fn t11_revocation_path_or_bit_tampered_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    let mut circuit = circuit_for(&reg, "g2", "g4", &Request::fixed());
    circuit.witness.as_mut().unwrap().g1.revoked = true;
    assert!(!mock_accepts(&circuit));

    let mut circuit = circuit_for(&reg, "g2", "g4", &Request::fixed());
    circuit.witness.as_mut().unwrap().g1.revocation_path[2].0 += F::ONE;
    assert!(!mock_accepts(&circuit));
}

#[test]
fn t12_request_digest_tampered_rejected() {
    let reg = Registry::fixed(&[]).unwrap();
    let mut circuit = circuit_for(&reg, "g2", "g4", &Request::fixed());
    circuit.public.request_digest += F::ONE;
    assert!(!mock_accepts(&circuit));
}

#[test]
fn instance_layout_has_five_public_values() {
    let reg = Registry::fixed(&[]).unwrap();
    let circuit = circuit_for(&reg, "g1", "g3", &Request::fixed());
    assert_eq!(circuit.public.to_instance().len(), 5);
    assert_ne!(circuit.public.grant_root, F::ZERO);
    assert_ne!(circuit.public.revoke_root, F::ZERO);
}

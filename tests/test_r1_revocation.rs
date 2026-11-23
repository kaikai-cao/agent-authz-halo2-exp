//! EXP-D2-A-R1 security fix tests: T13 / T14.
//!
//! T13 is the key regression test.  It builds the *after-revocation* registry,
//! takes the *real* witnesses for the revoked path g1+g3, and uses that same
//! registry's GR/RR as public input.  Therefore the Merkle openings are valid
//! and both roots match; the only reason the proof can fail is the circuit's
//! `not-revoked` constraint.  The test asserts the failure is exactly that
//! gate, not a root mismatch.
//!
//! T14 confirms the independent path g2+g4 still verifies against the same
//! after-revocation registry, i.e. the fix does not harm legitimate sources.

use agent_authz_halo2_exp::circuit::{AuthPathCircuit, PathWitness};
use agent_authz_halo2_exp::model::Request;
use agent_authz_halo2_exp::public_inputs::PublicInputs;
use agent_authz_halo2_exp::registry::Registry;
use halo2_proofs::dev::MockProver;

const K: u32 = 12;

fn verify_failures(circuit: &AuthPathCircuit) -> Result<(), String> {
    let instance = circuit.public.to_instance().to_vec();
    match MockProver::run(K, circuit, vec![instance]) {
        Ok(p) => p.verify().map_err(|fs| format!("{:?}", fs)),
        Err(e) => Err(format!("synthesize failed: {:?}", e)),
    }
}

/// Render detailed failures so T13 can prove the failure gate is `not-revoked`.
/// `VerifyFailure` implements `Display`, including the gate name (e.g.
/// "Constraint 0 in gate 4 ('not-revoked')..."), so string matching is enough
/// and does not depend on private metadata fields.
fn failure_report(circuit: &AuthPathCircuit) -> String {
    let instance = circuit.public.to_instance().to_vec();
    match MockProver::run(K, circuit, vec![instance]) {
        Ok(p) => match p.verify() {
            Err(fs) => fs
                .iter()
                .map(|f| format!("{}", f))
                .collect::<Vec<_>>()
                .join("\n"),
            Ok(()) => String::new(),
        },
        Err(e) => format!("synthesize failed: {:?}", e),
    }
}

#[test]
fn t13_revoked_real_witness_matching_roots_rejected_by_not_revoked_gate() {
    // After-revocation registry: g1 revoked.  Witnesses come from this SAME
    // registry, so both Merkle openings are valid against its published roots.
    let after = Registry::fixed(&["g1"]).unwrap();
    let request = Request::fixed();
    let g0 = after.witness("g1").unwrap();
    let g1 = after.witness("g3").unwrap();

    assert!(g0.revoked, "g1 must be marked revoked in the after-registry");
    assert!(!g1.revoked, "g3 must remain unrevoked");
    assert!(
        after.openings_valid(&g0) && after.openings_valid(&g1),
        "the witnesses MUST open to the published GR/RR; otherwise this test"
    );

    let circuit = AuthPathCircuit::new(
        PublicInputs::new(after.grant_root, after.revoke_root, &request),
        PathWitness {
            g0,
            g1,
            request: request.fields(),
        },
    );

    // The circuit must reject.
    assert!(verify_failures(&circuit).is_err(), "revoked path was wrongly accepted");

    // The rejection must come from the `not-revoked` gate specifically, proving
    // it is the revocation constraint and NOT a Merkle-root mismatch.
    let report = failure_report(&circuit);
    assert!(
        report.contains("not-revoked"),
        "expected failure gate `not-revoked`, got report:\n{}",
        report
    );
}

#[test]
fn t14_independent_path_survives_revocation_with_matching_roots() {
    // Same after-revocation registry, but the independent g2+g4 path.
    let after = Registry::fixed(&["g1"]).unwrap();
    let request = Request::fixed();
    let g0 = after.witness("g2").unwrap();
    let g1 = after.witness("g4").unwrap();
    assert!(!g0.revoked && !g1.revoked);
    assert!(after.openings_valid(&g0) && after.openings_valid(&g1));

    let circuit = AuthPathCircuit::new(
        PublicInputs::new(after.grant_root, after.revoke_root, &request),
        PathWitness {
            g0,
            g1,
            request: request.fields(),
        },
    );
    assert!(
        verify_failures(&circuit).is_ok(),
        "independent path g2+g4 must still verify after g1 revocation"
    );
}

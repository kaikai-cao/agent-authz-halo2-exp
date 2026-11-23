//! Independent off-circuit reference model: T1/T2/T3 outcomes and each local rule.

use agent_authz_halo2_exp::model::{
    fixed_grants, Grant, Request, SCOPE_READ, SCOPE_WRITE,
};
use agent_authz_halo2_exp::reference::{
    evaluate_authorization_path, validate_grant_chain, validate_permission_attenuation,
    validate_revocation_state, validate_time_interval, Decision,
};
use agent_authz_halo2_exp::registry::Registry;

#[test]
fn reference_revocation_scenario_matches_task_spec() {
    let request = Request::fixed();
    let before = Registry::fixed(&[]).unwrap();
    let after = Registry::fixed(&["g1"]).unwrap();

    // T1 / T3
    assert_eq!(evaluate_authorization_path(&before, "g1", "g3", &request), Decision::Allow);
    assert_eq!(evaluate_authorization_path(&after, "g2", "g4", &request), Decision::Allow);
    // T2
    match evaluate_authorization_path(&after, "g1", "g3", &request) {
        Decision::Deny(reason) => assert!(reason.contains("revoked"), "{reason}"),
        Decision::Allow => panic!("revoked path must not be allowed"),
    }
}

#[test]
fn reference_local_rules_reject_each_tamper() {
    let request = Request::fixed();
    let grants = fixed_grants();
    let g1 = grants[0].clone();
    let g3 = grants[2].clone();

    let mut bad_parent = g3.clone();
    bad_parent.parent = "g2".into();
    assert!(validate_grant_chain(&g1, &bad_parent, &request).is_allow() == false);

    let mut bad_issuer = g3.clone();
    bad_issuer.issuer = "Agent-B".into();
    assert!(!validate_grant_chain(&g1, &bad_issuer, &request).is_allow());

    let mut bad_scope = g3.clone();
    bad_scope.scope = SCOPE_WRITE;
    assert!(!validate_permission_attenuation(&g1, &bad_scope, &request).is_allow());

    let expired_root = grants[1].clone();
    let expired_child = grants[5].clone();
    assert!(!validate_time_interval(&expired_root, &expired_child, &request).is_allow());

    let mut too_early = request.clone();
    too_early.time = 1;
    assert!(!validate_time_interval(&g1, &g3, &too_early).is_allow());
}

#[test]
fn reference_revocation_and_request_action_are_checked() {
    let request = Request::fixed();
    let after = Registry::fixed(&["g1"]).unwrap();
    assert!(!validate_revocation_state(&after, "g1").is_allow());
    assert!(validate_revocation_state(&after, "g2").is_allow());

    let mut write_request = request.clone();
    write_request.action = SCOPE_WRITE;
    let before = Registry::fixed(&[]).unwrap();
    // g1 read -> g3 read cannot satisfy a write request, even though g5 exists
    // as a separate write grant; the reference model checks this concrete path.
    let g1 = before.grant("g1").unwrap().clone();
    let g3 = before.grant("g3").unwrap().clone();
    assert!(!validate_permission_attenuation(&g1, &g3, &write_request).is_allow());
    assert_eq!(SCOPE_READ, 1);
}

#[test]
fn reference_never_claims_deny_completeness() {
    let request = Request::fixed();
    let after = Registry::fixed(&["g1"]).unwrap();
    let deny = evaluate_authorization_path(&after, "g1", "g3", &request);
    match deny {
        Decision::Deny(reason) => assert!(reason.contains("g1")),
        Decision::Allow => panic!("revoked path must not be allowed"),
    }
    // A different concrete path remains available; this is an existence proof
    // for that path only, not a statement about all paths in the graph.
    assert!(evaluate_authorization_path(&after, "g2", "g4", &request).is_allow());
    let _: Grant = fixed_grants()[3].clone();
}

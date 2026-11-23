//! Independent off-circuit authorization decision model.
//!
//! This module never calls circuit or gadget code.  It is the oracle against
//! which MockProver and real-proof outcomes are compared.

use crate::model::{scope_bits, Grant, Request, SCOPE_READ, SCOPE_WRITE, SCOPE_INVOKE};
use crate::registry::Registry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// g0 must be a root grant and g1 must be its direct child, issued by g0's
/// subject and ending at the requested agent.
pub fn validate_grant_chain(g0: &Grant, g1: &Grant, request: &Request) -> Decision {
    if g0.parent != crate::model::ZERO_PARENT {
        return Decision::Deny("g0 is not a root grant".into());
    }
    if g1.parent != g0.id {
        return Decision::Deny("g1.parent_id does not match g0.id".into());
    }
    if g1.issuer != g0.subject {
        return Decision::Deny("issuer continuity violated".into());
    }
    if g1.subject != request.agent {
        return Decision::Deny("g1.subject is not the requesting agent".into());
    }
    if g0.resource != request.resource || g1.resource != request.resource {
        return Decision::Deny("resource mismatch".into());
    }
    Decision::Allow
}

/// Every permission bit of the child must be present in the parent, and the
/// request action must be present in both.
pub fn validate_permission_attenuation(g0: &Grant, g1: &Grant, request: &Request) -> Decision {
    if g0.scope & !0b111 != 0 || g1.scope & !0b111 != 0 {
        return Decision::Deny("scope mask wider than 3 bits".into());
    }
    for i in 0..3 {
        if scope_bits(g1.scope)[i] == 1 && scope_bits(g0.scope)[i] == 0 {
            return Decision::Deny("child scope exceeds parent scope".into());
        }
        if scope_bits(request.action)[i] == 1 && scope_bits(g1.scope)[i] == 0 {
            return Decision::Deny("request action not covered by child scope".into());
        }
        if scope_bits(request.action)[i] == 1 && scope_bits(g0.scope)[i] == 0 {
            return Decision::Deny("request action not covered by root scope".into());
        }
    }
    Decision::Allow
}

/// Closed intervals, plus attenuation: child interval nested in parent interval.
pub fn validate_time_interval(g0: &Grant, g1: &Grant, request: &Request) -> Decision {
    if request.time < g0.valid_from || request.time > g0.valid_until {
        return Decision::Deny("request time outside root grant interval".into());
    }
    if request.time < g1.valid_from || request.time > g1.valid_until {
        return Decision::Deny("request time outside child grant interval".into());
    }
    if g1.valid_from < g0.valid_from || g1.valid_until > g0.valid_until {
        return Decision::Deny("child interval not nested in parent interval".into());
    }
    Decision::Allow
}

pub fn validate_revocation_state(registry: &Registry, id: &str) -> Decision {
    if registry.grant(id).is_none() {
        return Decision::Deny(format!("{} absent from registry", id));
    }
    if registry.is_revoked(id) {
        return Decision::Deny(format!("{} revoked", id));
    }
    Decision::Allow
}

/// Full existence check for one concrete two-level path.
pub fn evaluate_authorization_path(
    registry: &Registry,
    id0: &str,
    id1: &str,
    request: &Request,
) -> Decision {
    let g0 = match registry.grant(id0) {
        Some(g) => g.clone(),
        None => return Decision::Deny(format!("{} absent from registry", id0)),
    };
    let g1 = match registry.grant(id1) {
        Some(g) => g.clone(),
        None => return Decision::Deny(format!("{} absent from registry", id1)),
    };

    for check in [
        validate_grant_chain(&g0, &g1, request),
        validate_permission_attenuation(&g0, &g1, request),
        validate_time_interval(&g0, &g1, request),
        validate_revocation_state(registry, id0),
        validate_revocation_state(registry, id1),
    ] {
        if let deny @ Decision::Deny(_) = check {
            return deny;
        }
    }

    // Both slots must open to the published roots with matching grant IDs.
    for id in [id0, id1] {
        let witness = match registry.witness(id) {
            Ok(w) => w,
            Err(e) => return Decision::Deny(e),
        };
        if !registry.openings_valid(&witness) {
            return Decision::Deny(format!("{} has invalid Merkle opening", id));
        }
    }

    Decision::Allow
}

/// Utility used by the test matrix to name a scope bitmask.
pub fn scope_name(mask: u8) -> &'static str {
    match mask {
        SCOPE_READ => "read",
        SCOPE_WRITE => "write",
        SCOPE_INVOKE => "invoke",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_decisions_match_fixed_scenario() {
        let req = Request::fixed();
        let before = Registry::fixed(&[]).unwrap();
        assert!(evaluate_authorization_path(&before, "g1", "g3", &req).is_allow());
        assert!(evaluate_authorization_path(&before, "g2", "g4", &req).is_allow());
        assert!(!evaluate_authorization_path(&before, "g1", "g5", &req).is_allow());
        assert!(!evaluate_authorization_path(&before, "g2", "g6", &req).is_allow());

        let after = Registry::fixed(&["g1"]).unwrap();
        assert!(!evaluate_authorization_path(&after, "g1", "g3", &req).is_allow());
        assert!(evaluate_authorization_path(&after, "g2", "g4", &req).is_allow());
    }
}

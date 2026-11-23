//! Poseidon field helpers shared by the off-circuit registry and the Halo2 gadget.
//!
//! Domain tags are distinct field elements derived from fixed ASCII labels.  The
//! labels are hashed with a domain-separated BLAKE2b and reduced into pallas::Base
//! so that the same value can be used off-circuit and inside the circuit (as a
//! public/constant input).

use blake2b_simd::Params as Blake2bParams;
use ff::PrimeField;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas::Base as F;

/// Deterministic, domain-separated label -> field map.
///
/// The first 16 bytes of BLAKE2b-256 are interpreted big-endian as u128 and then
/// reduced modulo the pallas::Base field modulus.  Since u128 < 2^128 < p, this
/// is actually injective on the truncated digest.
pub fn label_to_field(label: &str) -> F {
    let digest = Blake2bParams::new()
        .hash_length(32)
        .personal(b"D2A-label-v1")
        .hash(label.as_bytes());
    let bytes = digest.as_bytes();
    let mut value = 0u128;
    for byte in &bytes[..16] {
        value = (value << 8) | u128::from(*byte);
    }
    F::from_u128(value)
}

pub fn field_to_hex(value: &F) -> String {
    let repr = value.to_repr();
    let bytes = repr.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub fn d_grant() -> F {
    label_to_field("D_GRANT")
}
pub fn d_revoke() -> F {
    label_to_field("D_REVOKE")
}
pub fn d_node() -> F {
    label_to_field("D_NODE")
}
pub fn d_request() -> F {
    label_to_field("D_REQUEST")
}

/// Off-circuit Poseidon hash with the same parameters as the Halo2 Pow5Chip.
pub fn poseidon_hash<const L: usize>(inputs: [F; L]) -> F {
    Hash::<F, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(inputs)
}

/// Leaf commitment of one grant record (9 preimage words).
pub fn grant_leaf(
    id: F,
    issuer: F,
    subject: F,
    resource: F,
    scope: F,
    valid_from: F,
    valid_until: F,
    parent: F,
) -> F {
    poseidon_hash::<9>([
        d_grant(),
        id,
        issuer,
        subject,
        resource,
        scope,
        valid_from,
        valid_until,
        parent,
    ])
}

/// Leaf commitment of one revocation-status record (3 preimage words).
pub fn revocation_leaf(id: F, revoked: F) -> F {
    poseidon_hash::<3>([d_revoke(), id, revoked])
}

/// Internal Merkle node: Poseidon(D_NODE, left, right).
pub fn node_hash(left: F, right: F) -> F {
    poseidon_hash::<3>([d_node(), left, right])
}

/// Request digest recomputed by the circuit and exposed as public input.
pub fn request_digest(
    agent: F,
    resource: F,
    action: F,
    args_hash: F,
    context_hash: F,
    time: F,
    policy_tag: F,
    epoch: F,
) -> F {
    poseidon_hash::<9>([
        d_request(),
        agent,
        resource,
        action,
        args_hash,
        context_hash,
        time,
        policy_tag,
        epoch,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_and_deterministic() {
        let labels = ["D_GRANT", "D_REVOKE", "D_NODE", "D_REQUEST", "g1", "Agent-C"];
        let values: Vec<F> = labels.iter().map(|s| label_to_field(s)).collect();
        for i in 0..values.len() {
            assert_eq!(values[i], label_to_field(labels[i]));
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j], "collision: {} / {}", labels[i], labels[j]);
            }
        }
    }
}

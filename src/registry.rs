//! 16-slot Poseidon grant/revocation trees and path witnesses.
//!
//! The revocation tree mirrors the grant tree slot-for-slot.  A grant is proven
//! *not revoked* by opening the very same slot to a leaf that binds its grant ID
//! to `revoked = 0`; this is deliberately stronger than a non-membership claim.

use std::collections::HashSet;

use ff::Field;
use pasta_curves::pallas::Base as F;

use crate::model::{
    Grant, GrantWitness, TREE_CAPACITY, TREE_DEPTH,
};
use crate::poseidon_hash::{grant_leaf, node_hash, revocation_leaf};

#[derive(Clone, Debug)]
pub struct Registry {
    pub grants: Vec<Grant>,
    pub grant_leaves: [F; TREE_CAPACITY],
    pub revoke_leaves: [F; TREE_CAPACITY],
    pub grant_root: F,
    pub revoke_root: F,
    revoked: HashSet<String>,
}

fn fold_level(level: &[F]) -> Vec<F> {
    level
        .chunks_exact(2)
        .map(|pair| node_hash(pair[0], pair[1]))
        .collect()
}

pub fn merkle_root(leaves: &[F; TREE_CAPACITY]) -> F {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = fold_level(&level);
    }
    level[0]
}

/// Root-most path first.  `sibling_is_left` is true iff the current node is the
/// right child at that level; it must equal the corresponding index bit.
pub fn merkle_path(leaves: &[F; TREE_CAPACITY], index: usize) -> Vec<(F, bool)> {
    assert!(index < TREE_CAPACITY, "index out of range");
    let mut level = leaves.to_vec();
    let mut cursor = index;
    let mut path = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        let sibling_index = cursor ^ 1;
        let sibling_is_left = (cursor & 1) == 1;
        path.push((level[sibling_index], sibling_is_left));
        level = fold_level(&level);
        cursor /= 2;
    }
    path
}

/// Off-circuit path verification, including index-bit / direction binding.
pub fn verify_merkle_path(
    root: F,
    leaf: F,
    index: usize,
    path: &[(F, bool)],
) -> bool {
    if path.len() != TREE_DEPTH || index >= TREE_CAPACITY {
        return false;
    }
    let mut cursor = index;
    let mut acc = leaf;
    for (sibling, sibling_is_left) in path {
        if *sibling_is_left != ((cursor & 1) == 1) {
            return false;
        }
        acc = if *sibling_is_left {
            node_hash(*sibling, acc)
        } else {
            node_hash(acc, *sibling)
        };
        cursor /= 2;
    }
    acc == root
}

impl Registry {
    /// Builds both trees, rejecting duplicate IDs, index reuse and bad indices.
    pub fn build(grants: Vec<Grant>, revoked: &[&str]) -> Result<Self, String> {
        let mut ids = HashSet::new();
        let mut indices = HashSet::new();
        for grant in &grants {
            if grant.index >= TREE_CAPACITY {
                return Err(format!("grant {} has out-of-range index", grant.id));
            }
            if !ids.insert(grant.id.clone()) {
                return Err(format!("duplicate grant id {}", grant.id));
            }
            if !indices.insert(grant.index) {
                return Err(format!("index {} reused", grant.index));
            }
            if grant.scope & !0b111 != 0 {
                return Err(format!("grant {} has invalid scope mask", grant.id));
            }
            if grant.valid_from > grant.valid_until {
                return Err(format!("grant {} has inverted validity interval", grant.id));
            }
        }
        let revoked: HashSet<String> = revoked.iter().map(|s| (*s).to_string()).collect();
        for id in &revoked {
            if !ids.contains(id) {
                return Err(format!("revocation refers to unknown grant {}", id));
            }
        }

        let mut grant_leaves = [F::ZERO; TREE_CAPACITY];
        let mut revoke_leaves = [F::ZERO; TREE_CAPACITY];
        for grant in &grants {
            let f = grant.to_field();
            grant_leaves[grant.index] = grant_leaf(
                f.id,
                f.issuer,
                f.subject,
                f.resource,
                f.scope,
                f.valid_from,
                f.valid_until,
                f.parent,
            );
            revoke_leaves[grant.index] = revocation_leaf(
                f.id,
                if revoked.contains(&grant.id) {
                    F::ONE
                } else {
                    F::ZERO
                },
            );
        }

        Ok(Self {
            grant_root: merkle_root(&grant_leaves),
            revoke_root: merkle_root(&revoke_leaves),
            grants,
            grant_leaves,
            revoke_leaves,
            revoked,
        })
    }

    pub fn fixed(revoked: &[&str]) -> Result<Self, String> {
        Self::build(crate::model::fixed_grants(), revoked)
    }

    /// Same fixed g2+g4 path, padded with inert filler records to reach `n`.
    pub fn with_record_count(n: usize, revoked: &[&str]) -> Result<Self, String> {
        assert!((4..=TREE_CAPACITY).contains(&n), "n must be in 4..=16");
        let mut grants = vec![
            crate::model::fixed_grants()[1].clone(), // g2, index 2
            crate::model::fixed_grants()[3].clone(), // g4, index 4
        ];
        let free_indices: Vec<usize> = (0..TREE_CAPACITY).filter(|i| *i != 2 && *i != 4).collect();
        for (j, index) in free_indices.into_iter().take(n - 2).enumerate() {
            grants.push(Grant {
                id: format!("f{}", j + 1),
                issuer: "Root-filler".into(),
                subject: "Agent-filler".into(),
                resource: "tool:other".into(),
                scope: crate::model::SCOPE_READ,
                valid_from: 2,
                valid_until: 20,
                parent: crate::model::ZERO_PARENT.into(),
                index,
            });
        }
        Self::build(grants, revoked)
    }

    pub fn is_revoked(&self, id: &str) -> bool {
        self.revoked.contains(id)
    }

    pub fn grant(&self, id: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.id == id)
    }

    /// Full private witness for one grant record in this registry.
    pub fn witness(&self, id: &str) -> Result<GrantWitness, String> {
        let grant = self
            .grant(id)
            .ok_or_else(|| format!("unknown grant {}", id))?;
        let index = grant.index;
        Ok(GrantWitness {
            grant_index: index,
            grant: grant.to_field(),
            grant_path: merkle_path(&self.grant_leaves, index),
            revoked: self.is_revoked(id),
            revocation_path: merkle_path(&self.revoke_leaves, index),
        })
    }

    /// Sanity check that both openings recompute the published roots.
    pub fn openings_valid(&self, witness: &GrantWitness) -> bool {
        let f = witness.grant;
        let leaf = grant_leaf(
            f.id, f.issuer, f.subject, f.resource, f.scope,
            f.valid_from, f.valid_until, f.parent,
        );
        let revoke_leaf = revocation_leaf(
            f.id,
            if witness.revoked { F::ONE } else { F::ZERO },
        );
        verify_merkle_path(self.grant_root, leaf, witness.grant_index, &witness.grant_path)
            && verify_merkle_path(
                self.revoke_root,
                revoke_leaf,
                witness.grant_index,
                &witness.revocation_path,
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_registry_opens_both_paths() {
        let reg = Registry::fixed(&[]).unwrap();
        for id in ["g1", "g2", "g3", "g4", "g5", "g6"] {
            let w = reg.witness(id).unwrap();
            assert!(reg.openings_valid(&w), "opening failed for {}", id);
        }
        let revoked = Registry::fixed(&["g1"]).unwrap();
        assert!(revoked.is_revoked("g1"));
        assert!(!revoked.is_revoked("g2"));
        assert!(revoked.openings_valid(&revoked.witness("g3").unwrap()));
    }

    #[test]
    fn builder_rejects_bad_input() {
        let mut grants = crate::model::fixed_grants();
        grants[1].id = "g1".into();
        assert!(Registry::build(grants, &[]).is_err());
        let grants = crate::model::fixed_grants();
        assert!(Registry::build(grants, &["missing"]).is_err());
    }

    #[test]
    fn tampered_path_is_rejected() {
        let reg = Registry::fixed(&[]).unwrap();
        let mut w = reg.witness("g3").unwrap();
        w.grant_path[0].0 += F::ONE;
        assert!(!reg.openings_valid(&w));
    }
}

//! Fixed authorization dataset and field-level record representation.

use ff::Field;
use pasta_curves::pallas::Base as F;

use crate::poseidon_hash::label_to_field;

pub const TREE_DEPTH: usize = 4;
pub const TREE_CAPACITY: usize = 1 << TREE_DEPTH; // 16
pub const ZERO_PARENT: &str = "";

pub const SCOPE_READ: u8 = 0b001;
pub const SCOPE_WRITE: u8 = 0b010;
pub const SCOPE_INVOKE: u8 = 0b100;

/// Human-readable grant record.  `index` is the unique slot in both trees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    /// 3-bit permission mask: read=001, write=010, invoke=100.
    pub scope: u8,
    pub valid_from: u8,
    pub valid_until: u8,
    /// Empty string denotes the trusted root (field value 0).
    pub parent: String,
    pub index: usize,
}

/// Field-encoded grant record used by both the registry and the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldGrant {
    pub id: F,
    pub issuer: F,
    pub subject: F,
    pub resource: F,
    pub scope: F,
    pub valid_from: F,
    pub valid_until: F,
    pub parent: F,
}

impl Grant {
    pub fn to_field(&self) -> FieldGrant {
        FieldGrant {
            id: label_to_field(&self.id),
            issuer: label_to_field(&self.issuer),
            subject: label_to_field(&self.subject),
            resource: label_to_field(&self.resource),
            scope: F::from(u64::from(self.scope)),
            valid_from: F::from(u64::from(self.valid_from)),
            valid_until: F::from(u64::from(self.valid_until)),
            parent: if self.parent == ZERO_PARENT {
                F::ZERO
            } else {
                label_to_field(&self.parent)
            },
        }
    }
}

/// The tool request.  `args_hash_label` / `context_hash_label` stand in for
/// externally computed digests; they are mapped to fields deterministically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub agent: String,
    pub resource: String,
    pub action: u8,
    pub args_hash_label: String,
    pub context_hash_label: String,
    pub time: u8,
    pub policy_version: String,
    pub epoch: u8,
}

impl Request {
    pub fn fixed() -> Self {
        Self {
            agent: "Agent-C".to_string(),
            resource: "tool:translate".to_string(),
            action: SCOPE_READ,
            args_hash_label: "args-digest-fixed".to_string(),
            context_hash_label: "context-digest-fixed".to_string(),
            time: 10,
            policy_version: "policy-v1".to_string(),
            epoch: 8,
        }
    }

    pub fn policy_tag(&self) -> F {
        label_to_field(&self.policy_version)
    }

    pub fn fields(&self) -> [F; 8] {
        [
            label_to_field(&self.agent),
            label_to_field(&self.resource),
            F::from(u64::from(self.action)),
            label_to_field(&self.args_hash_label),
            label_to_field(&self.context_hash_label),
            F::from(u64::from(self.time)),
            self.policy_tag(),
            F::from(u64::from(self.epoch)),
        ]
    }
}

/// Witness for one grant in one registry: the record plus both Merkle paths.
#[derive(Clone, Debug)]
pub struct GrantWitness {
    pub grant_index: usize,
    pub grant: FieldGrant,
    /// (sibling, sibling_is_left) for each level, root-most path first.
    pub grant_path: Vec<(F, bool)>,
    pub revoked: bool,
    /// The revocation tree uses the same slot index as the grant tree.
    pub revocation_path: Vec<(F, bool)>,
}

/// The exact six records fixed by the experiment task package.
pub fn fixed_grants() -> Vec<Grant> {
    vec![
        Grant {
            id: "g1".into(),
            issuer: "Root-1".into(),
            subject: "Agent-A".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_READ,
            valid_from: 2,
            valid_until: 20,
            parent: ZERO_PARENT.into(),
            index: 1,
        },
        Grant {
            id: "g2".into(),
            issuer: "Root-2".into(),
            subject: "Agent-B".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_READ,
            valid_from: 2,
            valid_until: 20,
            parent: ZERO_PARENT.into(),
            index: 2,
        },
        Grant {
            id: "g3".into(),
            issuer: "Agent-A".into(),
            subject: "Agent-C".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_READ,
            valid_from: 2,
            valid_until: 20,
            parent: "g1".into(),
            index: 3,
        },
        Grant {
            id: "g4".into(),
            issuer: "Agent-B".into(),
            subject: "Agent-C".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_READ,
            valid_from: 2,
            valid_until: 20,
            parent: "g2".into(),
            index: 4,
        },
        Grant {
            id: "g5".into(),
            issuer: "Agent-A".into(),
            subject: "Agent-C".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_WRITE,
            valid_from: 2,
            valid_until: 20,
            parent: "g1".into(),
            index: 5,
        },
        Grant {
            id: "g6".into(),
            issuer: "Agent-B".into(),
            subject: "Agent-C".into(),
            resource: "tool:translate".into(),
            scope: SCOPE_READ,
            valid_from: 2,
            valid_until: 9, // expired at request time 10
            parent: "g2".into(),
            index: 6,
        },
    ]
}

pub fn scope_bits(scope: u8) -> [u8; 3] {
    [
        (scope >> 0) & 1,
        (scope >> 1) & 1,
        (scope >> 2) & 1,
    ]
}

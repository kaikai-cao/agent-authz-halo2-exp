//! Public Halo2 instance layout: (GR, RR, policyTag, epoch, Dq).

use pasta_curves::pallas::Base as F;

use crate::model::Request;
use crate::poseidon_hash::request_digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub grant_root: F,
    pub revoke_root: F,
    pub policy_tag: F,
    pub epoch: F,
    pub request_digest: F,
}

pub const PUBLIC_INPUT_COUNT: usize = 5;

impl PublicInputs {
    pub fn new(grant_root: F, revoke_root: F, request: &Request) -> Self {
        let fields = request.fields();
        Self {
            grant_root,
            revoke_root,
            policy_tag: fields[6],
            epoch: fields[7],
            request_digest: request_digest(
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
                fields[6], fields[7],
            ),
        }
    }

    /// The single instance column, in layout order.
    pub fn to_instance(&self) -> [F; PUBLIC_INPUT_COUNT] {
        [
            self.grant_root,
            self.revoke_root,
            self.policy_tag,
            self.epoch,
            self.request_digest,
        ]
    }

    pub fn from_instance(values: &[F]) -> Self {
        assert_eq!(values.len(), PUBLIC_INPUT_COUNT);
        Self {
            grant_root: values[0],
            revoke_root: values[1],
            policy_tag: values[2],
            epoch: values[3],
            request_digest: values[4],
        }
    }
}

//! Off-circuit Poseidon vs Halo2 Pow5Chip, tree shape and domain separation.

use std::convert::TryInto;

use agent_authz_halo2_exp::model::{Grant, Request, TREE_CAPACITY};
use agent_authz_halo2_exp::poseidon_hash::{
    d_node, grant_leaf, label_to_field, node_hash, poseidon_hash,
    request_digest, revocation_leaf,
};
use agent_authz_halo2_exp::registry::{merkle_path, merkle_root, verify_merkle_path, Registry};
use ff::Field;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};
use pasta_curves::pallas::Base as F;

#[derive(Clone, Debug)]
struct OneHashCircuit {
    preimage: [F; 3],
    expected: F,
}

#[derive(Clone, Debug)]
struct OneHashConfig {
    poseidon: Pow5Config<F, 3, 2>,
    state: [Column<Advice>; 3],
}

impl Circuit<F> for OneHashCircuit {
    type Config = OneHashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            preimage: [F::ZERO; 3],
            expected: F::ZERO,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> OneHashConfig {
        let state: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rc_b: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        meta.enable_constant(rc_b[0]);
        for col in state {
            meta.enable_equality(col);
        }
        let state_cols = state;
        OneHashConfig {
            poseidon: Pow5Chip::configure::<P128Pow5T3>(meta, state_cols, partial_sbox, rc_a, rc_b),
            state: state_cols,
        }
    }

    fn synthesize(
        &self,
        config: OneHashConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cells = layouter.assign_region(
            || "preimage",
            |mut region| -> Result<[AssignedCell<F, F>; 3], Error> {
                let mut assigned = Vec::new();
                for (i, value) in self.preimage.iter().enumerate() {
                    assigned.push(region.assign_advice(
                        || format!("word_{i}"),
                        config.state[i],
                        0,
                        || Value::known(*value),
                    )?);
                }
                Ok(assigned.try_into().unwrap())
            },
        )?;
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let digest = hasher.hash(layouter.namespace(|| "hash"), cells)?;
        layouter.assign_region(
            || "expected",
            |mut region| {
                let cell = region.assign_advice(
                    || "expected",
                    config.state[0],
                    0,
                    || Value::known(self.expected),
                )?;
                region.constrain_equal(digest.cell(), cell.cell())
            },
        )
    }
}

#[test]
fn gadget_and_off_circuit_poseidon_agree() {
    let preimage = [d_node(), label_to_field("left-node"), label_to_field("right-node")];
    let expected = poseidon_hash::<3>(preimage);
    let circuit = OneHashCircuit { preimage, expected };
    let prover = MockProver::run(8, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let wrong = OneHashCircuit {
        preimage,
        expected: expected + F::ONE,
    };
    let prover = MockProver::run(8, &wrong, vec![]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn domain_separated_leaves_do_not_collide() {
    let id = label_to_field("g1");
    let other = label_to_field("Agent-A");
    let grant = grant_leaf(id, id, other, other, F::ONE, F::from(2), F::from(20), F::ZERO);
    let revoke = revocation_leaf(id, F::ZERO);
    let node = node_hash(grant, revoke);
    let request = request_digest(
        id, other, F::ONE, id, other, F::from(10), label_to_field("policy-v1"), F::from(8),
    );
    let all = [grant, revoke, node, request];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
    assert_eq!(grant, grant_leaf(id, id, other, other, F::ONE, F::from(2), F::from(20), F::ZERO));
}

#[test]
fn sparse_registry_slots_open_correctly() {
    // The fixed experiment uses 16 = 2^4; verify the RFC-like fold accepts a
    // non-power-of-two prefix as well (the tree shape is defined by the fold,
    // not by padded empty leaves).
    let leaves: Vec<F> = (0..5).map(|i| label_to_field(&format!("leaf-{i}"))).collect();
    let mut sized = [F::ZERO; TREE_CAPACITY];
    sized[..5].copy_from_slice(&leaves);
    let root = merkle_root(&sized);
    assert_ne!(root, F::ZERO);
    for index in 0..5 {
        let path = merkle_path(&sized, index);
        assert!(verify_merkle_path(root, leaves[index], index, &path));
    }
}

#[test]
fn registry_roots_and_paths_are_consistent() {
    let reg = Registry::fixed(&[]).unwrap();
    let revoked = Registry::fixed(&["g1"]).unwrap();
    assert_eq!(reg.grant_root, revoked.grant_root);
    assert_ne!(reg.revoke_root, revoked.revoke_root);
    for grant in &reg.grants {
        let w = reg.witness(&grant.id).unwrap();
        assert_eq!(w.revoked, false);
        assert!(verify_merkle_path(
            reg.grant_root,
            grant_leaf(
                w.grant.id, w.grant.issuer, w.grant.subject, w.grant.resource,
                w.grant.scope, w.grant.valid_from, w.grant.valid_until, w.grant.parent,
            ),
            w.grant_index,
            &w.grant_path,
        ));
    }
    let _ = Request::fixed();
    let _ = Grant {
        id: "unused".into(),
        issuer: "x".into(),
        subject: "y".into(),
        resource: "z".into(),
        scope: 1,
        valid_from: 1,
        valid_until: 2,
        parent: String::new(),
        index: 0,
    };
}

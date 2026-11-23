//! Halo2 circuit for a two-level private authorization path.
//!
//! Public instance: (GR, RR, policyTag, epoch, Dq).  Everything else is
//! private advice.  The circuit opens two grant records and two revocation
//! records, checks delegation/scope/time semantics, and recomputes Dq.

use std::convert::TryInto;

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed,
        Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas::Base as F;

use crate::model::{scope_bits, GrantWitness, TREE_DEPTH};
use crate::poseidon_hash::{d_grant, d_node, d_revoke, d_request};
use crate::public_inputs::PublicInputs;

/// All private values for one concrete proof.
#[derive(Clone, Debug)]
pub struct PathWitness {
    pub g0: GrantWitness,
    pub g1: GrantWitness,
    /// agent, resource, action, argsHash, contextHash, time, policyTag, epoch
    pub request: [F; 8],
}

impl PathWitness {
    /// Used by keygen: no private values, all advice cells are `Value::unknown()`.
    pub fn blank() -> Self {
        let blank_grant = |index: usize| GrantWitness {
            grant_index: index,
            grant: crate::model::FieldGrant {
                id: F::ZERO,
                issuer: F::ZERO,
                subject: F::ZERO,
                resource: F::ZERO,
                scope: F::ZERO,
                valid_from: F::ZERO,
                valid_until: F::ZERO,
                parent: F::ZERO,
            },
            grant_path: vec![(F::ZERO, false); TREE_DEPTH],
            revoked: false,
            revocation_path: vec![(F::ZERO, false); TREE_DEPTH],
        };
        Self {
            g0: blank_grant(0),
            g1: blank_grant(0),
            request: [F::ZERO; 8],
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    poseidon: Pow5Config<F, 3, 2>,
    scratch: Column<Advice>,
    bool_col: Column<Advice>,
    byte_col: Column<Advice>,
    add: [Column<Advice>; 3],
    scope_cols: [Column<Advice>; 12],
    sel: [Column<Advice>; 5],
    instance: Column<Instance>,
    q_bool: Selector,
    q_byte: Selector,
    q_add: Selector,
    q_scope: Selector,
    q_select: Selector,
}

fn assign_vec(
    cfg: &AuthConfig,
    region: &mut Region<'_, F>,
    row: &mut usize,
    label: &'static str,
    values: &[F],
    known: bool,
) -> Result<Vec<AssignedCell<F, F>>, Error> {
    let mut cells = Vec::with_capacity(values.len());
    for (i, value) in values.iter().enumerate() {
        let v = if known {
            Value::known(*value)
        } else {
            Value::unknown()
        };
        cells.push(region.assign_advice(
            || format!("{label}_{i}"),
            cfg.scratch,
            *row + i,
            || v.clone(),
        )?);
    }
    *row += values.len();
    Ok(cells)
}

/// Assign one boolean into both scratch and the dedicated boolean column, and
/// bind them with an equality constraint.
fn assign_bool(
    cfg: &AuthConfig,
    region: &mut Region<'_, F>,
    scratch_row: &mut usize,
    bool_row: &mut usize,
    value: F,
    known: bool,
    label: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let v = if known {
        Value::known(value)
    } else {
        Value::unknown()
    };
    let cell = region.assign_advice(
        || format!("{label}_scratch"),
        cfg.scratch,
        *scratch_row,
        || v.clone(),
    )?;
    *scratch_row += 1;
    let bit = region.assign_advice(
        || format!("{label}_bit"),
        cfg.bool_col,
        *bool_row,
        || v.clone(),
    )?;
    cfg.q_bool.enable(region, *bool_row)?;
    *bool_row += 1;
    region.constrain_equal(cell.cell(), bit.cell())?;
    Ok(cell)
}

/// Range-check an 8-bit value by decomposing it into constrained boolean bits.
fn assign_byte(
    cfg: &AuthConfig,
    region: &mut Region<'_, F>,
    bool_row: &mut usize,
    value: F,
    known: bool,
    label: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let start = *bool_row;
    let byte = value.to_repr().as_ref()[0];
    for i in 0..8 {
        let bit_value = F::from(u64::from((byte >> i) & 1));
        let v = if known {
            Value::known(bit_value)
        } else {
            Value::unknown()
        };
        region.assign_advice(
            || format!("{label}_bit_{i}"),
            cfg.bool_col,
            start + i,
            || v.clone(),
        )?;
        cfg.q_bool.enable(region, start + i)?;
    }
    *bool_row = start + 8;
    cfg.q_byte.enable(region, start)?;
    let v = if known {
        Value::known(value)
    } else {
        Value::unknown()
    };
    region.assign_advice(|| format!("{label}_byte"), cfg.byte_col, start, || v)
}

/// Constrain `a + b = c` where `b` is separately range-checked to 8 bits.
fn assign_add(
    cfg: &AuthConfig,
    region: &mut Region<'_, F>,
    add_row: &mut usize,
    a: F,
    b: F,
    c: F,
    known: bool,
    label: &'static str,
) -> Result<(), Error> {
    let row = *add_row;
    for (col, value) in cfg.add.iter().zip([a, b, c]) {
        let v = if known {
            Value::known(value)
        } else {
            Value::unknown()
        };
        region.assign_advice(|| label.to_string(), *col, row, || v)?;
    }
    cfg.q_add.enable(region, row)?;
    *add_row += 1;
    Ok(())
}

fn hash_words<L: Layouter<F>, const N: usize>(
    cfg: &AuthConfig,
    mut layouter: L,
    name: &'static str,
    words: [AssignedCell<F, F>; N],
) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(cfg.poseidon.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<N>, 3, 2>::init(
        chip,
        layouter.namespace(|| format!("{name}_init")),
    )?;
    hasher.hash(layouter.namespace(|| format!("{name}_hash")), words)
}

/// left/right = f(current, sibling, index_bit), with the selection constrained.
/// bit=1 means the sibling is the left child at this level (MSB-first path).
fn select_cells<L: Layouter<F>>(
    cfg: &AuthConfig,
    mut layouter: L,
    current: AssignedCell<F, F>,
    sibling: AssignedCell<F, F>,
    direction: AssignedCell<F, F>,
    name: &'static str,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
    layouter.assign_region(
        || name,
        |mut region| {
            current.copy_advice(|| "cur", &mut region, cfg.sel[0], 0)?;
            sibling.copy_advice(|| "sib", &mut region, cfg.sel[1], 0)?;
            direction.copy_advice(|| "dir", &mut region, cfg.sel[2], 0)?;

            let left_value = current
                .value()
                .copied()
                .zip(sibling.value().copied())
                .zip(direction.value().copied())
                .map(|((c, s), d)| c * (F::ONE - d) + s * d);
            let right_value = current
                .value()
                .copied()
                .zip(sibling.value().copied())
                .zip(direction.value().copied())
                .map(|((c, s), d)| s * (F::ONE - d) + c * d);

            let left = region.assign_advice(|| "left", cfg.sel[3], 0, || left_value)?;
            let right = region.assign_advice(|| "right", cfg.sel[4], 0, || right_value)?;
            cfg.q_select.enable(&mut region, 0)?;
            Ok((left, right))
        },
    )
}

/// Instances of the same 4-level walk for 9-word grant leaves and 3-word
/// revocation leaves.
fn walk_leaves<L: Layouter<F>, const N: usize>(
    cfg: &AuthConfig,
    mut layouter: L,
    words: [AssignedCell<F, F>; N],
    siblings: [AssignedCell<F, F>; TREE_DEPTH],
    directions: [AssignedCell<F, F>; TREE_DEPTH],
    d_node: &AssignedCell<F, F>,
    name: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let mut current = hash_words(cfg, layouter.namespace(|| name), name, words)?;
    for level in 0..TREE_DEPTH {
        let (left, right) = select_cells(
            cfg,
            layouter.namespace(|| format!("{name}_select_{level}")),
            current,
            siblings[level].clone(),
            directions[level].clone(),
            "select",
        )?;
        current = hash_words(
            cfg,
            layouter.namespace(|| format!("{name}_node_{level}")),
            "node",
            [d_node.clone(), left, right],
        )?;
    }
    Ok(current)
}

/// Assigned values produced by the single witness region.
#[derive(Clone)]
struct Bundle {
    g0_words: [AssignedCell<F, F>; 9],
    g0_sibs: [AssignedCell<F, F>; TREE_DEPTH],
    g0_dirs: [AssignedCell<F, F>; TREE_DEPTH],
    g0_rev_words: [AssignedCell<F, F>; 3],
    g0_rev_sibs: [AssignedCell<F, F>; TREE_DEPTH],
    g0_rev_dirs: [AssignedCell<F, F>; TREE_DEPTH],
    g1_words: [AssignedCell<F, F>; 9],
    g1_sibs: [AssignedCell<F, F>; TREE_DEPTH],
    g1_dirs: [AssignedCell<F, F>; TREE_DEPTH],
    g1_rev_words: [AssignedCell<F, F>; 3],
    g1_rev_sibs: [AssignedCell<F, F>; TREE_DEPTH],
    g1_rev_dirs: [AssignedCell<F, F>; TREE_DEPTH],
    request_words: [AssignedCell<F, F>; 9],
    d_node: AssignedCell<F, F>,
    policy: AssignedCell<F, F>,
    epoch: AssignedCell<F, F>,
}

#[derive(Clone, Debug)]
pub struct AuthPathCircuit {
    pub public: PublicInputs,
    pub witness: Option<PathWitness>,
}

impl AuthPathCircuit {
    pub fn new(public: PublicInputs, witness: PathWitness) -> Self {
        Self {
            public,
            witness: Some(witness),
        }
    }

    /// Circuit shape used for key generation; contains no private values.
    pub fn for_keygen(public: PublicInputs) -> Self {
        Self {
            public,
            witness: None,
        }
    }
}

fn mask_bits(value: F) -> [F; 3] {
    let byte = value.to_repr().as_ref()[0];
    let bits = scope_bits(byte);
    bits.map(|b| if b == 1 { F::ONE } else { F::ZERO })
}

impl Circuit<F> for AuthPathCircuit {
    type Config = AuthConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::for_keygen(self.public)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
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
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let scratch = meta.advice_column();
        let bool_col = meta.advice_column();
        let byte_col = meta.advice_column();
        let add: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // 0..3 parent bits, 3..6 child bits, 6..9 action bits,
        // 9 parent scope value, 10 child scope value, 11 action value.
        let scope_cols: [Column<Advice>; 12] = (0..12)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let sel: [Column<Advice>; 5] = (0..5)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let instance = meta.instance_column();

        for col in [scratch, bool_col, byte_col]
            .into_iter()
            .chain(add)
            .chain(scope_cols)
            .chain(sel)
        {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        let q_bool = meta.selector();
        let q_byte = meta.selector();
        let q_add = meta.selector();
        let q_scope = meta.selector();
        let q_select = meta.selector();

        meta.create_gate("boolean", |meta| {
            let q = meta.query_selector(q_bool);
            let a = meta.query_advice(bool_col, Rotation::cur());
            Constraints::with_selector(q, vec![a.clone() * a.clone() - a])
        });

        meta.create_gate("byte8", |meta| {
            let q = meta.query_selector(q_byte);
            let byte = meta.query_advice(byte_col, Rotation::cur());
            let mut sum = Expression::Constant(F::ZERO);
            for i in 0..8u32 {
                sum = sum
                    + Expression::Constant(F::from(1u64 << i))
                        * meta.query_advice(bool_col, Rotation(i as i32));
            }
            Constraints::with_selector(q, vec![byte - sum])
        });

        meta.create_gate("add3", |meta| {
            let q = meta.query_selector(q_add);
            let a = meta.query_advice(add[0], Rotation::cur());
            let b = meta.query_advice(add[1], Rotation::cur());
            let c = meta.query_advice(add[2], Rotation::cur());
            Constraints::with_selector(q, vec![a + b - c])
        });

        meta.create_gate("scope-attenuation", |meta| {
            let q = meta.query_selector(q_scope);
            let parent: Vec<Expression<F>> = (0..3)
                .map(|i| meta.query_advice(scope_cols[i], Rotation::cur()))
                .collect();
            let child: Vec<Expression<F>> = (0..3)
                .map(|i| meta.query_advice(scope_cols[3 + i], Rotation::cur()))
                .collect();
            let action: Vec<Expression<F>> = (0..3)
                .map(|i| meta.query_advice(scope_cols[6 + i], Rotation::cur()))
                .collect();
            let parent_scope = meta.query_advice(scope_cols[9], Rotation::cur());
            let child_scope = meta.query_advice(scope_cols[10], Rotation::cur());
            let action_value = meta.query_advice(scope_cols[11], Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let mut polys = Vec::new();
            for i in 0..3 {
                // child_i * (1 - parent_i) = 0
                polys.push(child[i].clone() * (one.clone() - parent[i].clone()));
                // action_i * (1 - child_i) = 0
                polys.push(action[i].clone() * (one.clone() - child[i].clone()));
            }
            let mut p_sum = Expression::Constant(F::ZERO);
            let mut c_sum = Expression::Constant(F::ZERO);
            let mut a_sum = Expression::Constant(F::ZERO);
            for i in 0..3usize {
                let coeff = Expression::Constant(F::from(1u64 << i));
                p_sum = p_sum + coeff.clone() * parent[i].clone();
                c_sum = c_sum + coeff.clone() * child[i].clone();
                a_sum = a_sum + coeff * action[i].clone();
            }
            polys.push(parent_scope - p_sum);
            polys.push(child_scope - c_sum);
            polys.push(action_value - a_sum);
            Constraints::with_selector(q, polys)
        });

        meta.create_gate("path-select", |meta| {
            let q = meta.query_selector(q_select);
            let cur = meta.query_advice(sel[0], Rotation::cur());
            let sib = meta.query_advice(sel[1], Rotation::cur());
            let dir = meta.query_advice(sel[2], Rotation::cur());
            let left = meta.query_advice(sel[3], Rotation::cur());
            let right = meta.query_advice(sel[4], Rotation::cur());
            Constraints::with_selector(
                q,
                vec![
                    left - (cur.clone() + dir.clone() * (sib.clone() - cur.clone())),
                    right - (sib.clone() + dir * (cur - sib)),
                ],
            )
        });

        AuthConfig {
            poseidon,
            scratch,
            bool_col,
            byte_col,
            add,
            scope_cols,
            sel,
            instance,
            q_bool,
            q_byte,
            q_add,
            q_scope,
            q_select,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let known = self.witness.is_some();
        let w = self.witness.clone().unwrap_or_else(PathWitness::blank);
        let v = |x: F| {
            if known {
                Value::known(x)
            } else {
                Value::unknown()
            }
        };

        let g0 = &w.g0;
        let g1 = &w.g1;
        let req = &w.request;

        let index_bits = |gw: &GrantWitness| -> [F; TREE_DEPTH] {
            let mut out = [F::ZERO; TREE_DEPTH];
            // LSB-first to match `registry::merkle_path` (sibling = cursor ^ 1).
            for d in 0..TREE_DEPTH {
                out[d] = F::from(((gw.grant_index >> d) & 1) as u64);
            }
            out
        };
        let dir_bits = |path: &[(F, bool)]| -> [F; TREE_DEPTH] {
            path.iter()
                .map(|(_, left)| if *left { F::ONE } else { F::ZERO })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        };
        let siblings = |path: &[(F, bool)]| -> [F; TREE_DEPTH] {
            path.iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        };

        let g0_index = index_bits(g0);
        let g1_index = index_bits(g1);
        let g0_dirs = dir_bits(&g0.grant_path);
        let g1_dirs = dir_bits(&g1.grant_path);
        let g0_rev_dirs = dir_bits(&g0.revocation_path);
        let g1_rev_dirs = dir_bits(&g1.revocation_path);
        let parent_scope_bits = mask_bits(g0.grant.scope); // g0 is the parent grant
        let child_scope_bits = mask_bits(g1.grant.scope);  // g1 is the child grant
        let action_bits = mask_bits(req[2]);

        let bundle = layouter.assign_region(
            || "authorization witness",
            |mut region| -> Result<Bundle, Error> {
                let mut sr = 0usize;
                let mut br = 0usize;
                let mut ar = 0usize;

                let from0 = assign_byte(&config, &mut region, &mut br, g0.grant.valid_from, known, "from0")?;
                let until0 = assign_byte(&config, &mut region, &mut br, g0.grant.valid_until, known, "until0")?;
                let from1 = assign_byte(&config, &mut region, &mut br, g1.grant.valid_from, known, "from1")?;
                let until1 = assign_byte(&config, &mut region, &mut br, g1.grant.valid_until, known, "until1")?;
                let time = assign_byte(&config, &mut region, &mut br, req[5], known, "time")?;

                let diffs = [
                    (g0.grant.valid_from, req[5] - g0.grant.valid_from, req[5], "d0_time_from"),
                    (req[5], g0.grant.valid_until - req[5], g0.grant.valid_until, "d0_until_time"),
                    (g1.grant.valid_from, req[5] - g1.grant.valid_from, req[5], "d1_time_from"),
                    (req[5], g1.grant.valid_until - req[5], g1.grant.valid_until, "d1_until_time"),
                    (g0.grant.valid_from, g1.grant.valid_from - g0.grant.valid_from, g1.grant.valid_from, "d_from_atten"),
                    (g1.grant.valid_until, g0.grant.valid_until - g1.grant.valid_until, g0.grant.valid_until, "d_until_atten"),
                ];
                for (a, d, c, label) in diffs {
                    assign_add(&config, &mut region, &mut ar, a, d, c, known, label)?;
                    assign_byte(&config, &mut region, &mut br, d, known, label)?;
                }

                let mut bools = |values: &[F], label: &'static str| -> Result<Vec<AssignedCell<F, F>>, Error> {
                    let mut out = Vec::with_capacity(values.len());
                    for value in values {
                        out.push(assign_bool(
                            &config, &mut region, &mut sr, &mut br,
                            *value, known, label,
                        )?);
                    }
                    Ok(out)
                };

                let g0_dir_cells = bools(&g0_dirs, "g0_dir")?;
                let g1_dir_cells = bools(&g1_dirs, "g1_dir")?;
                let g0_rev_dir_cells = bools(&g0_rev_dirs, "g0_rev_dir")?;
                let g1_rev_dir_cells = bools(&g1_rev_dirs, "g1_rev_dir")?;
                let g0_index_cells = bools(&g0_index, "g0_index")?;
                let g1_index_cells = bools(&g1_index, "g1_index")?;
                let parent_bits_cells = bools(&parent_scope_bits, "parent_scope_bit")?;
                let child_bits_cells = bools(&child_scope_bits, "child_scope_bit")?;
                let action_bits_cells = bools(&action_bits, "action_bit")?;
                let g0_revoked = assign_bool(
                    &config, &mut region, &mut sr, &mut br,
                    if g0.revoked { F::ONE } else { F::ZERO }, known, "g0_revoked")?;
                let g1_revoked = assign_bool(
                    &config, &mut region, &mut sr, &mut br,
                    if g1.revoked { F::ONE } else { F::ZERO }, known, "g1_revoked")?;

                // Both trees must use the very same slot index.
                for i in 0..TREE_DEPTH {
                    region.constrain_equal(g0_index_cells[i].cell(), g0_dir_cells[i].cell())?;
                    region.constrain_equal(g0_index_cells[i].cell(), g0_rev_dir_cells[i].cell())?;
                    region.constrain_equal(g1_index_cells[i].cell(), g1_dir_cells[i].cell())?;
                    region.constrain_equal(g1_index_cells[i].cell(), g1_rev_dir_cells[i].cell())?;
                }

                let parent_scope = assign_vec(&config, &mut region, &mut sr, "parent_scope", &[g0.grant.scope], known)?;
                let child_scope = assign_vec(&config, &mut region, &mut sr, "child_scope", &[g1.grant.scope], known)?;
                let action_value = assign_vec(&config, &mut region, &mut sr, "action", &[req[2]], known)?;
                for i in 0..3 {
                    parent_bits_cells[i].copy_advice(|| "p", &mut region, config.scope_cols[i], 0)?;
                    child_bits_cells[i].copy_advice(|| "c", &mut region, config.scope_cols[3 + i], 0)?;
                    action_bits_cells[i].copy_advice(|| "a", &mut region, config.scope_cols[6 + i], 0)?;
                }
                parent_scope[0].copy_advice(|| "ps", &mut region, config.scope_cols[9], 0)?;
                child_scope[0].copy_advice(|| "cs", &mut region, config.scope_cols[10], 0)?;
                action_value[0].copy_advice(|| "av", &mut region, config.scope_cols[11], 0)?;
                config.q_scope.enable(&mut region, 0)?;

                let g0_fields = assign_vec(
                    &config, &mut region, &mut sr, "g0_field",
                    &[g0.grant.id, g0.grant.issuer, g0.grant.subject, g0.grant.resource, g0.grant.parent], known)?;
                let g1_fields = assign_vec(
                    &config, &mut region, &mut sr, "g1_field",
                    &[g1.grant.id, g1.grant.issuer, g1.grant.subject, g1.grant.resource, g1.grant.parent], known)?;
                let g0_sibs = assign_vec(&config, &mut region, &mut sr, "g0_sib", &siblings(&g0.grant_path), known)?;
                let g1_sibs = assign_vec(&config, &mut region, &mut sr, "g1_sib", &siblings(&g1.grant_path), known)?;
                let g0_rev_sibs = assign_vec(&config, &mut region, &mut sr, "g0_rev_sib", &siblings(&g0.revocation_path), known)?;
                let g1_rev_sibs = assign_vec(&config, &mut region, &mut sr, "g1_rev_sib", &siblings(&g1.revocation_path), known)?;
                let d_grant_cell = assign_vec(&config, &mut region, &mut sr, "d_grant", &[d_grant()], true)?;
                let d_revoke_cell = assign_vec(&config, &mut region, &mut sr, "d_revoke", &[d_revoke()], true)?;
                let d_node_cell = assign_vec(&config, &mut region, &mut sr, "d_node", &[d_node()], true)?;
                let d_request_cell = assign_vec(&config, &mut region, &mut sr, "d_request", &[d_request()], true)?;
                let policy = assign_vec(&config, &mut region, &mut sr, "policy", &[req[6]], known)?;
                let epoch = assign_vec(&config, &mut region, &mut sr, "epoch", &[req[7]], known)?;
                let req_fields = assign_vec(
                    &config, &mut region, &mut sr, "req_field",
                    &[req[0], req[1], req[3], req[4]], known)?;

                let g0_words = [
                    d_grant_cell[0].clone(), g0_fields[0].clone(), g0_fields[1].clone(),
                    g0_fields[2].clone(), g0_fields[3].clone(), parent_scope[0].clone(),
                    from0, until0, g0_fields[4].clone(),
                ];
                let g1_words = [
                    d_grant_cell[0].clone(), g1_fields[0].clone(), g1_fields[1].clone(),
                    g1_fields[2].clone(), g1_fields[3].clone(), child_scope[0].clone(),
                    from1, until1, g1_fields[4].clone(),
                ];
                let g0_rev_words = [d_revoke_cell[0].clone(), g0_fields[0].clone(), g0_revoked];
                let g1_rev_words = [d_revoke_cell[0].clone(), g1_fields[0].clone(), g1_revoked];
                let request_words = [
                    d_request_cell[0].clone(),
                    req_fields[0].clone(), req_fields[1].clone(), action_value[0].clone(),
                    req_fields[2].clone(), req_fields[3].clone(), time,
                    policy[0].clone(), epoch[0].clone(),
                ];

                Ok(Bundle {
                    g0_words,
                    g0_sibs: g0_sibs.try_into().unwrap(),
                    g0_dirs: g0_dir_cells.try_into().unwrap(),
                    g0_rev_words,
                    g0_rev_sibs: g0_rev_sibs.try_into().unwrap(),
                    g0_rev_dirs: g0_rev_dir_cells.try_into().unwrap(),
                    g1_words,
                    g1_sibs: g1_sibs.try_into().unwrap(),
                    g1_dirs: g1_dir_cells.try_into().unwrap(),
                    g1_rev_words,
                    g1_rev_sibs: g1_rev_sibs.try_into().unwrap(),
                    g1_rev_dirs: g1_rev_dir_cells.try_into().unwrap(),
                    request_words,
                    d_node: d_node_cell[0].clone(),
                    policy: policy[0].clone(),
                    epoch: epoch[0].clone(),
                })
            },
        )?;

        // Delegation, resource and subject constraints.  Each pair of cells is
        // always copy-constrained (also during keygen), so the permutation
        // structure is identical for keygen and proving.
        layouter.assign_region(
            || "delegation equalities",
            |mut region| -> Result<(), Error> {
                let pairs = [
                    (g0.grant.parent, F::ZERO, "g0_parent_zero"),
                    (g1.grant.parent, g0.grant.id, "g1_parent"),
                    (g1.grant.issuer, g0.grant.subject, "issuer_continuity"),
                    (g1.grant.subject, req[0], "request_subject"),
                    (g0.grant.resource, req[1], "g0_resource"),
                    (g1.grant.resource, req[1], "g1_resource"),
                ];
                for (i, (a, b, label)) in pairs.iter().enumerate() {
                    let ca = region.assign_advice(|| *label, config.scratch, 2 * i, || v(*a))?;
                    let cb = region.assign_advice(|| *label, config.scratch, 2 * i + 1, || v(*b))?;
                    region.constrain_equal(ca.cell(), cb.cell())?;
                }
                Ok(())
            },
        )?;

        let g0_root = walk_leaves(
            &config,
            layouter.namespace(|| "g0_grant"),
            bundle.g0_words, bundle.g0_sibs, bundle.g0_dirs,
            &bundle.d_node, "g0_grant")?;
        let g1_root = walk_leaves(
            &config,
            layouter.namespace(|| "g1_grant"),
            bundle.g1_words, bundle.g1_sibs, bundle.g1_dirs,
            &bundle.d_node, "g1_grant")?;
        let g0_rev_root = walk_leaves(
            &config,
            layouter.namespace(|| "g0_revoke"),
            bundle.g0_rev_words, bundle.g0_rev_sibs, bundle.g0_rev_dirs,
            &bundle.d_node, "g0_revoke")?;
        let g1_rev_root = walk_leaves(
            &config,
            layouter.namespace(|| "g1_revoke"),
            bundle.g1_rev_words, bundle.g1_rev_sibs, bundle.g1_rev_dirs,
            &bundle.d_node, "g1_revoke")?;

        let digest = hash_words(
            &config, layouter.namespace(|| "request_digest"), "request_digest",
            bundle.request_words)?;

        layouter.constrain_instance(g0_root.cell(), config.instance, 0)?;
        layouter.constrain_instance(g1_root.cell(), config.instance, 0)?;
        layouter.constrain_instance(g0_rev_root.cell(), config.instance, 1)?;
        layouter.constrain_instance(g1_rev_root.cell(), config.instance, 1)?;
        layouter.constrain_instance(bundle.policy.cell(), config.instance, 2)?;
        layouter.constrain_instance(bundle.epoch.cell(), config.instance, 3)?;
        layouter.constrain_instance(digest.cell(), config.instance, 4)?;

        Ok(())
    }
}

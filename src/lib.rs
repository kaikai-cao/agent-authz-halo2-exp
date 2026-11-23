//! EXP-D2-A: Private Authorization Path Proof with Halo2.
//!
//! Fixed two-level delegation, 16-slot Poseidon grant/revocation trees,
//! Pallas field with `P128Pow5T3`.  This is a protocol-circuit experiment,
//! not a complete authorization system.

pub mod circuit;
pub mod model;
pub mod poseidon_hash;
pub mod public_inputs;
pub mod reference;
pub mod registry;

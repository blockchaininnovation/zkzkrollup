use crate::r#const::PATH_LEN;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::marker::PhantomData;

fn mock_hash<F: FieldExt>(a: F, b: F) -> F {
    let g = F::random(ChaCha8Rng::from_seed([101u8; 32]));
    (a + g) * (b + g)
}

struct Alloc<F: FieldExt> {
    cell: Cell,
    value: Value<F>,
}

enum MaybeAlloc<F: FieldExt> {
    Alloc(Alloc<F>),
    Unalloc(F),
}

impl<F: FieldExt> MaybeAlloc<F> {
    fn value(&self) -> Value<F> {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.value.clone(),
            MaybeAlloc::Unalloc(value) => Value::known(value.clone()),
        }
    }

    fn cell(&self) -> Cell {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.cell.clone(),
            MaybeAlloc::Unalloc(_) => unreachable!(),
        }
    }
}

pub struct MerkleChip<F: FieldExt> {
    config: MerkleChipConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct MerkleChipConfig {
    a_col: Column<Advice>,
    b_col: Column<Advice>,
    c_col: Column<Advice>,
    pub_col: Column<Instance>,
    s_pub: Selector,
    s_bool: Selector,
    s_swap: Selector,
    s_hash: Selector,
    perm_digest: Permutation,
}

impl<F: FieldExt> Chip<F> for MerkleChip<F> {
    type Config = MerkleChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> MerkleChip<F> {
    fn new(config: MerkleChipConfig) -> Self {
        MerkleChip {
            config,
            _marker: PhantomData,
        }
    }

    pub(crate) fn configure(cs: &mut ConstraintSystem<F>) -> MerkleChipConfig {
        let g = F::random(ChaCha8Rng::from_seed([101u8; 32]));
        let a_col = cs.advice_column();
        let b_col = cs.advice_column();
        let c_col = cs.advice_column();
        let pub_col = cs.instance_column();

        let s_pub = cs.selector();
        let s_bool = cs.selector();
        let s_swap = cs.selector();
        let s_hash = cs.selector();

        cs.create_gate("public input", |cs| {
            let c = cs.query_advice(c_col, Rotation::cur());
            let pi = cs.query_instance(pub_col, Rotation::cur());
            let s_pub = cs.query_selector(s_pub);
            vec![s_pub * (c - pi)]
        });

        cs.create_gate("boolean constrain", |cs| {
            let c = cs.query_advice(c_col, Rotation::cur());
            let s_bool = cs.query_selector(s_bool);
            vec![s_bool * c.clone() * (Expression::Constant(F::one()) - c)]
        });

        // |-------|-------|-------|--------|
        // | a_col | b_col | c_col | s_swap |
        // |-------|-------|-------|--------|
        // |   a   |   b   |  bit  |    1   |
        // |   l   |   r   |       |        |
        // |-------|-------|-------|--------|
        // where:
        //     bit = 0  ==>  l = a, r = b
        //     bit = 1  ==>  l = b, r = a
        //
        // Choose left gate:
        //     logic: let l = if bit == 0 { a } else { b }
        //     poly:  bit * (b - a) - (l - a) = 0
        //
        // Choose right gate:
        //     logic: let r = if bit == 0 { b } else { a }
        //     poly:  bit * (b - a) - (b - r) = 0
        //
        // Swap gate = choose left + choose right:
        //     logic: let (l, r) = if bit == 0 { (a, b) } else { (b, a) }
        //     poly: bit * (b - a) - (l - a) + bit * (b - a) - (b - r) = 0
        //           bit * 2 * (b - a)  - (l - a) - (b - r) = 0
        cs.create_gate("swap", |cs| {
            let a = cs.query_advice(a_col, Rotation::cur());
            let b = cs.query_advice(b_col, Rotation::cur());
            let bit = cs.query_advice(c_col, Rotation::cur());
            let s_swap = cs.query_selector(s_swap);
            let l = cs.query_advice(a_col, Rotation::next());
            let r = cs.query_advice(b_col, Rotation::next());
            vec![s_swap * ((bit * F::from(2) * (b.clone() - a.clone()) - (l - a)) - (b - r))]
        });

        // (l + gamma) * (r + gamma) = digest
        cs.create_gate("hash", |cs| {
            let l = cs.query_advice(a_col, Rotation::cur());
            let r = cs.query_advice(b_col, Rotation::cur());
            let digest = cs.query_advice(c_col, Rotation::cur());
            let s_hash = cs.query_selector(s_hash);
            vec![s_hash * ((l + Expression::Constant(g)) * (r + Expression::Constant(g)) - digest)]
        });

        let perm_digest = Permutation::new(cs, &[c_col.into(), a_col.into()]);

        MerkleChipConfig {
            a_col,
            b_col,
            c_col,
            pub_col,
            s_pub,
            s_bool,
            s_swap,
            s_hash,
            perm_digest,
        }
    }

    fn hash_leaf_layer(
        &self,
        layouter: &mut impl Layouter<F>,
        leaf: F,
        path_elem: F,
        c_bit: F,
    ) -> Result<Alloc<F>, Error> {
        self.hash_layer_inner(layouter, MaybeAlloc::Unalloc(leaf), path_elem, c_bit, 0)
    }

    fn hash_non_leaf_layer(
        &self,
        layouter: &mut impl Layouter<F>,
        prev_digest: Alloc<F>,
        path_elem: F,
        c_bit: F,
        layer: usize,
    ) -> Result<Alloc<F>, Error> {
        self.hash_layer_inner(
            layouter,
            MaybeAlloc::Alloc(prev_digest),
            path_elem,
            c_bit,
            layer,
        )
    }

    fn hash_layer_inner(
        &self,
        layouter: &mut impl Layouter<F>,
        leaf_or_digest: MaybeAlloc<F>,
        path_elem: F,
        c_bit: F,
        layer: usize,
    ) -> Result<Alloc<F>, Error> {
        let mut digest_alloc: Option<Alloc<F>> = None;

        layouter.assign_region(
            || "leaf layer",
            |mut region| {
                let mut row_offset = 0;

                // Allocate in `a_col` either the leaf or reallocate the previous tree layer's
                // calculated digest (stored in the previous row's `c_col`).
                let a_value = leaf_or_digest.value();

                let a_cell = region.assign_advice(
                    || {
                        format!(
                            "{} (layer {})",
                            if layer == 0 { "leaf" } else { "a" },
                            layer
                        )
                    },
                    self.config.a_col,
                    row_offset,
                    || a_value,
                )?;

                if layer > 0 {
                    let prev_digest_cell = leaf_or_digest.cell();
                    region.constrain_equal(&self.config.perm_digest, prev_digest_cell, a_cell)?;
                }

                // Allocate private inputs for this tree layer's path element and challenge bit (in
                // columns `b_col` and `c_col` respectively). Expose the challenge bit as a public
                // input.
                let _elem_cell = region.assign_advice(
                    || format!("path elem (layer {})", layer),
                    self.config.b_col,
                    row_offset,
                    || Value::known(path_elem),
                )?;

                let _c_bit_cell = region.assign_advice(
                    || format!("challenge bit (layer {})", layer),
                    self.config.c_col,
                    row_offset,
                    || Value::known(c_bit),
                )?;

                // Expose the challenge bit as a public input.
                self.config.s_pub.enable(&mut region, row_offset)?;

                // Boolean constrain the challenge bit.
                self.config.s_bool.enable(&mut region, row_offset)?;

                // Enable the "swap" gate to ensure the correct order of the Merkle hash inputs.
                self.config.s_swap.enable(&mut region, row_offset)?;

                // In the next row, allocate the correctly ordered Merkle hash inputs, calculated digest, and
                // enable the "hash" gate. If this is the last tree layer, expose the calculated
                // digest as a public input for the tree's root.
                row_offset += 1;

                let (preimg_l_value, preimg_r_value): (Value<F>, Value<F>) = if c_bit == F::zero() {
                    (a_value, Value::known(path_elem))
                } else {
                    (Value::known(path_elem), a_value)
                };

                let _preimg_l_cell = region.assign_advice(
                    || format!("preimg_l (layer {})", layer),
                    self.config.a_col,
                    row_offset,
                    || preimg_l_value,
                )?;

                let _preimg_r_cell = region.assign_advice(
                    || format!("preimage right (layer {})", layer),
                    self.config.b_col,
                    row_offset,
                    || preimg_r_value,
                )?;

                let digest_value = mock_hash(preimg_l_value, preimg_r_value);

                let digest_cell = region.assign_advice(
                    || format!("digest (layer {})", layer),
                    self.config.c_col,
                    row_offset,
                    || digest_value,
                )?;

                digest_alloc = Some(Alloc {
                    cell: digest_cell,
                    value: digest_value,
                });

                self.config.s_hash.enable(&mut region, row_offset)?;

                // If the calculated digest is the tree's root, expose it as a public input.
                let digest_is_root = layer == PATH_LEN - 1;
                if digest_is_root {
                    self.config.s_pub.enable(&mut region, row_offset)?;
                }

                Ok(())
            },
        )?;

        Ok(digest_alloc.unwrap())
    }
}

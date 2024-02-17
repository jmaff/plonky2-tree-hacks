use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::common::{hash::merkle::gadgets::merkle_proof::NUM_HASH_OUT_ELEMENTS, WHashOut};

pub trait CircuitBuilderHashCore<F: RichField + Extendable<D>, const D: usize> {
    fn constant_whash(&mut self, value: WHashOut<F>) -> HashOutTarget;
    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget;
    fn two_to_one_swapped<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashCore<F, D>
    for CircuitBuilder<F, D>
{
    /*fn constant_hash(&mut self, value: HashOut<F>) -> HashOutTarget {
        let a = self.cons
    }*/

    fn constant_whash(&mut self, value: WHashOut<F>) -> HashOutTarget {
        self.constant_hash(value.0)
    }

    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget {
        self.constant_whash(WHashOut::from_string_or_panic(value))
    }

    fn two_to_one_swapped<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget {
        let zero = self.zero();
        let mut state = H::AlgebraicPermutation::new(std::iter::repeat(zero));

        state.set_from_slice(&left.elements, 0);
        state.set_from_slice(&right.elements, NUM_HASH_OUT_ELEMENTS);
        state = H::permute_swapped(state, swap, self);

        HashOutTarget {
            elements: state.squeeze()[0..NUM_HASH_OUT_ELEMENTS]
                .try_into()
                .unwrap(),
        }
    }
}

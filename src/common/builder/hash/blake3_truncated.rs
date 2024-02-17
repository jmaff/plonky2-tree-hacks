use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{RichField, HashOutTarget};
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::hash::traits::hasher::GenericCircuitMerkleHasher;
use crate::common::richer_field::RicherField;
use crate::common::u32::arithmetic_u32::{U32Target, CircuitBuilderU32};

use super::blake3::CircuitBuilderHashBlake3;
use super::hash192::{Hash192Target, CircuitBuilderHash192};
use super::hash256::Hash256Target;

pub trait CircuitBuilderTruncatedBlake3<F: RichField + Extendable<D>, const D: usize> {
    fn truncated_blake3(&mut self, data: &[U32Target]) -> Hash192Target;
    fn two_to_one_truncated_blake3(
        &mut self,
        left: Hash192Target,
        right: Hash192Target,
    ) -> Hash192Target;
    fn truncated_blake3_hash_out(&mut self, data: &[U32Target]) -> HashOutTarget;
    fn two_to_one_truncated_blake3_hash_out(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget;
}

#[inline]
fn truncate_hash_256_target(target: Hash256Target) -> Hash192Target {
    [
        target[0],
        target[1],
        target[2],
        target[3],
        target[4],
        target[5],
    ]
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderTruncatedBlake3<F, D>
    for CircuitBuilder<F, D>
{
    fn truncated_blake3(&mut self, data: &[U32Target]) -> Hash192Target {
      truncate_hash_256_target(self.hash_blake3_u32(data))
    }

    fn two_to_one_truncated_blake3(
        &mut self,
        left: Hash192Target,
        right: Hash192Target,
    ) -> Hash192Target {
      self.truncated_blake3(&[
         left,
         right
      ].concat())
    }

    fn truncated_blake3_hash_out(&mut self, data: &[U32Target]) -> HashOutTarget {
      let result = self.truncated_blake3(data);
      self.hash192_to_hash_out(result)
    }

    fn two_to_one_truncated_blake3_hash_out(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget {
      let left_192 = self.hash_out_to_hash192(left);
      let right_192 = self.hash_out_to_hash192(right);
      let result = self.two_to_one_truncated_blake3(left_192, right_192);
      self.hash192_to_hash_out(result)
    }
}



pub struct Blake3Hasher192;
impl GenericCircuitMerkleHasher<Hash192Target> for Blake3Hasher192{
    fn gc_two_to_one<F: RicherField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, left: Hash192Target, right: Hash192Target) -> Hash192Target {
        builder.two_to_one_truncated_blake3(left, right)
    }

    fn two_to_one_swapped<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash192Target,
        right: Hash192Target,
        swap: BoolTarget,
    ) -> Hash192Target {
        let x = builder.select_hash192(swap, left, right);
        let y = builder.select_hash192(swap, right, left);
        Self::gc_two_to_one(builder, x, y)
    }

    fn two_to_one_swapped_marked_leaf<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash192Target,
        right: Hash192Target,
        swap: BoolTarget,
    ) -> Hash192Target {
        let x = builder.select_hash192(swap, left, right);
        let y = builder.select_hash192(swap, right, left);
        let preimage = [
            x[0],
            x[1],
            x[2],
            x[3],
            x[4],
            x[5],

            y[0],
            y[1],
            y[2],
            y[3],
            y[4],
            y[5],
            
            builder.one_u32(),
        ];
        
      builder.truncated_blake3(&preimage)
    }
}


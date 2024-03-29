use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::{RichField, HashOutTarget};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::binaryhelpers::bytes::{read_u32_be_at, read_u32_le_at};
use crate::common::generic::{ConnectableTarget, CreatableTarget, SwappableTarget};
use crate::common::hash::traits::hasher::ToTargets;
use crate::common::u32::arithmetic_u32::{U32Target, CircuitBuilderU32};
use crate::common::u32::witness::WitnessU32;




pub type Hash192Target = [U32Target; 6];
impl ToTargets for Hash192Target {
    fn to_targets(&self) -> Vec<Target> {
        self.iter().map(|f|{f.0}).collect_vec()
    }
}
pub trait WitnessHash192<F: PrimeField64>: Witness<F> {
    fn set_hash192_target(&mut self, target: &Hash192Target, value: &[u8]);
    fn set_hash192_target_le(&mut self, target: &Hash192Target, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash192<F> for T {
    fn set_hash192_target(&mut self, target: &Hash192Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_be_at(value, 0));
        self.set_u32_target(target[1], read_u32_be_at(value, 4));
        self.set_u32_target(target[2], read_u32_be_at(value, 8));
        self.set_u32_target(target[3], read_u32_be_at(value, 12));
        self.set_u32_target(target[4], read_u32_be_at(value, 16));
        self.set_u32_target(target[5], read_u32_be_at(value, 20));
    }

    fn set_hash192_target_le(&mut self, target: &Hash192Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_le_at(value, 0));
        self.set_u32_target(target[1], read_u32_le_at(value, 4));
        self.set_u32_target(target[2], read_u32_le_at(value, 8));
        self.set_u32_target(target[3], read_u32_le_at(value, 12));
        self.set_u32_target(target[4], read_u32_le_at(value, 16));
        self.set_u32_target(target[5], read_u32_le_at(value, 20));
    }
}

pub trait CircuitBuilderHash192<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash192_target(&mut self) -> Hash192Target;
    fn connect_hash192(&mut self, x: Hash192Target, y: Hash192Target);
    fn select_hash192(&mut self, b: BoolTarget, x: Hash192Target, y: Hash192Target) -> Hash192Target;

    fn hash192_to_hash_out(&mut self, x: Hash192Target) -> HashOutTarget;
    fn hash_out_to_hash192(&mut self, x: HashOutTarget) -> Hash192Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash192<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash192_target(&mut self) -> Hash192Target {
        [
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),

            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
        ]
    }

    fn connect_hash192(&mut self, x: Hash192Target, y: Hash192Target) {
        self.connect_u32(x[0], y[0]);
        self.connect_u32(x[1], y[1]);
        self.connect_u32(x[2], y[2]);
        self.connect_u32(x[3], y[3]);
        self.connect_u32(x[4], y[4]);
        self.connect_u32(x[5], y[5]);
    }

    fn select_hash192(&mut self, b: BoolTarget, x: Hash192Target, y: Hash192Target) -> Hash192Target {
        [
            self.select_u32(b, x[0], y[0]),
            self.select_u32(b, x[1], y[1]),
            self.select_u32(b, x[2], y[2]),
            self.select_u32(b, x[3], y[3]),
            self.select_u32(b, x[4], y[4]),
            self.select_u32(b, x[5], y[5]),
        ]
    }

    fn hash192_to_hash_out(&mut self, x: Hash192Target) -> HashOutTarget {
        let shift_16 = self.constant(F::from_canonical_u64(1<<16));
        let shift_32 = self.constant(F::from_canonical_u64(1<<32));
        let x1_parts = self.split_low_high(x[1].0, 16, 32);
        let x4_parts = self.split_low_high(x[4].0, 16, 32);

        HashOutTarget {
            elements: [
                self.mul_add(x[0].0, shift_16, x1_parts.1),
                self.mul_add(x1_parts.0, shift_32, x[2].0),
                self.mul_add(x[3].0, shift_16, x4_parts.1),
                self.mul_add(x4_parts.0, shift_32, x[5].0),
            ]
        }
    }

    fn hash_out_to_hash192(&mut self, x: HashOutTarget) -> Hash192Target {
        let (x_1_high_16, x_0) = self.split_low_high(x.elements[0], 16, 48);
        let (x_2, x_1_low_16) = self.split_low_high(x.elements[1], 32, 48);
        let (x_4_high_16, x_3) = self.split_low_high(x.elements[2], 16, 48);
        let (x_5, x_4_low_16) = self.split_low_high(x.elements[3], 32, 48);

        let shift_16 = self.constant(F::from_canonical_u64(1<<16));
        [
            U32Target(x_0),
            U32Target(self.mul_add(x_1_high_16, shift_16, x_1_low_16)),
            U32Target(x_2),
            U32Target(x_3),
            U32Target(self.mul_add(x_4_high_16, shift_16, x_4_low_16)),
            U32Target(x_5),
        ]
    }

    
}


impl SwappableTarget for Hash192Target {
    fn swap<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, swap: BoolTarget, left: Self, right: Self) -> Self {
        builder.select_hash192(swap, right, left)
    }
}

impl CreatableTarget for Hash192Target {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        builder.add_virtual_hash192_target()
    }
}

impl ConnectableTarget for Hash192Target{
    fn connect<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, connect_value: Self) {
        builder.connect_hash192(*self, connect_value)
    }
}
use plonky2::{hash::{hash_types::{RichField, HashOut}, poseidon::PoseidonHash}, plonk::config::Hasher, field::goldilocks_field::GoldilocksField};

use crate::common::{hash::traits::hasher::WHasher, WHashOut};


impl<F:RichField> WHasher<F> for PoseidonHash {
    fn w_two_to_one(left: WHashOut<F>, right: WHashOut<F>) -> WHashOut<F> {
        WHashOut(Self::two_to_one(left.0, right.0))
    }
}

const fn gl_hash_out_from_u64(a: u64, b: u64, c: u64, d: u64) -> HashOut<GoldilocksField> {
    HashOut { elements: [
        GoldilocksField(a),
        GoldilocksField(b),
        GoldilocksField(c),
        GoldilocksField(d),
    ] }
}
pub const POSEDION_GOLDILOCKS_ZERO_HASHES: [HashOut<GoldilocksField>; 1] = [
    gl_hash_out_from_u64(0, 0, 0, 0),
];
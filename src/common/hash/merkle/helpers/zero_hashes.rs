use plonky2::hash::hash_types::RichField;

use crate::common::{hash::traits::hasher::WHasher, WHashOut};

pub fn compute_zero_hashes<F: RichField, H: WHasher<F>>(height: u8) -> Vec<WHashOut<F>>{
    let mut zero_hashes = vec![WHashOut::<F>::ZERO];
    let mut current = WHashOut::<F>::ZERO;
    for _ in 0..height {
        current = H::w_two_to_one(current, current);
        zero_hashes.push(current);
    }
    zero_hashes
}


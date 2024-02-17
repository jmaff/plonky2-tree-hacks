use plonky2::{hash::hash_types::RichField, field::goldilocks_field::GoldilocksField};


pub trait RicherField: RichField {
}
impl RicherField for GoldilocksField{}
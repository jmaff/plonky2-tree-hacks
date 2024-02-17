use plonky2::hash::hash_types::RichField;

use crate::common::WHashOut;


pub trait ZMTNodeStore<F: RichField> {
    fn set_node(&mut self, level: u8, index: u64, node: &WHashOut<F>)->anyhow::Result<Option<WHashOut<F>>>;
    fn get_node(&self, level: u8, index: u64)->anyhow::Result<Option<WHashOut<F>>>;
}
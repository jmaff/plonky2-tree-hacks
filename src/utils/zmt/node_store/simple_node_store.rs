use plonky2::{hash::hash_types::{RichField, HashOut}};

#[cfg(all(not(feature = "std"), not(test)))]
pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

use std::cmp::Ordering;
#[cfg(any(feature = "std", test))]
pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

use crate::common::WHashOut;

use super::core::ZMTNodeStore;
#[derive(Debug, Clone, Copy, Hash)]
struct NodeStoreKey {
    level: u8,
    index: u64,
}


impl Ord for NodeStoreKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.level != other.level {
            return self.level.cmp(&other.level);
        }else{
            return self.index.cmp(&other.index);
        }
    }
}

impl PartialOrd for NodeStoreKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NodeStoreKey {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && self.index == other.index
    }
}
impl Eq for NodeStoreKey {}

pub struct SimpleNodeStore {
    nodes: BTreeMap<NodeStoreKey, [u64; 4]>,
}

fn u64_array_to_whashout<F: RichField>(arr: &[u64; 4])->WHashOut<F>{
    WHashOut(HashOut::<F>{
        elements: [
            F::from_canonical_u64(arr[0]),
            F::from_canonical_u64(arr[1]),
            F::from_canonical_u64(arr[2]),
            F::from_canonical_u64(arr[3]),
        ]
    })
}
fn whashout_to_u64_array<F: RichField>(hash: &WHashOut<F>)->[u64; 4] {
    [
        hash.0.elements[0].to_canonical_u64(),
        hash.0.elements[1].to_canonical_u64(),
        hash.0.elements[2].to_canonical_u64(),
        hash.0.elements[3].to_canonical_u64()
    ]
}
impl SimpleNodeStore {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }
}
impl<F: RichField> ZMTNodeStore<F> for SimpleNodeStore {
    fn set_node(&mut self, level: u8, index: u64, node: &WHashOut<F>)-> anyhow::Result<Option<WHashOut<F>>>  {
        let result = self.nodes.insert(NodeStoreKey{level, index}, whashout_to_u64_array(node));
        if result.is_some() {
            Ok(Some(u64_array_to_whashout(&result.unwrap())))

        }else{
            Ok(None)
        }
    }
    fn get_node(&self, level: u8, index: u64)->anyhow::Result<Option<WHashOut<F>>> {
        let result = self.nodes.get(&NodeStoreKey{level, index});
        if result.is_some() {
            Ok(Some(u64_array_to_whashout(&result.unwrap())))
        }else{
            Ok(None)
        }
    }
}
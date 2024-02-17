use plonky2::hash::hash_types::RichField;

use crate::common::{
    hash::{
        merkle::helpers::{
            merkle_proof::{DeltaMerkleProof, MerkleProof},
            zero_hashes::compute_zero_hashes,
        },
        traits::hasher::WHasher,
    },
    WHashOut,
};

use super::node_store::core::ZMTNodeStore;

pub struct ZeroMerkleTree<F: RichField, H: WHasher<F>, S: ZMTNodeStore<F>> {
    height: u8,
    zero_hashes: Vec<WHashOut<F>>,
    store: S,
    _field: std::marker::PhantomData<F>,
    _hasher: std::marker::PhantomData<H>,
}

// merkle tree with methods for get root (returns whashout), get leaf (returns merkle proof), set leaf (returns delta merkle proof), and get height
impl<F: RichField, H: WHasher<F>, S: ZMTNodeStore<F>> ZeroMerkleTree<F, H, S> {
    pub fn new(height: u8, store: S) -> Self {
        Self {
            height,
            store,
            zero_hashes: compute_zero_hashes::<F, H>(height),
            _field: std::marker::PhantomData,
            _hasher: std::marker::PhantomData,
        }
    }
    fn get_node_or_zero(&self, level: u8, index: u64) -> anyhow::Result<WHashOut<F>> {
        self.store
            .get_node(level, index)
            .map(|node| node.unwrap_or_else(|| self.zero_hashes[(self.height - level) as usize]))
    }
    fn set_node_or_zero(
        &mut self,
        level: u8,
        index: u64,
        value: &WHashOut<F>,
    ) -> anyhow::Result<WHashOut<F>> {
        self.store
            .set_node(level, index, value)
            .map(|node| node.unwrap_or_else(|| self.zero_hashes[(self.height - level) as usize]))
    }
    pub fn set_leaf(
        &mut self,
        index: u64,
        value: WHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProof<F>> {
        let mut old_value = WHashOut::ZERO; //self.get_node_or_zero(self.height, index)?;
        let mut siblings: Vec<WHashOut<F>> = vec![];
        let mut current_value = value;
        let mut current_index = index;
        let mut level = self.height;
        while level > 0 {
            if level == self.height {
                old_value = self.set_node_or_zero(level, current_index, &current_value)?;
            } else {
                self.set_node_or_zero(level, current_index, &current_value)?;
            }
            let sibling_index = current_index ^ 1;
            let sibling = self.get_node_or_zero(level, sibling_index)?;

            current_value = if current_index & 1 == 0 {
                H::w_two_to_one(current_value, sibling)
            } else {
                H::w_two_to_one(sibling, current_value)
            };
            siblings.push(sibling);
            current_index = current_index >> 1;
            level -= 1;
        }

        let old_root = self.set_node_or_zero(0, 0, &current_value)?;

        Ok(DeltaMerkleProof {
            old_root: old_root,
            old_value: old_value,
            new_root: current_value,
            new_value: value,
            index: F::from_canonical_u64(index),
            siblings: siblings,
        })
    }
    pub fn get_leaf_value(&self, index: u64) -> anyhow::Result<WHashOut<F>> {
        self.get_node_or_zero(self.height, index)
    }
    pub fn get_leaf(&self, index: u64) -> anyhow::Result<MerkleProof<F>> {
        let mut current_index = index;
        let mut level = self.height;
        let mut siblings: Vec<WHashOut<F>> = vec![];
        while level > 0 {
            let sibling_index = current_index ^ 1;
            let sibling = self.get_node_or_zero(level, sibling_index)?;
            siblings.push(sibling);
            level -= 1;
            current_index = current_index >> 1;
        }
        let root = self.get_node_or_zero(0, 0)?;
        let value = self.get_node_or_zero(self.height, index)?;

        Ok(MerkleProof {
            root: root,
            value: value,
            index: F::from_canonical_u64(index),
            siblings: siblings,
        })
    }
    pub fn get_height(&self) -> u8 {
        self.height
    }
    pub fn max_leaves(&self) -> u64 {
        1u64<<(self.height as u64)
    }

}

#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash};

    use crate::{common::{WHashOut, hash::merkle::helpers::merkle_proof::MerkleProof}, utils::zmt::node_store::simple_node_store::SimpleNodeStore};

    use super::ZeroMerkleTree;

    type F = GoldilocksField;
    type H = PoseidonHash;
    #[test]
    fn test_zmt_basic() -> anyhow::Result<()> {
        let mut zmt = ZeroMerkleTree::<F, H, SimpleNodeStore>::new(32, SimpleNodeStore::new());
        let a = zmt.set_leaf(1, WHashOut::from_values(1, 0, 0, 0))?;
        assert_eq!(a.new_root, WHashOut::from_string_or_panic("8e57f79e2d660d3fa6f8e8e603d6232cc578766949086917dfe6bd1bb8c2d38a"));
        assert!(a.verify::<H>());
        let get_a = zmt.get_leaf(a.index.0)?;
        assert!(get_a.verify::<H>());
        assert_eq!(
            get_a, MerkleProof{
                index: a.index,
                root: a.new_root,
                siblings: a.siblings,
                value: a.new_value,
            }
        );
        let b = zmt.set_leaf(1000, WHashOut::from_values(7, 0, 0, 0))?;
        assert!(b.verify::<H>());
        assert_eq!(b.new_root, WHashOut::from_string_or_panic("6845454d82426fe6f8a80131f2c78216ed70f9690b3d72d57a984f8ed1f7d9b6"));
        let get_b = zmt.get_leaf(b.index.0)?;
        assert!(get_b.verify::<H>());
        assert_eq!(
            get_b, MerkleProof{
                index: b.index,
                root: b.new_root,
                siblings: b.siblings,
                value: b.new_value,
            }
        );
        Ok(())
    }
}

use std::fmt::Display;

use plonky2::{hash::hash_types::RichField, iop::witness::Witness};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::common::{hash::merkle::{helpers::merkle_proof::{ MerkleProofCore, DeltaMerkleProofCore}, gadgets::sha256::{merkle_proof::MerkleProofSha256Gadget, delta_merkle_proof::DeltaMerkleProofSha256Gadget}}, builder::hash::hash256::{WitnessHash256, Hash256Target}, generic::WitnessValueFor};


#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);

impl Hash256 {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = hex::decode(s).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8;32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Hash256(bytes)
    }
}


impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

pub type MerkleProof256 = MerkleProofCore<Hash256>;
pub type DeltaMerkleProof256 = DeltaMerkleProofCore<Hash256>;


impl MerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash256<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof256,
    ) {
        witness.set_hash256_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash256<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof256,
    ) {
        witness.set_hash256_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash256_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}


impl<F: RichField> WitnessValueFor<Hash256Target, F> for Hash256 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash256Target) {
        witness.set_hash256_target(&target, &self.0);
    }
}
impl<F: RichField> WitnessValueFor<Hash256Target, F, false> for Hash256 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash256Target) {
        witness.set_hash256_target_le(&target, &self.0);
    }
}

use std::fmt::Display;

use plonky2::{hash::hash_types::{RichField, HashOut}, iop::witness::Witness};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::common::{hash::merkle::{helpers::merkle_proof::{ MerkleProofCore, DeltaMerkleProofCore}, gadgets::sha256_truncated::{merkle_proof::MerkleProofTruncatedSha256Gadget, delta_merkle_proof::DeltaMerkleProofTruncatedSha256Gadget}}, builder::hash::hash192::{WitnessHash192, Hash192Target}, generic::WitnessValueFor};



#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub struct Hash192(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 24]);

impl Hash192 {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = hex::decode(s).unwrap();
        assert_eq!(bytes.len(), 24);
        let mut array = [0u8; 24];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl Display for Hash192 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
fn read_u48_in_field_from_bytes<F:RichField>(bytes: &[u8; 24], index: usize) -> F {
    // leave as non-canonical incase of field with a prime <= 48 bits
    F::from_noncanonical_u64((bytes[index] as u64) << 40
        | (bytes[index+1] as u64) << 32
        | (bytes[index+2] as u64) << 24
        | (bytes[index+3] as u64) << 16
        | (bytes[index+4] as u64) << 8
        | (bytes[index+5] as u64))
}
impl<F:RichField> From<&Hash192> for HashOut<F> {
    fn from(bytes: &Hash192) -> Self {
        HashOut { elements: [
            read_u48_in_field_from_bytes(&bytes.0, 0),
            read_u48_in_field_from_bytes(&bytes.0, 6),
            read_u48_in_field_from_bytes(&bytes.0, 12),
            read_u48_in_field_from_bytes(&bytes.0, 18),
        ] }
    }
}

impl Hash192 {
    pub fn to_hash_out<F:RichField>(&self) -> HashOut<F> {
        HashOut { elements: [
            read_u48_in_field_from_bytes(&self.0, 0),
            read_u48_in_field_from_bytes(&self.0, 6),
            read_u48_in_field_from_bytes(&self.0, 12),
            read_u48_in_field_from_bytes(&self.0, 18),
        ] }
    }
    pub fn from_hash_out<F:RichField>(hash: HashOut<F>)->Self {
        let mut bytes = [0u8; 24];
        for i in 0..4 {
            let element = hash.elements[i].to_canonical_u64();
            bytes[i*6] = (element >> 40) as u8;
            bytes[i*6+1] = (element >> 32) as u8;
            bytes[i*6+2] = (element >> 24) as u8;
            bytes[i*6+3] = (element >> 16) as u8;
            bytes[i*6+4] = (element >> 8) as u8;
            bytes[i*6+5] = element as u8;
        }
        Self(bytes)
    }
}
impl<F:RichField> From<Hash192> for HashOut<F> {
    fn from(hash192: Hash192) -> Self {
        hash192.to_hash_out()
    }
}



pub type MerkleProof192 = MerkleProofCore<Hash192>;
pub type DeltaMerkleProof192 = DeltaMerkleProofCore<Hash192>;


impl MerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash192<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof192,
    ) {
        witness.set_hash192_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash192<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof192,
    ) {
        witness.set_hash192_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash192_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}


impl<F: RichField> WitnessValueFor<Hash192Target, F, false> for Hash192 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash192Target) {
        witness.set_hash192_target_le(&target, &self.0);
    }
}

impl<F: RichField> WitnessValueFor<Hash192Target, F, true> for Hash192 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash192Target) {
        witness.set_hash192_target(&target, &self.0);
    }
}


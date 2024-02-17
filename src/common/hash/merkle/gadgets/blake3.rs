use crate::common::builder::hash::{hash256::Hash256Target, blake3::Blake3Hasher, hash192::Hash192Target, blake3_truncated::Blake3Hasher192};
use super::generic::{delta_merkle_proof::GenericDeltaMerkleProofVecGadget, merkle_proof::GenericMerkleProofVecGadget};

pub type Blake3DeltaMerkleProofVecGadget = GenericDeltaMerkleProofVecGadget<Hash256Target, Blake3Hasher>;
pub type Blake3MerkleProofVecGadget = GenericMerkleProofVecGadget<Hash256Target, Blake3Hasher>;

pub type Blake3x192DeltaMerkleProofVecGadget = GenericDeltaMerkleProofVecGadget<Hash192Target, Blake3Hasher192>;
pub type Blake3x192MerkleProofVecGadget = GenericMerkleProofVecGadget<Hash192Target, Blake3Hasher192>;
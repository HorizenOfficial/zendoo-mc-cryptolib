use algebra::{
    fields::{tweedle::Fr, PrimeField},
    BigInteger256,
};

use primitives::{
    crh::{
        poseidon::parameters::tweedle::{
            TweedleFrPoseidonHash,
            TweedleFrBatchPoseidonHash,
        }
    },
    merkle_tree::field_based_mht::{
        optimized::FieldBasedOptimizedMHT,
        parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS,
        FieldBasedMerkleTree, FieldBasedMerkleTreeParameters, BatchFieldBasedMerkleTreeParameters,
        FieldBasedMerkleTreePrecomputedEmptyConstants,
        FieldBasedMerkleTreePath, FieldBasedMHTPath,
    },
};

pub type BigInteger = BigInteger256;
pub type FieldElement = Fr;
pub type FieldHash = TweedleFrPoseidonHash;
pub type BatchFieldHash = TweedleFrBatchPoseidonHash;

pub const FIELD_SIZE: usize = 32; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE; // 32

#[derive(Debug, Clone)]
pub struct GingerMerkleTreeParameters;

impl FieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type Data = FieldElement;
    type H = FieldHash;
    const MERKLE_ARITY: usize = 2;
    const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> =
        Some(MHT_PARAMETERS);
}

impl BatchFieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type BH = BatchFieldHash;
}

pub type GingerMHTPath = FieldBasedMHTPath<GingerMerkleTreeParameters>;

//Mocked stuff
pub type SCProof = Fr;
pub type SCVk = Fr;

pub const SC_PROOF_SIZE: usize = 1;
pub const SC_VK_SIZE: usize = 1;
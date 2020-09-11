use algebra::{
    curves::mnt4753::MNT4 as PairingCurve,
    fields::{mnt4753::Fr, PrimeField},
    BigInteger768, FromBytes, ToBytes,
};

use crate::BackwardTransfer;
use primitives::{
    crh::{
        FieldBasedHash,
        poseidon::{
            MNT4PoseidonHash,
            batched_crh::MNT4BatchPoseidonHash as BatchFieldHash,
        }
    },
    merkle_tree::field_based_mht::{
        optimized::FieldBasedOptimizedMHT,
        poseidon::{
            MNT4753_PHANTOM_MERKLE_ROOT as PHANTOM_MERKLE_ROOT,
            MNT4753_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS
        },
        FieldBasedMerkleTree, FieldBasedMerkleTreeParameters, BatchFieldBasedMerkleTreeParameters,
        FieldBasedMerkleTreePrecomputedEmptyConstants,
        FieldBasedMerkleTreePath, FieldBasedMHTPath,
    },
};
use proof_systems::groth16::{prepare_verifying_key, verifier::verify_proof, Proof, VerifyingKey};

use std::{fs::File, io::Result as IoResult, path::Path};
pub type Error = Box<dyn std::error::Error>;

#[cfg(feature = "mc-test-circuit")]
use crate::MCTestCircuit;

pub type FieldElement = Fr;

pub const FIELD_SIZE: usize = 96; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE; // 96

pub const GROTH_PROOF_SIZE: usize = 771;

// Assuming 1 public input: (2G1 + 2G2 + 1GT) = 1540 + 4 byte to save size of gamma_abc_g1 vec
pub const VK_SIZE: usize = 1544;

//*******************************Generic I/O functions**********************************************

pub fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8]) -> IoResult<T> {
    T::read(buffer)
}

pub fn serialize_to_buffer<T: ToBytes>(to_write: &T, buffer: &mut [u8]) -> IoResult<()> {
    to_write.write(buffer)
}

pub fn read_from_file<T: FromBytes>(file_path: &Path) -> IoResult<T> {
    let mut fs = File::open(file_path)?;
    let t = T::read(&mut fs)?;
    Ok(t)
}

//Will return error if buffer.len > FIELD_SIZE. If buffer.len < FIELD_SIZE, padding 0s will be added
pub fn read_field_element_from_buffer_with_padding(buffer: &[u8]) -> IoResult<FieldElement> {
    let buff_len = buffer.len();

    //Pad to reach field element size
    let mut new_buffer = vec![];
    new_buffer.extend_from_slice(buffer);
    for _ in buff_len..FIELD_SIZE {
        new_buffer.push(0u8)
    } //Add padding zeros to reach field size

    FieldElement::read(&new_buffer[..])
}

pub fn read_field_element_from_u64(num: u64) -> FieldElement {
    FieldElement::from_repr(BigInteger768::from(num))
}

//************************************Poseidon Hash function****************************************

pub type FieldHash = MNT4PoseidonHash;

pub fn init_poseidon_hash(personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init(personalization)
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement){
    hash.update(*input);
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> FieldElement{
    hash.finalize()
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<&[FieldElement]>) {
    hash.reset(personalization);
}

#[deprecated(note = "Use UpdatableFieldHash instead")]
pub fn compute_poseidon_hash(input: &[FieldElement]) -> Result<FieldElement, Error> {
    let mut digest = FieldHash::init(None);
    for &fe in input.iter() {
        digest.update(fe);
    }
    Ok(digest.finalize())
}

//*****************************Naive threshold sig circuit related functions************************
pub type SCProof = Proof<PairingCurve>;
pub type SCVk = VerifyingKey<PairingCurve>;

impl BackwardTransfer {
    pub fn to_field_element(&self) -> IoResult<FieldElement> {
        let mut buffer = vec![];
        self.pk_dest.write(&mut buffer)?;
        self.amount.write(&mut buffer)?;
        read_field_element_from_buffer_with_padding(buffer.as_slice())
    }
}

#[cfg(feature = "mc-test-circuit")]
pub fn generate_test_mc_parameters(params_dir: &Path) -> Result<(), Error>
{
    //Save params to file
    let pk_path = params_dir.join("test_mc_pk");
    let vk_path = params_dir.join("test_mc_vk");

    let params = MCTestCircuit::<FieldElement>::generate_parameters()?;

    let mut fs_pk = File::create(pk_path)?;
    params.clone().write(&mut fs_pk)?;

    let mut fs_vk = File::create(vk_path)?;
    params.vk.write(&mut fs_vk)?;

    Ok(())
}


#[cfg(feature = "mc-test-circuit")]
pub fn create_test_mc_proof(
    end_epoch_mc_b_hash: &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list: &[BackwardTransfer],
    quality: u64,
    constant: &FieldElement,
    pk_path: &Path,
    proof_path: &Path,
) -> Result<(), Error> {

    //Read inputs as field elements
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(end_epoch_mc_b_hash)?;
    let prev_end_epoch_mc_b_hash =
        read_field_element_from_buffer_with_padding(prev_end_epoch_mc_b_hash)?;
    let quality = read_field_element_from_u64(quality);
    let bt_root = get_bt_merkle_root(bt_list)?;

    let params = read_from_file(pk_path)?;

    // Save proof to file
    let proof = MCTestCircuit::<FieldElement>::create_proof(
        end_epoch_mc_b_hash, prev_end_epoch_mc_b_hash, bt_root,
        quality, *constant, params
    )?;

    let mut fs_proof = File::create(proof_path)?;
    proof.write(&mut fs_proof)?;

    Ok(())
}

const BT_MERKLE_TREE_HEIGHT: usize = 12;

pub fn get_bt_merkle_root(bt_list: &[BackwardTransfer]) -> Result<FieldElement, Error>
{
    if bt_list.len() > 0 {
        let mut bt_as_fes = vec![];
        for bt in bt_list.iter() {
            let bt_as_fe = bt.to_field_element()?;
            bt_as_fes.push(bt_as_fe);
        }
        let mut bt_mt =
            GingerMHT::init(BT_MERKLE_TREE_HEIGHT,2usize.pow(BT_MERKLE_TREE_HEIGHT as u32));
        for &fe in bt_as_fes.iter(){
            bt_mt.append(fe);
        }
        bt_mt.finalize_in_place();
        bt_mt.root().ok_or(Error::from("Failed to compute BT Merkle Tree root"))

    } else { Ok(PHANTOM_MERKLE_ROOT) }
}

pub fn verify_sc_proof(
    end_epoch_mc_b_hash: &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list: &[BackwardTransfer],
    quality: u64,
    constant: Option<&FieldElement>,
    proofdata: Option<&FieldElement>,
    sc_proof: &SCProof,
    vk: &SCVk,
) -> Result<bool, Error> {
    //Read inputs as field elements
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(end_epoch_mc_b_hash)?;
    let prev_end_epoch_mc_b_hash =
        read_field_element_from_buffer_with_padding(prev_end_epoch_mc_b_hash)?;
    let quality = read_field_element_from_u64(quality);
    let bt_root = get_bt_merkle_root(bt_list)?;

    //Load vk from file
    let pvk = prepare_verifying_key(&vk);

    //Prepare public inputs

    let wcert_sysdata_hash = {
        let mut digest = init_poseidon_hash(None);
        digest
            .update(quality)
            .update(bt_root)
            .update(prev_end_epoch_mc_b_hash)
            .update(end_epoch_mc_b_hash)
            .finalize()
    };

    let mut digest = init_poseidon_hash(None);

    if constant.is_some(){
        digest.update(*(constant.unwrap()));
    }

    if proofdata.is_some(){
        digest.update(*(proofdata.unwrap()));
    }

    digest.update(wcert_sysdata_hash);

    let aggregated_inputs = digest.finalize();

    //Verify proof
    let is_verified = verify_proof(&pvk, &sc_proof, &[aggregated_inputs])?;
    Ok(is_verified)
}

//************Merkle Tree functions******************

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

pub fn verify_ginger_merkle_path(
    path: &GingerMHTPath,
    height: usize,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify(height, leaf, root)
}

pub type GingerMHT = FieldBasedOptimizedMHT<GingerMerkleTreeParameters>;

pub fn new_ginger_mht(height: usize, processing_step: usize) -> GingerMHT {
    GingerMHT::init(height, processing_step)
}

pub fn append_leaf_to_ginger_mht(tree: &mut GingerMHT, leaf: &FieldElement){
    tree.append(*leaf);
}

pub fn finalize_ginger_mht(tree: &GingerMHT) -> GingerMHT {
    tree.finalize()
}

pub fn finalize_ginger_mht_in_place(tree: &mut GingerMHT) {
    tree.finalize_in_place();
}

pub fn get_ginger_mht_root(tree: &GingerMHT) -> Option<FieldElement> {
    tree.root()
}

pub fn get_ginger_mht_path(tree: &GingerMHT, leaf_index: usize) -> Option<GingerMHTPath> {
    tree.get_merkle_path(leaf_index)
}

pub fn reset_ginger_mht(tree: &mut GingerMHT){
    tree.reset();
}

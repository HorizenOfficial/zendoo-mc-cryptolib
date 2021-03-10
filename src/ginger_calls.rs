use algebra::{PrimeField, FromBytes, ToBytes};
use crate::type_mapping::*;

use std::{fs::File, io::Result as IoResult, path::Path};
pub type Error = Box<dyn std::error::Error>;

use primitives::{FieldBasedHash, FieldBasedOptimizedMHT, FieldBasedMerkleTreePath, FieldBasedMerkleTree};


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
    FieldElement::from_repr(BigInteger::from(num))
}

//************************************Poseidon Hash function****************************************

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

//************Merkle Tree functions******************

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

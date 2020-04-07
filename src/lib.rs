use algebra::{fields::mnt4753::Fr, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Affine, G1Projective},
    ProjectiveCurve}, bytes::{FromBytes, ToBytes},
    UniformRand};

use primitives::{
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    },
    merkle_tree::field_based_mht::{
        FieldBasedMerkleHashTree, FieldBasedMerkleTreeConfig, FieldBasedMerkleTreePath
    },
};

use proof_systems::groth16::{Proof, verifier::verify_proof, prepare_verifying_key};

use rand::rngs::OsRng;
use libc::{
    c_uint, c_uchar
};
use std::{
    path::Path, slice, ffi::OsStr, os::unix::ffi::OsStrExt, fs::File, ptr::null_mut,
    io::{
        Error as IoError, ErrorKind,
    },
};

pub mod error;
use error::*;

#[cfg(test)]
pub mod tests;

// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771

// ************TYPES**********************

pub struct ZendooMcFieldBasedMerkleTreeParams;

impl FieldBasedMerkleTreeConfig for ZendooMcFieldBasedMerkleTreeParams {
    const HEIGHT: usize = 5;
    type H = FrHash;
}

type GingerMerkleTree = FieldBasedMerkleHashTree<ZendooMcFieldBasedMerkleTreeParams>;
type GingerMerkleTreePath = FieldBasedMerkleTreePath<ZendooMcFieldBasedMerkleTreeParams>;

type GingerProof = Proof<PairingCurve>;

// ***********UTILITY FUNCTIONS*************

fn read_raw_pointer<T>(input: *const T, elem_type: &str) -> Option<&T> {
    if input.is_null(){
        set_last_error(Box::new(NullPointerError(format!("Null {}", elem_type))), NULL_PTR_ERROR);
        return None
    }
    Some(unsafe{ &* input })
}

fn read_double_raw_pointer<T: Copy>(input: *const *const T, input_len: usize, elem_type: &str) -> Option<Vec<T>> {

    //Read *const T from *const *const T
    if input.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Ptr to {}s is null", elem_type))), NULL_PTR_ERROR);
        return None
    }
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for (i, &ptr) in input_raw.iter().enumerate() {
        if ptr.is_null() {
            set_last_error(Box::new(NullPointerError(format!("{} {} is null", elem_type, i))), NULL_PTR_ERROR);
            return None
        }
        input.push(unsafe{ *ptr });
    }

    Some(input)
}

fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8], buff_size: usize) -> *mut T {
    match T::read(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should read {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        }
    }
}

fn serialize_to_buffer<T: ToBytes>(to_write: *const T, buffer: &mut [u8], buff_size: usize, elem_type: &str) -> bool {
    let to_write = match read_raw_pointer(to_write, elem_type) {
        Some(to_write) => to_write,
        None => return false,
    };

    match to_write.write(buffer){
        Ok(_) => true,
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should write {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            false
        }
    }
}

fn read_from_file<T: FromBytes>(file_path: *const u8, file_path_len: usize, struct_type: &str) -> Option<T>{
    // Read file path
    let file_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(file_path, file_path_len)
    }));

    // Load struct from file
    let mut fs = match File::open(file_path) {
        Ok(file) => file,
        Err(_) => {
            let e = IoError::new(ErrorKind::NotFound, format!("unable to load {} file", struct_type));
            set_last_error(Box::new(e), IO_ERROR);
            return None
        }
    };

    match T::read(&mut fs) {
        Ok(t) => Some(t),
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("unable to deserialize {} from file", struct_type));
            set_last_error(Box::new(e), IO_ERROR);
            None
        }
    }
}

//***********Field functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_field_size_in_bytes() -> c_uint { FR_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_field(
    field_element: *const Fr,
    result:        *mut [c_uchar; FR_SIZE]
) -> bool
{ serialize_to_buffer(field_element, &mut (unsafe { &mut *result })[..], FR_SIZE, "field element") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes:    *const [c_uchar; FR_SIZE]
) -> *mut Fr
{ deserialize_from_buffer(&(unsafe { &*field_bytes })[..], FR_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_field_free(field: *mut Fr)
{
    if field.is_null()  { return }
    drop(unsafe { Box::from_raw(field) });
}

//***********Pk functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_pk_size_in_bytes() -> c_uint { G1_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_pk(
    pk:            *const G1Affine,
    result:        *mut [c_uchar; G1_SIZE]
) -> bool
{ serialize_to_buffer(pk, &mut (unsafe { &mut *result })[..], G1_SIZE, "pk") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_pk(
    pk_bytes:    *const [c_uchar; G1_SIZE]
) -> *mut G1Affine
{ deserialize_from_buffer(&(unsafe { &*pk_bytes })[..], G1_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_pk_free(pk: *mut G1Affine)
{
    if pk.is_null()  { return }
    drop(unsafe { Box::from_raw(pk) });
}

//********************SNARK functions********************

#[no_mangle]
pub extern "C" fn get_ginger_zk_proof_size() -> c_uint { GROTH_PROOF_SIZE as u32 }

#[no_mangle]
pub extern "C" fn serialize_ginger_zk_proof(
    zk_proof:       *const GingerProof,
    zk_proof_bytes: *mut [c_uchar; GROTH_PROOF_SIZE]
) -> bool { serialize_to_buffer(zk_proof, &mut (unsafe { &mut *zk_proof_bytes })[..], GROTH_PROOF_SIZE, "zk proof") }

#[no_mangle]
pub extern "C" fn deserialize_ginger_zk_proof(
    zk_proof_bytes: *const [c_uchar; GROTH_PROOF_SIZE]
) -> *mut GingerProof
{ deserialize_from_buffer(&(unsafe { &*zk_proof_bytes })[..], GROTH_PROOF_SIZE) }

#[no_mangle]
pub extern "C" fn verify_ginger_zk_proof
(
    vk_path:            *const u8,
    vk_path_len:        usize,
    zkp:                *const GingerProof,
    public_inputs:      *const *const Fr,
    public_inputs_len:  usize,
) -> bool
{
    //Read public inputs
    let public_inputs = match read_double_raw_pointer(public_inputs, public_inputs_len, "public input") {
        Some(public_inputs) => public_inputs,
        None => return false,
    };

    // Deserialize the proof
    let zkp = match read_raw_pointer(zkp, "zk_proof"){
        Some(zkp) => zkp,
        None => return false
    };

    //Load Vk
    let vk = match read_from_file(vk_path, vk_path_len, "vk"){
        Some(vk) => vk,
        None => return false
    };

    let pvk = prepare_verifying_key(&vk);

    //After computing pvk, vk is not needed anymore
    drop(vk);

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(Box::new(e), CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn ginger_zk_proof_free(zkp: *mut GingerProof)
{
    if zkp.is_null()  { return }
    drop(unsafe { Box::from_raw(zkp) });
}

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_compute_poseidon_hash(
    input:        *const *const Fr,
    input_len:    usize,
) -> *mut Fr
{
    //Read message
    let message = match read_double_raw_pointer(input, input_len, "field element") {
        Some(message) => message,
        None => return null_mut()
    };

    //Compute hash
    let hash = match FrHash::evaluate(message.as_slice()) {
        Ok(hash) => hash,
        Err(e) => return {
            set_last_error(e, CRYPTO_ERROR);
            null_mut()
        },
    };

    //Return pointer to hash
    Box::into_raw(Box::new(hash))

}

#[no_mangle]
pub extern "C" fn zendoo_compute_keys_hash_commitment(
    pks:        *const *const G1Affine,
    pks_len:    usize,
) -> *mut Fr
{

    //Read pks
    let pks_x = match read_double_raw_pointer(pks, pks_len, "pk") {
        Some(pks) => pks.iter().map(|&pk| pk.x).collect::<Vec<_>>(),
        None => return null_mut()
    };

    //Compute hash
    let hash = match FrHash::evaluate(pks_x.as_slice()) {
        Ok(hash) => hash,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    //Return pointer to hash
    Box::into_raw(Box::new(hash))
}

// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn ginger_mt_new(
    leaves:        *const *const Fr,
    leaves_len:    usize,
) -> *mut GingerMerkleTree
{
    //Read leaves
    let leaves = match read_double_raw_pointer(leaves, leaves_len, "field element") {
        Some(leaves) => leaves,
        None => return null_mut()
    };

    //Generate tree and compute Merkle Root
    let gmt = match GingerMerkleTree::new(&leaves) {
        Ok(tree) => tree,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_root(
    tree:   *const GingerMerkleTree,
) -> *mut Fr
{
    let tree = match read_raw_pointer(tree, "tree"){
        Some(tree) => tree,
        None => return null_mut()
    };
    let root = tree.root();
    Box::into_raw(Box::new(root))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_merkle_path(
    leaf:       *const Fr,
    leaf_index: usize,
    tree:       *const GingerMerkleTree,
) -> *mut GingerMerkleTreePath
{
    //Read tree
    let tree = match read_raw_pointer(tree, "tree"){
        Some(tree) => tree,
        None => return null_mut()
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf"){
        Some(leaf) => leaf,
        None => return null_mut()
    };

    //Compute Merkle Path
    let mp = match tree.generate_proof(leaf_index, leaf) {
        Ok(path) => path,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(mp))
}

#[no_mangle]
pub extern "C" fn ginger_mt_verify_merkle_path(
    leaf:        *const Fr,
    merkle_root: *const Fr,
    path:        *const GingerMerkleTreePath,
) -> bool
{

    //Read path
    let path = match read_raw_pointer(path, "path"){
        Some(path) => path,
        None => return false
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf"){
        Some(leaf) => leaf,
        None => return false
    };

    //Read root
    let root = match read_raw_pointer(merkle_root, "root"){
        Some(root) => root,
        None => return false
    };

    // Verify leaf belonging
    match path.verify(root, leaf) {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn ginger_mt_free(tree: *mut GingerMerkleTree) {
    if tree.is_null() { return }
    drop(unsafe { Box::from_raw(tree) });
}

#[no_mangle]
pub extern "C" fn ginger_mt_path_free(path: *mut GingerMerkleTreePath) {
    if path.is_null()  { return }
    drop(unsafe { Box::from_raw(path) });
}

//***************Test functions*******************

fn check_equal<T: Eq>(val_1: *const T, val_2: *const T) -> bool{
    let val_1 = unsafe{ &* val_1 };
    let val_2 = unsafe{ &* val_2 };
    val_1 == val_2
}

#[no_mangle]
pub extern "C" fn zendoo_get_random_field() -> *mut Fr {
    let mut rng = OsRng;
    let random_f = Fr::rand(&mut rng);
    Box::into_raw(Box::new(random_f))
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const Fr,
    field_2: *const Fr,
) -> bool { check_equal(field_1, field_2 )}

#[no_mangle]
pub extern "C" fn zendoo_get_random_pk() -> *mut G1Affine {
    let mut rng = OsRng;
    let random_g = G1Projective::rand(&mut rng);
    Box::into_raw(Box::new(random_g.into_affine()))
}

#[no_mangle]
pub extern "C" fn zendoo_pk_assert_eq(
    pk_1: *const G1Affine,
    pk_2: *const G1Affine,
) -> bool { check_equal(pk_1, pk_2) }
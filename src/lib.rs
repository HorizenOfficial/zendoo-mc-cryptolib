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

use proof_systems::groth16::{Proof, verifier::verify_proof, prepare_verifying_key, VerifyingKey};

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
    const HASH_LEAVES: bool = true;
    const HEIGHT: usize = 32;
    type H = FrHash;
}

type GingerMerkleTree = FieldBasedMerkleHashTree<ZendooMcFieldBasedMerkleTreeParams>;
type GingerMerkleTreePath = FieldBasedMerkleTreePath<ZendooMcFieldBasedMerkleTreeParams>;

type GingerProof = Proof<PairingCurve>;

// ***********UTILITY FUNCTIONS*************

fn read_double_raw_pointer<T: Copy>(input: *const *const T, input_len: usize) -> Option<Vec<T>> {

    //Read *const T from *const *const T
    if input.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Input ptr is null"))), NULL_PTR_ERROR);
        return None
    }
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for (i, &ptr) in input_raw.iter().enumerate() {
        if ptr.is_null() {
            set_last_error(Box::new(NullPointerError(format!("Input {} is null", i))), NULL_PTR_ERROR);
            return None
        }
        input.push(unsafe{ *ptr });
    }

    Some(input)
}

fn read_vk(vk_path: *const u8, vk_path_len: usize) -> Result<VerifyingKey<PairingCurve>, IoError>
{
    // Read vk path
    let vk_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(vk_path, vk_path_len)
    }));

    // Load vk from file
    let mut vk_fs = match File::open(vk_path) {
        Ok(vk_file) => vk_file,
        Err(_) => return Err(IoError::new(ErrorKind::NotFound, "unable to load vk file"))
    };

    match VerifyingKey::<PairingCurve>::read(&mut vk_fs) {
        Ok(vk) => Ok(vk),
        Err(_) => Err(IoError::new(ErrorKind::InvalidData, "unable to deserialize vk from file"))
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
{
    if field_element.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Null field element"))), NULL_PTR_ERROR);
        return false
    }
    let fe = unsafe { &*field_element };
    match fe.write(&mut (unsafe { &mut *result })[..]) {
        Err(_) => {
            let err = IoError::new(ErrorKind::InvalidData, format!("result should be {} bytes", FR_SIZE));
            set_last_error(Box::new(err), IO_ERROR);
            false
        }
        Ok(_) => true
    }
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes:    *const [c_uchar; FR_SIZE]
) -> *mut Fr
{
    //Read field
    let fe_bytes = unsafe { &*field_bytes };
    let fe = match Fr::read(&fe_bytes[..]) {
        Ok(fe) => fe,
        Err(e) => {
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        },
    };
    Box::into_raw(Box::new(fe))
}

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
{
    if pk.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Null pk"))), NULL_PTR_ERROR);
        return false
    }
    let pk = unsafe { &*pk };
    match pk.write(&mut (unsafe { &mut *result })[..]) {
        Err(_) => {
            let err = IoError::new(ErrorKind::InvalidData, format!("result should be {} bytes", G1_SIZE));
            set_last_error(Box::new(err), IO_ERROR);
            false
        }
        Ok(_) => true
    }
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_pk(
    pk_bytes:    *const [c_uchar; G1_SIZE]
) -> *mut G1Affine
{
    //Read pk
    let pk_bytes = unsafe{&* pk_bytes};
    let pk = match G1Affine::read(&pk_bytes[..]) {
        Ok(fe) => fe,
        Err(e) => {
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(pk))
}

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
) -> bool {

    if zk_proof.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Null zk proof"))), NULL_PTR_ERROR);
        return false
    }
    let zk_proof = unsafe {&* zk_proof};
    match zk_proof.write(&mut (unsafe { &mut *zk_proof_bytes })[..]) {
        Err(_) => {
            let err = IoError::new(ErrorKind::InvalidData, format!("result should be {} bytes", GROTH_PROOF_SIZE));
            set_last_error(Box::new(err), IO_ERROR);
            false
        }
        Ok(_) => true
    }
}

#[no_mangle]
pub extern "C" fn deserialize_ginger_zk_proof(
    zk_proof_bytes: *const [c_uchar; GROTH_PROOF_SIZE]
) -> *mut GingerProof
{
    //Deserialize the proof
    let zkp = match GingerProof::read(&(unsafe { &*zk_proof_bytes })[..]) {
        Ok(zkp) => zkp,
        Err(e) => {
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(zkp))
}

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
    let public_inputs = match read_double_raw_pointer(public_inputs, public_inputs_len) {
        Some(public_inputs) => public_inputs,
        None => return false,
    };

    // Deserialize the proof
    let zkp = unsafe {&* zkp};

    //Load Vk
    let vk = match read_vk(vk_path, vk_path_len){
        Ok(vk) => vk,
        Err(e) => {
            set_last_error(Box::new(e), IO_ERROR);
            return false;
        }
    };

    let pvk = prepare_verifying_key(&vk);

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        // No error, and proof verification successful
        Ok(true) => true,
        // Any other case
        Ok(false) => false,
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
    let message = match read_double_raw_pointer(input, input_len) {
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
    let pks_x = match read_double_raw_pointer(pks, pks_len) {
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
    let leaves = match read_double_raw_pointer(leaves, leaves_len) {
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
    if tree.is_null() {
        let err = NullPointerError(format!("Null tree"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return null_mut()
    }
    let root = unsafe { &*tree }.root();
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
    if tree.is_null() {
        let err = NullPointerError(format!("Null tree"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return null_mut()
    }
    let tree = unsafe { &*tree };

    //Read leaf
    if leaf.is_null(){
        let err = NullPointerError(format!("Null leaf"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return null_mut()
    }
    let leaf = unsafe{ &*leaf };

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
    if path.is_null() {
        let err = NullPointerError(format!("Null path"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return false
    }
    let path = unsafe { &*path };

    //Read leaf
    if leaf.is_null(){
        let err = NullPointerError(format!("Null leaf"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return false
    }
    let leaf = unsafe{ &*leaf };

    //Read root
    if merkle_root.is_null(){
        let err = NullPointerError(format!("Null merkle root"));
        set_last_error(Box::new(err), NULL_PTR_ERROR);
        return false
    }
    let root = unsafe{ &*merkle_root };

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

#[no_mangle]
pub extern "C" fn zendoo_get_random_field() -> *mut Fr {
    let mut rng = OsRng::default();
    let random_f = Fr::rand(&mut rng);
    Box::into_raw(Box::new(random_f))
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const Fr,
    field_2: *const Fr,
) -> bool
{
    let field_1 = unsafe {&* field_1};
    let field_2 = unsafe {&* field_2};
    field_1 == field_2
}

#[no_mangle]
pub extern "C" fn zendoo_get_random_pk() -> *mut G1Affine {
    let mut rng = OsRng::default();
    let random_g = G1Projective::rand(&mut rng);
    Box::into_raw(Box::new(random_g.into_affine()))
}

#[no_mangle]
pub extern "C" fn zendoo_pk_assert_eq(
    pk_1: *const G1Affine,
    pk_2: *const G1Affine,
) -> bool
{
    let pk_1 = unsafe {&* pk_1};
    let pk_2 = unsafe {&* pk_2};
    pk_1 == pk_2
}
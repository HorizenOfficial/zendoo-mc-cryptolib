use algebra::{FromBytes, ToBytes, UniformRand};
use libc::{c_uchar, c_uint};
use rand::rngs::OsRng;
use std::{
    ffi::OsStr,
    io::{Error as IoError, ErrorKind},
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr::null_mut,
    slice,
};

pub mod error;
use error::*;

pub mod ginger_calls;
use ginger_calls::*;

#[cfg(test)]
pub mod tests;

// ***********UTILITY FUNCTIONS*************

fn read_raw_pointer<T>(input: *const T, elem_type: &str) -> Option<&T> {
    if input.is_null() {
        set_last_error(
            Box::new(NullPointerError(format!("Null {}", elem_type))),
            NULL_PTR_ERROR,
        );
        return None;
    }
    Some(unsafe { &*input })
}

fn read_double_raw_pointer<T: Copy>(
    input: *const *const T,
    input_len: usize,
    elem_type: &str,
) -> Option<Vec<T>> {
    //Read *const T from *const *const T
    if input.is_null() {
        set_last_error(
            Box::new(NullPointerError(format!("Ptr to {}s is null", elem_type))),
            NULL_PTR_ERROR,
        );
        return None;
    }
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for (i, &ptr) in input_raw.iter().enumerate() {
        if ptr.is_null() {
            set_last_error(
                Box::new(NullPointerError(format!("{} {} is null", elem_type, i))),
                NULL_PTR_ERROR,
            );
            return None;
        }
        input.push(unsafe { *ptr });
    }

    Some(input)
}

fn deserialize_to_raw_pointer<T: FromBytes>(buffer: &[u8], buff_size: usize) -> *mut T {
    match deserialize_from_buffer(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!("should read {} bytes", buff_size),
            );
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut();
        }
    }
}

fn serialize_from_raw_pointer<T: ToBytes>(
    to_write: *const T,
    buffer: &mut [u8],
    buff_size: usize,
    elem_type: &str,
) -> bool {
    let to_write = match read_raw_pointer(to_write, elem_type) {
        Some(to_write) => to_write,
        None => return false,
    };

    match serialize_to_buffer(to_write, buffer) {
        Ok(_) => true,
        Err(_) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!("should write {} bytes", buff_size),
            );
            set_last_error(Box::new(e), IO_ERROR);
            false
        }
    }
}

fn deserialize_from_file<T: FromBytes>(
    file_path: *const u8,
    file_path_len: usize,
    struct_type: &str,
) -> Option<T> {
    // Read file path
    let file_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(file_path, file_path_len)
    }));

    match read_from_file(file_path) {
        Ok(t) => Some(t),
        Err(e) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "unable to deserialize {} from file: {}",
                    struct_type,
                    e.to_string()
                ),
            );
            set_last_error(Box::new(e), IO_ERROR);
            None
        }
    }
}

//***********Field functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_field_size_in_bytes() -> c_uint {
    FIELD_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_field(
    field_element: *const FieldElement,
    result: *mut [c_uchar; FIELD_SIZE],
) -> bool {
    serialize_from_raw_pointer(
        field_element,
        &mut (unsafe { &mut *result })[..],
        FIELD_SIZE,
        "field element",
    )
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes: *const [c_uchar; FIELD_SIZE],
) -> *mut FieldElement {
    deserialize_to_raw_pointer(&(unsafe { &*field_bytes })[..], FIELD_SIZE)
}

#[no_mangle]
pub extern "C" fn zendoo_field_free(field: *mut FieldElement) {
    if field.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(field) });
}

//********************Sidechain SNARK functions********************
#[repr(C)]
pub struct BackwardTransfer {
    pub pk_dest: [c_uchar; 32],
    pub amount: u64,
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_proof_size() -> c_uint {
    GROTH_PROOF_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_sc_proof(
    sc_proof: *const SCProof,
    sc_proof_bytes: *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    serialize_from_raw_pointer(
        sc_proof,
        &mut (unsafe { &mut *sc_proof_bytes })[..],
        GROTH_PROOF_SIZE,
        "sc proof",
    )
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof(
    sc_proof_bytes: *const [c_uchar; GROTH_PROOF_SIZE],
) -> *mut SCProof {
    deserialize_to_raw_pointer(&(unsafe { &*sc_proof_bytes })[..], GROTH_PROOF_SIZE)
}

#[no_mangle]
pub extern "C" fn zendoo_sc_proof_free(sc_proof: *mut SCProof) {
    if sc_proof.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(sc_proof) });
}

#[no_mangle]
pub extern "C" fn zendoo_verify_sc_proof(
    end_epoch_mc_b_hash: *const [c_uchar; 32],
    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
    bt_list: *const BackwardTransfer,
    bt_list_len: usize,
    quality: u64,
    constant: *const FieldElement,
    proofdata: *const *const FieldElement,
    proofdata_len: usize,
    sc_proof: *const SCProof,
    vk_path: *const u8,
    vk_path_len: usize,
) -> bool {
    //Read end_epoch_mc_b_hash
    let end_epoch_mc_b_hash = match read_raw_pointer(end_epoch_mc_b_hash, "end_epoch_mc_block_hash")
    {
        Some(end_epoch_mc_b_hash) => end_epoch_mc_b_hash,
        None => return false,
    };

    //Read prev_end_epoch_mc_b_hash
    let prev_end_epoch_mc_b_hash =
        match read_raw_pointer(prev_end_epoch_mc_b_hash, "prev_end_epoch_mc_block_hash") {
            Some(prev_end_epoch_mc_b_hash) => prev_end_epoch_mc_b_hash,
            None => return false,
        };

    //Read bt_list
    let bt_list = unsafe { slice::from_raw_parts(bt_list, bt_list_len) };

    //Read constant
    let constant = match read_raw_pointer(constant, "constant"){
        Some(constant) => Some(constant),
        None => {
            zendoo_clear_error(); //If ptr is null error will be set, but constant is allowed to be NULL
            None
        },
    };

    //Read proofdata
    let proofdata = match read_double_raw_pointer(proofdata, proofdata_len, "proofdata"){
        Some(proofdata) => Some(proofdata),
        None => {
            zendoo_clear_error(); //If ptr is null error will be set, but proofdata is allowed to be NULL
            None
        },
    };

    //Read SCProof
    let sc_proof = match read_raw_pointer(sc_proof, "sc_proof") {
        Some(sc_proof) => sc_proof,
        None => return false,
    };

    //Read vk from file
    let vk = match deserialize_from_file(vk_path, vk_path_len, "sc verification key") {
        Some(vk) => vk,
        None => return false,
    };

    //Verify proof
    match ginger_calls::verify_sc_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        bt_list,
        quality,
        constant,
        proofdata,
        sc_proof,
        vk,
    ) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_compute_poseidon_hash(
    input: *const *const FieldElement,
    input_len: usize,
) -> *mut FieldElement {
    //Read message
    let message = match read_double_raw_pointer(input, input_len, "field element") {
        Some(message) => message,
        None => return null_mut(),
    };

    //Compute hash
    let hash = match compute_poseidon_hash(message.as_slice()) {
        Ok(hash) => hash,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        }
    };

    //Return pointer to hash
    Box::into_raw(Box::new(hash))
}

// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn ginger_mt_new(
    leaves: *const *const FieldElement,
    leaves_len: usize,
) -> *mut GingerMerkleTree {
    //Read leaves
    let leaves = match read_double_raw_pointer(leaves, leaves_len, "field element") {
        Some(leaves) => leaves,
        None => return null_mut(),
    };

    //Generate tree and compute Merkle Root
    let gmt = match new_ginger_merkle_tree(leaves.as_slice()) {
        Ok(tree) => tree,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut();
        }
    };

    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_root(tree: *const GingerMerkleTree) -> *mut FieldElement {
    let tree = match read_raw_pointer(tree, "tree") {
        Some(tree) => tree,
        None => return null_mut(),
    };
    Box::into_raw(Box::new(get_ginger_merkle_root(tree)))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_merkle_path(
    leaf: *const FieldElement,
    leaf_index: usize,
    tree: *const GingerMerkleTree,
) -> *mut GingerMerkleTreePath {
    //Read tree
    let tree = match read_raw_pointer(tree, "tree") {
        Some(tree) => tree,
        None => return null_mut(),
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf") {
        Some(leaf) => leaf,
        None => return null_mut(),
    };

    //Compute Merkle Path
    let mp = match get_ginger_merkle_path(leaf, leaf_index, tree) {
        Ok(path) => path,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut();
        }
    };

    Box::into_raw(Box::new(mp))
}

#[no_mangle]
pub extern "C" fn ginger_mt_verify_merkle_path(
    leaf: *const FieldElement,
    merkle_root: *const FieldElement,
    path: *const GingerMerkleTreePath,
) -> bool {
    //Read path
    let path = match read_raw_pointer(path, "path") {
        Some(path) => path,
        None => return false,
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf") {
        Some(leaf) => leaf,
        None => return false,
    };

    //Read root
    let root = match read_raw_pointer(merkle_root, "root") {
        Some(root) => root,
        None => return false,
    };

    // Verify leaf belonging
    match verify_ginger_merkle_path(path, root, leaf) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn ginger_mt_free(tree: *mut GingerMerkleTree) {
    if tree.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(tree) });
}

#[no_mangle]
pub extern "C" fn ginger_mt_path_free(path: *mut GingerMerkleTreePath) {
    if path.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(path) });
}

//***************Test functions*******************

fn check_equal<T: Eq>(val_1: *const T, val_2: *const T) -> bool {
    let val_1 = unsafe { &*val_1 };
    let val_2 = unsafe { &*val_2 };
    val_1 == val_2
}

#[no_mangle]
pub extern "C" fn zendoo_get_random_field() -> *mut FieldElement {
    let mut rng = OsRng;
    let random_f = FieldElement::rand(&mut rng);
    Box::into_raw(Box::new(random_f))
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const FieldElement,
    field_2: *const FieldElement,
) -> bool {
    check_equal(field_1, field_2)
}

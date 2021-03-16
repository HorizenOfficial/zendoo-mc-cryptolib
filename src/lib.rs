use algebra::{FromBytes, ToBytes, UniformRand};
use libc::{c_uchar, c_uint};
use rand::rngs::OsRng;
use std::{
    io::{Error as IoError, ErrorKind},
    path::Path,
    ptr::null_mut,
    any::type_name,
    slice,
};

pub mod error;
use error::*;

pub mod ginger_calls;
use ginger_calls::*;

pub mod type_mapping;
use type_mapping::*;

//#[cfg(test)]
//pub mod tests;

#[cfg(not(target_os = "windows"))]
use std::ffi::OsStr;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

// ***********UTILITY FUNCTIONS*************

fn read_raw_pointer<'a, T>(input: *const T) -> &'a T {
    assert!(!input.is_null());
    unsafe { &*input }
}

fn read_mut_raw_pointer<'a, T>(input: *mut T) -> &'a mut T {
    assert!(!input.is_null());
    unsafe { &mut *input }
}

fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

fn read_double_raw_pointer<T: Copy>(
    input: *const *const T,
    input_len: usize,
) -> Vec<T> {

    //Read *const T from *const *const T
    assert!(!input.is_null());
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for &ptr in input_raw.iter() {
        assert!(!ptr.is_null());
        input.push(unsafe { *ptr });
    }
    input
}

fn deserialize_to_raw_pointer<T: FromBytes>(buffer: &[u8]) -> *mut T {
    match deserialize_from_buffer(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!("unable to read {} from buffer", type_name::<T>()),
            );
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut();
        }
    }
}

fn serialize_from_raw_pointer<T: ToBytes>(
    to_write: *const T,
    buffer: &mut [u8],
) {
    serialize_to_buffer(read_raw_pointer(to_write), buffer)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

fn deserialize_from_file<T: FromBytes>(
    file_path: &Path,
) -> Option<T> {
    match read_from_file(file_path) {
        Ok(t) => Some(t),
        Err(e) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "unable to deserialize {} from file: {}",
                    type_name::<T>(),
                    e.to_string()
                ),
            );
            set_last_error(Box::new(e), IO_ERROR);
            None
        }
    }
}

pub fn free_pointer<T> (ptr: *mut T) {
    if ptr.is_null() { return };

    unsafe { drop( Box::from_raw(ptr)) }
}

//***********Bit Vector functions****************
use cctp_primitives::bit_vector::compression::*;

#[repr(C)]
pub struct BitVectorBuffer {
    data: *mut u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn zendoo_compress_bit_vector(buffer: *const BitVectorBuffer, algorithm: CompressionAlgorithm) -> *mut BitVectorBuffer {

    let bit_vector: Vec<u8> = unsafe { Vec::from_raw_parts((*buffer).data, (*buffer).len, (*buffer).len) };

    match compress_bit_vector(&bit_vector, algorithm) {
        Ok(mut compressed_bit_vector) => {
            let data = compressed_bit_vector.as_mut_ptr();
            let len = compressed_bit_vector.len();
            std::mem::forget(compressed_bit_vector);
            let bit_vector_buffer = BitVectorBuffer {data, len};
            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(_) => null_mut()
    }

}

#[no_mangle]
pub extern "C" fn zendoo_decompress_bit_vector(buffer: *const BitVectorBuffer, expected_uncrompressed_size: usize) -> *mut BitVectorBuffer {

    let compressed_bit_vector: Vec<u8> = unsafe { Vec::from_raw_parts((*buffer).data, (*buffer).len, (*buffer).len) };

    match decompress_bit_vector(&compressed_bit_vector, expected_uncrompressed_size) {
        Ok(mut decompressed_bit_vector) => {
            let data = decompressed_bit_vector.as_mut_ptr();
            let len = decompressed_bit_vector.len();
            std::mem::forget(decompressed_bit_vector);
            let bit_vector_buffer = BitVectorBuffer {data, len};
            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(_) => null_mut()
    }

}

#[test]
fn compress_decompress() {
    use std::{alloc::{self, Layout}, mem};
    loop {
        let mut bit_vector: Vec<u8> = (0..100).collect();
        println!("Capacity: {}", bit_vector.capacity());
        let data = bit_vector.as_mut_ptr();
        let len = bit_vector.len();

        let buffer = BitVectorBuffer { data, len };

        let compressed_buffer = zendoo_compress_bit_vector(&buffer, CompressionAlgorithm::Bzip2);
        let uncompressed_buffer = zendoo_decompress_bit_vector(compressed_buffer, len);

        let processed_bit_vector = unsafe { Vec::from_raw_parts((*uncompressed_buffer).data, (*uncompressed_buffer).len, (*uncompressed_buffer).len) };
        assert_eq!((0..100).collect::<Vec<u8>>(), processed_bit_vector);

        std::mem::forget(bit_vector);
        std::mem::forget(unsafe{(*compressed_buffer).data});

        let layout = Layout::from_size_align(processed_bit_vector.len(), mem::align_of::<u8>()).expect("Bad layout");
        //unsafe {alloc::dealloc((*uncompressed_buffer).data, layout)};

        //break;
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
){
    serialize_from_raw_pointer(
        field_element,
        &mut (unsafe { &mut *result })[..],
    )
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes: *const [c_uchar; FIELD_SIZE],
) -> *mut FieldElement {
    deserialize_to_raw_pointer(&(unsafe { &*field_bytes })[..])
}

#[no_mangle]
pub extern "C" fn zendoo_field_free(field: *mut FieldElement) { free_pointer(field) }

//********************Sidechain SNARK functions********************
#[repr(C)]
pub struct BackwardTransfer {
    pub pk_dest: [c_uchar; 20],
    pub amount: u64,
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_proof_size_in_bytes() -> c_uint {
    SC_PROOF_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_sc_proof(
    sc_proof: *const SCProof,
    sc_proof_bytes: *mut [c_uchar; SC_PROOF_SIZE],
){}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof(
    sc_proof_bytes: *const [c_uchar; SC_PROOF_SIZE],
) -> *mut SCProof {
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_proof_free(sc_proof: *mut SCProof) {  }

#[no_mangle]
pub extern "C" fn zendoo_get_sc_vk_size_in_bytes() -> c_uint {
    SC_VK_SIZE as u32
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    vk_path: *const u8,
    vk_path_len: usize,
) -> *mut SCVk
{
    null_mut()
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    vk_path: *const u16,
    vk_path_len: usize,
) -> *mut SCVk
{
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk(
    sc_vk_bytes: *const [c_uchar; SC_VK_SIZE],
) -> *mut SCVk {
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_vk_free(sc_vk: *mut SCVk) { }

#[no_mangle]
pub extern "C" fn zendoo_verify_sc_proof(
    end_epoch_mc_b_hash: *const [c_uchar; 32],
    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
    bt_list: *const BackwardTransfer,
    bt_list_len: usize,
    quality: u64,
    constant: *const FieldElement,
    proofdata: *const FieldElement,
    sc_proof: *const SCProof,
    vk:       *const SCVk,
) -> bool { true }

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_init_poseidon_hash(
    personalization: *const *const FieldElement,
    personalization_len: usize,
) -> *mut FieldHash {

    let uh = if !personalization.is_null(){
        init_poseidon_hash(Some(read_double_raw_pointer(personalization, personalization_len).as_slice()))
    } else {
        init_poseidon_hash(None)
    };

    Box::into_raw(Box::new(uh))
}

#[no_mangle]
pub extern "C" fn zendoo_update_poseidon_hash(
    fe: *const FieldElement,
    digest: *mut FieldHash
){

    let input = read_raw_pointer(fe);

    let digest = read_mut_raw_pointer(digest);

    update_poseidon_hash(digest, input);
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_poseidon_hash(
    digest: *const FieldHash
) -> *mut FieldElement {

    let digest = read_raw_pointer(digest);

    let output = finalize_poseidon_hash(digest);

    Box::into_raw(Box::new(output))
}

#[no_mangle]
pub extern "C" fn zendoo_reset_poseidon_hash(
    digest: *mut FieldHash,
    personalization: *const *const FieldElement,
    personalization_len: usize,
) {

    let digest = read_mut_raw_pointer(digest);

    if !personalization.is_null(){
        reset_poseidon_hash(digest, Some(read_double_raw_pointer(personalization, personalization_len).as_slice()));
    } else {
        reset_poseidon_hash(digest, None);
    }
}

#[no_mangle]
pub extern "C" fn zendoo_free_poseidon_hash(
    digest: *mut FieldHash
) { free_pointer(digest) }

#[deprecated]
#[no_mangle]
pub extern "C" fn zendoo_compute_poseidon_hash(
    input: *const *const FieldElement,
    input_len: usize,
) -> *mut FieldElement {

    // Read message
    let message = read_double_raw_pointer(input, input_len);

    // Compute hash
    let mut digest = init_poseidon_hash(None);
    for fe in message.into_iter(){
        digest.update(fe);
    }

    //Return pointer to hash
    Box::into_raw(Box::new(digest.finalize()))
}

// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn zendoo_new_ginger_mht(
    height: usize,
    processing_step: usize,
) -> *mut GingerMHT {

    let gmt = new_ginger_mht(height, processing_step);
    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn zendoo_append_leaf_to_ginger_mht(
    leaf: *const FieldElement,
    tree: *mut GingerMHT,
)
{
    let leaf = read_raw_pointer(leaf);

    let tree = read_mut_raw_pointer(tree);

    append_leaf_to_ginger_mht(tree, leaf);
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_ginger_mht(
    tree: *const GingerMHT
) -> *mut GingerMHT
{
    let tree = read_raw_pointer(tree);

    let tree_copy = finalize_ginger_mht(tree);

    Box::into_raw(Box::new(tree_copy))
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_ginger_mht_in_place(
    tree: *mut GingerMHT
)
{
    let tree = read_mut_raw_pointer(tree);

    finalize_ginger_mht_in_place(tree);
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_mht_root(
    tree: *const GingerMHT
) -> *mut FieldElement
{
    let tree = read_raw_pointer(tree);

    match get_ginger_mht_root(tree) {
        Some(root) => Box::into_raw(Box::new(root)),
        None => null_mut()
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_merkle_path(
    tree: *const GingerMHT,
    leaf_index: usize
) -> *mut GingerMHTPath
{
    let tree = read_raw_pointer(tree);

    match get_ginger_mht_path(tree, leaf_index) {
        Some(path) => Box::into_raw(Box::new(path)),
        None => null_mut()
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_empty_node(
    height: usize
) -> *mut FieldElement
{
    use primitives::merkle_tree::field_based_mht::parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS;

    let max_height = MHT_PARAMETERS.nodes.len() - 1;
    assert!(height <= max_height, format!("Empty node not pre-computed for height {}", height));

    let empty_node = MHT_PARAMETERS.nodes[max_height - height].clone();

    Box::into_raw(Box::new(empty_node))
}

#[no_mangle]
pub extern "C" fn zendoo_verify_ginger_merkle_path(
    path: *const GingerMHTPath,
    height: usize,
    leaf: *const FieldElement,
    root: *const FieldElement,
) -> bool
{
    let path = read_raw_pointer(path);

    let root = read_raw_pointer(root);

    let leaf = read_raw_pointer(leaf);

    match verify_ginger_merkle_path(path, height, leaf, root) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_free_ginger_merkle_path(
    path: *mut GingerMHTPath
) { free_pointer(path) }

#[no_mangle]
pub extern "C" fn zendoo_reset_ginger_mht(
    tree: *mut GingerMHT
)
{
    let tree = read_mut_raw_pointer(tree);

    reset_ginger_mht(tree);
}

#[no_mangle]
pub extern "C" fn zendoo_free_ginger_mht(
    tree: *mut GingerMHT
) { free_pointer(tree) }

//***************Test functions*******************

#[cfg(feature = "mc-test-circuit")]
pub mod mc_test_circuit;
#[cfg(feature = "mc-test-circuit")]
pub use self::mc_test_circuit::*;
use primitives::FieldBasedHash;

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_generate_mc_test_params(
    params_dir: *const u16,
    params_dir_len: usize,
) -> bool {

    // Read params_dir
    let params_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(params_dir, params_dir_len)
    });
    let params_dir = Path::new(&params_str);

    match ginger_calls::generate_test_mc_parameters(params_dir) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_generate_mc_test_params(
    params_dir: *const u8,
    params_dir_len: usize,
) -> bool {

    // Read params_dir
    let params_dir = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(params_dir, params_dir_len)
    }));

    match ginger_calls::generate_test_mc_parameters(params_dir) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
    proof_path: *const u8,
    proof_path_len: usize,
) -> *mut SCProof
{
    // Read file path
    let proof_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(proof_path, proof_path_len)
    }));

    match deserialize_from_file(proof_path){
        Some(proof) => Box::into_raw(Box::new(proof)),
        None => null_mut(),
    }
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
    proof_path: *const u16,
    proof_path_len: usize,
) -> *mut SCProof
{
    // Read file path
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(proof_path, proof_path_len)
    });
    let proof_path = Path::new(&path_str);

    match deserialize_from_file(proof_path){
        Some(proof) => Box::into_raw(Box::new(proof)),
        None => null_mut(),
    }
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_create_mc_test_proof(
    end_epoch_mc_b_hash: *const [c_uchar; 32],
    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
    bt_list: *const BackwardTransfer,
    bt_list_len: usize,
    quality: u64,
    constant: *const FieldElement,
    pk_path: *const u8,
    pk_path_len: usize,
    proof_path: *const u8,
    proof_path_len: usize,
) -> bool
{
    //Read end_epoch_mc_b_hash
    let end_epoch_mc_b_hash = read_raw_pointer(end_epoch_mc_b_hash);

    //Read prev_end_epoch_mc_b_hash
    let prev_end_epoch_mc_b_hash = read_raw_pointer(prev_end_epoch_mc_b_hash);

    //Read bt_list
    let bt_list = if !bt_list.is_null() {
        unsafe { slice::from_raw_parts(bt_list, bt_list_len) }
    } else {
        &[]
    };

    //Read constant
    let constant = read_raw_pointer(constant);

    //Read pk path
    let pk_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(pk_path, pk_path_len)
    }));

    //Read path to which save the proof
    let proof_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(proof_path, proof_path_len)
    }));

    //Generate proof and vk
    match ginger_calls::create_test_mc_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        bt_list,
        quality,
        constant,
        pk_path,
        proof_path,
    ) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_create_mc_test_proof(
    end_epoch_mc_b_hash: *const [c_uchar; 32],
    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
    bt_list: *const BackwardTransfer,
    bt_list_len: usize,
    quality: u64,
    constant: *const FieldElement,
    pk_path: *const u16,
    pk_path_len: usize,
    proof_path: *const u16,
    proof_path_len: usize,
) -> bool
{
    //Read end_epoch_mc_b_hash
    let end_epoch_mc_b_hash = read_raw_pointer(end_epoch_mc_b_hash);

    //Read prev_end_epoch_mc_b_hash
    let prev_end_epoch_mc_b_hash = read_raw_pointer(prev_end_epoch_mc_b_hash);

    //Read bt_list
    let bt_list = if !bt_list.is_null() {
        unsafe { slice::from_raw_parts(bt_list, bt_list_len) }
    } else {
        &[]
    };

    //Read constant
    let constant = read_raw_pointer(constant);

    //Read pk path
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(pk_path, pk_path_len)
    });
    let pk_path = Path::new(&path_str);

    //Read path to which save the proof
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(proof_path, proof_path_len)
    });
    let proof_path = Path::new(&path_str);

    //Generate proof and vk
    match ginger_calls::create_test_mc_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        bt_list,
        quality,
        constant,
        pk_path,
        proof_path,
    ) {
        Ok(()) => true,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

fn check_equal<T: PartialEq>(val_1: *const T, val_2: *const T) -> bool {
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
pub extern "C" fn zendoo_get_field_from_long(value: u64) -> *mut FieldElement {
    let fe = FieldElement::from(value);
    Box::into_raw(Box::new(fe))
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const FieldElement,
    field_2: *const FieldElement,
) -> bool {
    check_equal(field_1, field_2)
}

#[no_mangle]
pub extern "C" fn zendoo_sc_vk_assert_eq(
    sc_vk_1: *const SCVk,
    sc_vk_2: *const SCVk,
) -> bool {
    check_equal(sc_vk_1, sc_vk_2)
}

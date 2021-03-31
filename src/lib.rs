use algebra::{FromBytes, ToBytes, UniformRand};
use libc::{c_uchar, c_uint};
use rand::rngs::OsRng;
use std::{
    io::{Error as IoError, ErrorKind},
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

#[cfg(test)]
pub mod tests;

// ***********UTILITY FUNCTIONS*************

fn read_raw_pointer<'a, T>(input: *const T) -> &'a T {
    assert!(!input.is_null());
    unsafe { &*input }
}

fn read_mut_raw_pointer<'a, T>(input: *mut T) -> &'a mut T {
    assert!(!input.is_null());
    unsafe { &mut *input }
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

pub fn free_pointer<T> (ptr: *mut T) {
    if ptr.is_null() { return };

    unsafe { drop( Box::from_raw(ptr)) }
}

//*********** Commitment Tree functions ****************
use cctp_primitives::commitment_tree::CommitmentTree;
use cctp_primitives::commitment_tree::hashers::hash_bytes;

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_create() -> *mut CommitmentTree {

    let cmt = CommitmentTree::create();
    let heap_obj = Box::new(cmt);
    //println!("Ctor: heap_obj {:p}", heap_obj);
    let raw_obj = Box::into_raw(heap_obj);
    //println!("      raw_obj  {:p}", raw_obj);
    raw_obj
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_delete(ptr : *mut CommitmentTree) {
    if ptr.is_null() {
        println!("delete: nullptr!");
        return;
    }
    unsafe {
        //println!("Dtor: raw_obj  {:p}", ptr);
        //let heap_obj = Box::from_raw(ptr);
        //println!("      heap_obj {:p}", heap_obj);
        drop (Box::from_raw(ptr))
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_custom_data_size_in_bytes() -> c_uint {
    CUSTOM_DATA_MAX_SIZE as u32
}


#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_scc(ptr : *mut CommitmentTree,
    sc_id: *const BufferWithSize,
    amount: i64,
    pub_key: *const BufferWithSize,
    withdrawal_epoch_length: u32,
    custom_data: *const BufferWithSize,
    constant:    *const BufferWithSize,
    cert_vk: *const BufferWithSize,
    btr_vk: *const BufferWithSize,
    csw_vk: *const BufferWithSize,
    tx_hash: *const BufferWithSize,
    out_idx: u32, 
    ret_code : &mut CctpErrorCode)-> bool
{
    *ret_code = CctpErrorCode::OK;
    if ptr.is_null() {
        *ret_code = CctpErrorCode::NullPtr;
        dbg!(*ret_code);
        return false;
    }

    // optional or variable size parameters
    let mut rs_custom_data : &[u8] = &[];
    let (is_ok, _err) = check_buffer(custom_data);
    if is_ok {
        rs_custom_data = unsafe {
            if (*custom_data).len > CUSTOM_DATA_MAX_SIZE { *ret_code = CctpErrorCode::InvalidBufferLength; dbg!(*ret_code); return false; } 
            slice::from_raw_parts((*custom_data).data, (*custom_data).len)
        };
    }

    let mut rs_constant : Option<&[u8]> = None;
    let (is_ok, _err) = check_buffer(constant);
    if is_ok {
        rs_constant = Some(unsafe {
            if (*constant).len != FIELD_SIZE { *ret_code = CctpErrorCode::InvalidBufferLength; dbg!(*ret_code); return false; } 
            slice::from_raw_parts((*constant).data, (*constant).len)
        });
    }

    let mut rs_csw_vk : Option<&[u8]> = None;
    let (is_ok, _err) = check_buffer(csw_vk);
    if is_ok {
        rs_csw_vk = Some(unsafe {
            if (*csw_vk).len != SC_VK_SIZE { *ret_code = CctpErrorCode::InvalidBufferLength; dbg!(*ret_code); return false; } 
            slice::from_raw_parts((*csw_vk).data, (*csw_vk).len)
        });
    }

    let mut rs_btr_vk : Option<&[u8]> = None;
    let (is_ok, _err) = check_buffer(btr_vk);
    if is_ok {
        rs_btr_vk = Some(unsafe {
            if (*btr_vk).len != SC_VK_SIZE { *ret_code = CctpErrorCode::InvalidBufferLength; dbg!(*ret_code); return false; } 
            slice::from_raw_parts((*btr_vk).data, (*btr_vk).len)
        });
    }

    // mandatory and constant size parameters
    let (is_ok, err) = check_buffer_length(sc_id, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_id = unsafe { slice::from_raw_parts((*sc_id).data,   (*sc_id).len)};

    let (is_ok, err) = check_buffer_length(pub_key, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_pub_key = unsafe { slice::from_raw_parts((*pub_key).data, (*pub_key).len)};

    let (is_ok, err) = check_buffer_length(cert_vk, SC_VK_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_cert_vk = unsafe { slice::from_raw_parts((*cert_vk).data, (*cert_vk).len)};

    let (is_ok, err) = check_buffer_length(tx_hash, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_tx_hash = unsafe { slice::from_raw_parts((*tx_hash).data, (*tx_hash).len)};

    let cmt = unsafe { &mut *ptr };
    let ret = cmt.add_scc(
        rs_sc_id,       amount,      rs_pub_key, withdrawal_epoch_length,
        rs_custom_data, rs_constant, rs_cert_vk, rs_btr_vk,
        rs_csw_vk,      rs_tx_hash,  out_idx);
    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!(*ret_code);
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_fwt(ptr : *mut CommitmentTree,
    sc_id: *const BufferWithSize,
    amount: i64,
    pub_key: *const BufferWithSize,
    tx_hash: *const BufferWithSize,
    out_idx: u32, 
    ret_code : &mut CctpErrorCode)-> bool
{
    *ret_code = CctpErrorCode::OK;
    if ptr.is_null() {
        *ret_code = CctpErrorCode::NullPtr;
        dbg!(*ret_code);
        return false;
    }

    let (is_ok, err) = check_buffer_length(sc_id, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_id = unsafe { slice::from_raw_parts((*sc_id).data,   (*sc_id).len)};

    let (is_ok, err) = check_buffer_length(pub_key, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_pub_key = unsafe { slice::from_raw_parts((*pub_key).data, (*pub_key).len)};

    let (is_ok, err) = check_buffer_length(tx_hash, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_tx_hash = unsafe { slice::from_raw_parts((*tx_hash).data, (*tx_hash).len)};

    let cmt = unsafe { &mut *ptr };
    let ret = cmt.add_fwt(
        rs_sc_id, amount, rs_pub_key, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_fwt() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_bwtr(ptr : *mut CommitmentTree,
    sc_id: *const BufferWithSize,
    sc_fee: i64,
    sc_req_data: *const BufferWithSize,
    pk_hash: *const BufferWithSize,
    tx_hash: *const BufferWithSize,
    out_idx: u32, 
    ret_code : &mut CctpErrorCode)-> bool
{
    *ret_code = CctpErrorCode::OK;
    if ptr.is_null() {
        *ret_code = CctpErrorCode::NullPtr;
        dbg!(*ret_code);
        return false;
    }

    let (is_ok, err) = check_buffer_length(sc_id, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_id = unsafe { slice::from_raw_parts((*sc_id).data,   (*sc_id).len)};

    let (is_ok, err) = check_buffer_length(pk_hash, UINT_160_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_pk_hash = unsafe { slice::from_raw_parts((*pk_hash).data, (*pk_hash).len)};

    let (is_ok, err) = check_buffer_length(tx_hash, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_tx_hash = unsafe { slice::from_raw_parts((*tx_hash).data, (*tx_hash).len)};

    let (is_ok, err) = check_buffer_length(sc_req_data, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_req_data = unsafe { slice::from_raw_parts((*sc_req_data).data, (*sc_req_data).len)};

    let cmt = unsafe { &mut *ptr };
    let ret = cmt.add_bwtr(
        rs_sc_id, sc_fee, rs_sc_req_data, rs_pk_hash, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_bwtr() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_csw(ptr : *mut CommitmentTree,
    sc_id: *const BufferWithSize,
    amount: i64,
    nullifier: *const BufferWithSize,
    pk_hash: *const BufferWithSize,
    active_cert_data_hash: *const BufferWithSize,
    ret_code : &mut CctpErrorCode)-> bool
{
    *ret_code = CctpErrorCode::OK;
    if ptr.is_null() {
        *ret_code = CctpErrorCode::NullPtr;
        dbg!(*ret_code);
        return false;
    }

    let (is_ok, err) = check_buffer_length(sc_id, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_id = unsafe { slice::from_raw_parts((*sc_id).data, (*sc_id).len)};

    let (is_ok, err) = check_buffer_length(nullifier, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_nullifier = unsafe { slice::from_raw_parts((*nullifier).data, (*nullifier).len)};

    let (is_ok, err) = check_buffer_length(pk_hash, UINT_160_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_pk_hash = unsafe { slice::from_raw_parts((*pk_hash).data, (*pk_hash).len)};

    let (is_ok, err) = check_buffer_length(active_cert_data_hash, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_active_cert_data_hash = unsafe { slice::from_raw_parts((*active_cert_data_hash).data, (*active_cert_data_hash).len)};

    let cmt = unsafe { &mut *ptr };
    let ret = cmt.add_csw(
        rs_sc_id, amount, rs_nullifier, rs_pk_hash, rs_active_cert_data_hash);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!(*ret_code);
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_cert(ptr : *mut CommitmentTree,
    sc_id: *const BufferWithSize,
    epoch_number: u32,
    quality: u64,
    cert_data_hash: *const BufferWithSize,
    bt_list: *const BackwardTransfer,
    bt_list_len: usize,
    custom_fields_merkle_root: *const BufferWithSize,
    end_cum_comm_tree_root: *const BufferWithSize,
    ret_code : &mut CctpErrorCode)-> bool
{
    *ret_code = CctpErrorCode::OK;
    if ptr.is_null() {
        *ret_code = CctpErrorCode::NullPtr;
        dbg!(*ret_code);
        return false;
    }

    let (is_ok, err) = check_buffer_length(sc_id, UINT_256_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_sc_id = unsafe { slice::from_raw_parts((*sc_id).data, (*sc_id).len)};

    let (is_ok, err) = check_buffer_length(cert_data_hash, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_cert_data_hash = unsafe { slice::from_raw_parts((*cert_data_hash).data, (*cert_data_hash).len)};

    let (is_ok, err) = check_buffer_length(custom_fields_merkle_root, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_custom_fields_merkle_root = unsafe { slice::from_raw_parts((*custom_fields_merkle_root).data, (*custom_fields_merkle_root).len)};

    let (is_ok, err) = check_buffer_length(end_cum_comm_tree_root, FIELD_SIZE);
    if !is_ok { *ret_code = err; dbg!(err); return false; }
    let rs_end_cum_comm_tree_root = unsafe { slice::from_raw_parts((*end_cum_comm_tree_root).data, (*end_cum_comm_tree_root).len)};


    //Read bt_list
    let mut v : Vec<(i64, [u8; UINT_160_SIZE])> = Vec::new();
    if !bt_list.is_null() {
        let list_sliced = unsafe { slice::from_raw_parts(bt_list, bt_list_len) };
        for x in list_sliced.iter() {
            let p1 : (i64, [u8; UINT_160_SIZE]) = (x.amount, x.pk_dest);
            v.push(p1);
        }
    }
    let rs_bt_list: &[(i64, [u8; UINT_160_SIZE])] = v.as_slice();
    /*
    for x in rs_bt_list.iter() {
        print!("val = {:5} -> [", x.0);
        for y in x.1.iter() {
            print!("{:02x}", y);
        }
        println!("]");
    }
    */

    let cmt = unsafe { &mut *ptr };
    let ret = cmt.add_cert(
        rs_sc_id, epoch_number, quality, rs_cert_data_hash, rs_bt_list,
        rs_custom_fields_merkle_root, rs_end_cum_comm_tree_root);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!(*ret_code);
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_get_commitment(ptr : *mut CommitmentTree) -> *mut FieldElement {
    if ptr.is_null() {
        dbg!("get_commitment: nullptr!");
        return null_mut();
    }
    let cmt = unsafe { &mut *ptr };

    match cmt.get_commitment() {
        Some(commitment) => 
        {
            /*
            let heap_obj = Box::new(commitment);
            println!("Got ct: heap_obj {:p}", heap_obj);
            let raw_obj = Box::into_raw(heap_obj);
            println!("      :  raw_obj {:p}", raw_obj);
            raw_obj
            */
            Box::into_raw(Box::new(commitment))
        }
        None =>  {
            dbg!("get_commitment() failed!");
            null_mut()
        }
    }
}

//***********Bit Vector functions****************
use cctp_primitives::bit_vector::compression::*;
use cctp_primitives::bit_vector::merkle_tree::*;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum CctpErrorCode {
    OK,
    NullPtr,
    InvalidValue,
    InvalidBufferData,
    InvalidBufferLength,
    CompressError,
    UncompressError,
    MerkleRootBuildError,
    GenericError
}

// checks that it is a valid buffer with non-zero data
pub fn check_buffer(buffer: *const BufferWithSize) -> (bool, CctpErrorCode)
{
    if buffer.is_null() {
        //println!("===> ERR CODE {:?}", CctpErrorCode::NullPtr);
        return (false, CctpErrorCode::NullPtr)
    }

    let data_attr = unsafe { (*buffer).data };
    if data_attr.is_null() {
        //println!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferData);
        return (false, CctpErrorCode::InvalidBufferData)
    }

    let len_attr = unsafe { (*buffer).len };
    if len_attr == 0 {
        //println!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferLength);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}

// checks that it is a valid buffer with non-zero data
pub fn check_buffer_length(buffer: *const BufferWithSize, len: usize) -> (bool, CctpErrorCode)
{
    let (is_ok, err) = check_buffer(buffer);
    if !is_ok { return (false, err) }

    let len_attr = unsafe { (*buffer).len };
    if len_attr != len {
        println!("===> ERR: buf_len={}, expected={}", len_attr, len);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}

#[repr(C)]
pub struct BufferWithSize {
    data: *mut u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_bit_vector_size_in_bytes() -> c_uint {
    BV_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_free_bit_vector(buffer: *mut BufferWithSize) {
    unsafe {
        let buffer = Box::from_raw(buffer);
        Vec::from_raw_parts((*buffer).data, (*buffer).len, (*buffer).len);
    };
}

#[no_mangle]
pub extern "C" fn zendoo_compress_bit_vector(buffer: *const BufferWithSize, algorithm: CompressionAlgorithm, ret_code: &mut CctpErrorCode) -> *mut BufferWithSize {

    let (is_ok, err) = check_buffer(buffer);
    if !is_ok {
        *ret_code = err;
        return null_mut();
    }

    let bit_vector = unsafe { slice::from_raw_parts((*buffer).data, (*buffer).len) };

    match compress_bit_vector(bit_vector, algorithm) {
        Ok(mut compressed_bit_vector) => {
            let data = compressed_bit_vector.as_mut_ptr();
            let len = compressed_bit_vector.len();
            assert_eq!(len, compressed_bit_vector.capacity());
            std::mem::forget(compressed_bit_vector);
            let bit_vector_buffer = BufferWithSize {data, len};
            *ret_code = CctpErrorCode::OK;
            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(_) => {
            *ret_code = CctpErrorCode::CompressError;
            dbg!(*ret_code);
            null_mut()
        }
    }

}

#[no_mangle]
pub extern "C" fn zendoo_decompress_bit_vector(buffer: *const BufferWithSize, expected_uncompressed_size: usize, ret_code: &mut CctpErrorCode) -> *mut BufferWithSize {

    let (is_ok, err) = check_buffer(buffer);
    if !is_ok {
        *ret_code = err;
        return null_mut();
    }

    let compressed_slice = unsafe { slice::from_raw_parts((*buffer).data, (*buffer).len ) };

    match decompress_bit_vector(compressed_slice, expected_uncompressed_size) {
        Ok(mut decompressed_bit_vector) => {
            let data = decompressed_bit_vector.as_mut_ptr();
            let len = decompressed_bit_vector.len();
            std::mem::forget(decompressed_bit_vector);
            let bit_vector_buffer = BufferWithSize {data, len};
            *ret_code = CctpErrorCode::OK;
            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(e) => {
            println!("===> {}", e);
            *ret_code = CctpErrorCode::UncompressError;
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_merkle_root_from_compressed_bytes(buffer: *const BufferWithSize, expected_uncompressed_size: usize, ret_code: &mut CctpErrorCode) -> *mut FieldElement
{
    let (is_ok, err) = check_buffer(buffer);
    if !is_ok {
        *ret_code = err;
        return null_mut();
    }

    let compressed_slice = unsafe { slice::from_raw_parts((*buffer).data, (*buffer).len ) };

    match merkle_root_from_compressed_bytes(compressed_slice, expected_uncompressed_size)
    {
        Ok(x) =>  {
            *ret_code = CctpErrorCode::OK;
            Box::into_raw(Box::new(x))
        },
        Err(e) => {
            println!("===> {}", e);
            *ret_code = CctpErrorCode::MerkleRootBuildError;
            null_mut()
        }
    }
}

#[test]
fn compress_decompress() {
    for _ in 0..10 {
        let mut bit_vector: Vec<u8> = (0..100).collect();
        let data = bit_vector.as_mut_ptr();
        let len = bit_vector.len();        

        let buffer = BufferWithSize { data, len };
        let mut ret_code = CctpErrorCode::OK;
        let compressed_buffer = zendoo_compress_bit_vector(&buffer, CompressionAlgorithm::Bzip2, &mut ret_code);
        let uncompressed_buffer = zendoo_decompress_bit_vector(compressed_buffer, len, &mut ret_code);

        let processed_bit_vector = unsafe { slice::from_raw_parts((*uncompressed_buffer).data, (*uncompressed_buffer).len) };
        assert_eq!((0..100).collect::<Vec<u8>>(), processed_bit_vector);

        zendoo_free_bit_vector(compressed_buffer);
        zendoo_free_bit_vector(uncompressed_buffer);
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
    pub pk_dest: [c_uchar; UINT_160_SIZE],
    pub amount: i64,
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_proof_size_in_bytes() -> c_uint {
    SC_PROOF_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_sc_proof(
    _sc_proof: *const SCProof,
    _sc_proof_bytes: *mut [c_uchar; SC_PROOF_SIZE],
){}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof(
    _sc_proof_bytes: *const [c_uchar; SC_PROOF_SIZE],
) -> *mut SCProof {
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_proof_free(_sc_proof: *mut SCProof) {  }

#[no_mangle]
pub extern "C" fn zendoo_get_sc_vk_size_in_bytes() -> c_uint {
    SC_VK_SIZE as u32
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    _vk_path: *const u8,
    _vk_path_len: usize,
) -> *mut SCVk
{
    null_mut()
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    _vk_path: *const u16,
    _vk_path_len: usize,
) -> *mut SCVk
{
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk(
    _sc_vk_bytes: *const [c_uchar; SC_VK_SIZE],
) -> *mut SCVk {
    null_mut()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_vk_free(_sc_vk: *mut SCVk) { }

#[no_mangle]
pub extern "C" fn zendoo_verify_sc_proof(
    _end_epoch_mc_b_hash: *const [c_uchar; 32],
    _prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
    _bt_list: *const BackwardTransfer,
    _bt_list_len: usize,
    _quality: u64,
    _constant: *const FieldElement,
    _proofdata: *const FieldElement,
    _sc_proof: *const SCProof,
    _vk:       *const SCVk,
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


#[no_mangle]
pub extern "C" fn zendoo_poseidon_hash( buf: *mut BufferWithSize) -> *mut FieldElement {

    let rs_buf : &[u8];
    let (is_ok, _err) = check_buffer(buf);
    if is_ok {
        rs_buf = unsafe {
            slice::from_raw_parts((*buf).data, (*buf).len)
        };
    }
    else
    {
        return null_mut();
    }

    match hash_bytes(rs_buf) {
        Err(_) => {
            return null_mut();
        }
        Ok(x) => {
            Box::into_raw(Box::new(x))
        }
    }
}

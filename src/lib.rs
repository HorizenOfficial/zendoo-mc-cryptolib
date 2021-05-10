use libc::{c_uchar, c_uint};
use rand::rngs::OsRng;
use std::ptr::null_mut;
use std::convert::TryInto;

pub mod type_mapping;
use type_mapping::*;

#[macro_use]
pub mod macros;
use macros::*;

pub mod utils;
use utils::*;

#[cfg(test)]
pub mod tests;

//*********** Commitment Tree functions ****************
use cctp_primitives::commitment_tree::CommitmentTree;
use cctp_primitives::utils::data_structures::{ProvingSystem, BitVectorElementsConfig, BackwardTransfer};
use cctp_primitives::utils::commitment_tree::ByteAccumulator;

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_create() -> *mut CommitmentTree {
    Box::into_raw(Box::new(CommitmentTree::create()))
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_delete(ptr : *mut CommitmentTree) {
    free_pointer(ptr)
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_custom_data_size_in_bytes() -> c_uint {
    CUSTOM_DATA_MAX_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_scc(
    ptr :                           *mut CommitmentTree,
    sc_id:                          *const BufferWithSize,
    amount:                         u64,
    pub_key:                        *const BufferWithSize,
    tx_hash:                        *const BufferWithSize,
    out_idx:                        u32,
    withdrawal_epoch_length:        u32,
    cert_proving_system:            ProvingSystem,
    csw_proving_system:             ProvingSystem,
    mc_btr_request_data_length:     u8,
    custom_field_elements_config:   *const BufferWithSize,
    custom_bv_elements_config:      *const BitVectorElementsConfig,
    custom_bv_elements_config_len:  usize,
    btr_fee:                        u64,
    ft_min_amount:                  u64,
    ccd:                            *const BufferWithSize,
    constant:                       *const BufferWithSize,
    cert_vk:                        *const BufferWithSize,
    csw_vk:                         *const BufferWithSize,
    ret_code:                       &mut CctpErrorCode
)-> bool
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id        = try_get_buffer_constant_size!(sc_id,        UINT_256_SIZE, ret_code, false);
    let rs_pub_key      = try_get_buffer_constant_size!(pub_key,      UINT_256_SIZE, ret_code, false);
    let rs_tx_hash      = try_get_buffer_constant_size!(tx_hash,      UINT_256_SIZE, ret_code, false);

    // Mandatory and variable size parameters
    let rs_custom_bv_elements_config = try_get_obj_list!(
        custom_bv_elements_config,
        custom_bv_elements_config_len,
        ret_code,
        false
    );
    let rs_custom_fe_conf = try_get_buffer_variable_size!(custom_field_elements_config, ret_code, false);
    let rs_ccd =            try_get_buffer_variable_size!(ccd,                          ret_code, false);
    let rs_cert_vk =        try_get_buffer_variable_size!(cert_vk,                      ret_code, false);

    // optional parameters
    let rs_constant     = try_get_optional_buffer_constant_size!(constant, FIELD_SIZE, ret_code, false);
    let rs_csw_vk       = try_get_optional_buffer_variable_size!(csw_vk, ret_code, false);
    let csw_proving_system = match csw_proving_system {
        ProvingSystem::Undefined => None,
        _ => Some(csw_proving_system)
    };

    // Add SidechainCreation to the CommitmentTree
    let ret = cmt.add_scc(
        rs_sc_id, amount, rs_pub_key, rs_tx_hash, out_idx, withdrawal_epoch_length,
        cert_proving_system, csw_proving_system, mc_btr_request_data_length,
        rs_custom_fe_conf, rs_custom_bv_elements_config, btr_fee, ft_min_amount,
        rs_ccd, rs_constant, rs_cert_vk, rs_csw_vk
    );

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_scc() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_fwt(
    ptr :       *mut CommitmentTree,
    sc_id:      *const BufferWithSize,
    amount:     u64,
    pub_key:    *const BufferWithSize,
    tx_hash:    *const BufferWithSize,
    out_idx:    u32,
    ret_code:   &mut CctpErrorCode
)-> bool
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id   = try_get_buffer_constant_size!(sc_id,   UINT_256_SIZE, ret_code, false);
    let rs_pub_key = try_get_buffer_constant_size!(pub_key, UINT_256_SIZE, ret_code, false);
    let rs_tx_hash = try_get_buffer_constant_size!(tx_hash, UINT_256_SIZE, ret_code, false);

    // Add ForwardTransfer to the CommitmentTree
    let ret = cmt.add_fwt(rs_sc_id, amount, rs_pub_key, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_fwt() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_bwtr(
    ptr:                    *mut CommitmentTree,
    sc_id:                  *const BufferWithSize,
    sc_fee:                 u64,
    sc_req_data:            *const BufferWithSize,
    sc_req_data_len:        usize,
    mc_dest_addr:           *const BufferWithSize,
    tx_hash:                *const BufferWithSize,
    out_idx:                u32,
    ret_code:               &mut CctpErrorCode
)-> bool
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id        = try_get_buffer_constant_size!(sc_id,        UINT_256_SIZE, ret_code, false);
    let rs_mc_dest_addr = try_get_buffer_constant_size!(mc_dest_addr, UINT_160_SIZE, ret_code, false);
    let rs_tx_hash      = try_get_buffer_constant_size!(tx_hash,      UINT_256_SIZE, ret_code, false);

    // Read sc_req_data_list
    let rs_sc_req_data = try_get_constant_length_buffers_list!(sc_req_data, sc_req_data_len, FIELD_SIZE, ret_code, false);

    let ret = cmt.add_bwtr(
        rs_sc_id, sc_fee, rs_sc_req_data, rs_mc_dest_addr, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_bwtr() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_csw(
    ptr :       *mut CommitmentTree,
    sc_id:      *const BufferWithSize,
    amount:     u64,
    nullifier:  *const BufferWithSize,
    pk_hash:    *const BufferWithSize,
    ret_code:   &mut CctpErrorCode
)-> bool
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, false);

    let rs_sc_id     = try_get_buffer_constant_size!(sc_id,     UINT_256_SIZE, ret_code, false);
    let rs_nullifier = try_get_buffer_constant_size!(nullifier, FIELD_SIZE,    ret_code, false);
    let rs_pk_hash   = try_get_buffer_constant_size!(pk_hash,   UINT_160_SIZE, ret_code, false);

    let ret = cmt.add_csw(rs_sc_id, amount, rs_nullifier, rs_pk_hash);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_csw() failed !");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_cert(
    ptr :                   *mut CommitmentTree,
    sc_id:                  *const BufferWithSize,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const BufferWithSize,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const BufferWithSize,
    btr_fee:                u64,
    ft_min_amount:          u64,
    ret_code :              &mut CctpErrorCode
)-> bool
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, false);

    // Read mandatory, constant size data
    let rs_sc_id                  = try_get_buffer_constant_size!(sc_id,                  UINT_256_SIZE, ret_code, false);
    let rs_end_cum_comm_tree_root = try_get_buffer_constant_size!(end_cum_comm_tree_root, FIELD_SIZE,    ret_code, false);

    // Read bt_list
    let rs_bt_list = try_get_obj_list!(bt_list, bt_list_len, ret_code, false);

    // Read custom fields list (if present)
    let rs_custom_fields = try_get_optional_constant_length_buffers_list!(
        custom_fields, custom_fields_len, FIELD_SIZE, ret_code, false
    );

    // Add certificate to ScCommitmentTree
    let ret = cmt.add_cert(
        rs_sc_id, epoch_number, quality, rs_bt_list, rs_custom_fields,
        rs_end_cum_comm_tree_root, btr_fee, ft_min_amount
    );

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        dbg!("add_cert() failed");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_get_commitment(
    ptr:      *mut CommitmentTree,
    ret_code: &mut CctpErrorCode,
) -> *mut FieldElement
{
    *ret_code = CctpErrorCode::OK;

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!(ptr, ret_code, null_mut());

    match cmt.get_commitment() {
        Some(commitment) => Box::into_raw(Box::new(commitment)),
        None =>  {
            *ret_code = CctpErrorCode::GenericError;
            dbg!("get_commitment() failed!");
            null_mut()
        }
    }
}

//***********Bit Vector functions****************
use cctp_primitives::bit_vector::compression::*;
use cctp_primitives::bit_vector::merkle_tree::*;


#[no_mangle]
pub extern "C" fn zendoo_free_bit_vector(buffer: *mut BufferWithSize) {
    free_buffer_with_size(buffer)
}

#[no_mangle]
pub extern "C" fn zendoo_compress_bit_vector(
    buffer:    *const BufferWithSize,
    algorithm: CompressionAlgorithm,
    ret_code:  &mut CctpErrorCode
) -> *mut BufferWithSize
{
    *ret_code = CctpErrorCode::OK;
    let bit_vector = try_get_buffer_variable_size!(buffer, ret_code, null_mut());

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
            dbg!("compress_bit_vector() failed !");
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_decompress_bit_vector(
    buffer: *const BufferWithSize,
    expected_uncompressed_size: usize,
    ret_code: &mut CctpErrorCode
) -> *mut BufferWithSize
{
    let compressed_slice = try_get_buffer_variable_size!(buffer, ret_code, null_mut());

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
pub extern "C" fn zendoo_merkle_root_from_compressed_bytes(
    buffer: *const BufferWithSize,
    expected_uncompressed_size: usize,
    ret_code: &mut CctpErrorCode
) -> *mut FieldElement
{
    let compressed_slice = try_get_buffer_variable_size!(buffer, ret_code, null_mut());

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


//#[no_mangle]
//pub extern "C" fn zendoo_poseidon_hash_constant_length(
//    buf: *const BufferWithSize,
//    ret_code: &mut CctpErrorCode
//) -> *mut FieldElement {
//
//    let rs_buf = try_get_buffer_variable_size!(buff, ret_code, null_mut());
//    match ByteAccumulator::init()
//        .update(rs_buf).expect("Should be able to append rs_buf")
//        .compute_field_hash_constant_length() {
//        Ok(digest) => Box::into_raw(Box::new(digest)),
//        Err(_) => {
//            *ret_code = CctpErrorCode::GenericError;
//            dbg!("compute_field_hash_constant_length() failed !");
//            null_mut()
//        }
//    }
//}
//

////***********Field functions****************
//#[no_mangle]
//pub extern "C" fn zendoo_get_field_size_in_bytes() -> c_uint {
//    FIELD_SIZE as u32
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_serialize_field(
//    field_element: *const FieldElement,
//    result: *mut [c_uchar; FIELD_SIZE],
//){
//    serialize_from_raw_pointer(
//        field_element,
//        &mut (unsafe { &mut *result })[..],
//    )
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_field(
//    field_bytes: *const [c_uchar; FIELD_SIZE],
//) -> *mut FieldElement {
//    deserialize_to_raw_pointer(&(unsafe { &*field_bytes })[..])
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_field_free(field: *mut FieldElement) { free_pointer(field) }
//
////********************Sidechain SNARK functions********************
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_sc_proof_size_in_bytes() -> c_uint {
//    SC_PROOF_SIZE as u32
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_serialize_sc_proof(
//    _sc_proof: *const SCProof,
//    _sc_proof_bytes: *mut [c_uchar; SC_PROOF_SIZE],
//){}
//
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_proof(
//    sc_proof_bytes: *const [c_uchar; GROTH_PROOF_SIZE],
//    enforce_membership: bool,
//) -> *mut SCProof {
//    if enforce_membership {
//        deserialize_to_raw_pointer_checked(&(unsafe { &*sc_proof_bytes })[..])
//    } else {
//        deserialize_to_raw_pointer(&(unsafe { &*sc_proof_bytes })[..])
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_sc_proof_free(_sc_proof: *mut SCProof) {  }
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_sc_vk_size_in_bytes() -> c_uint {
//    SC_VK_SIZE as u32
//}
//
//#[cfg(not(target_os = "windows"))]
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
//    vk_path: *const u8,
//    vk_path_len: usize,
//    enforce_membership: bool,
//) -> *mut SCVk
//{
//    // Read file path
//    let vk_path = Path::new(OsStr::from_bytes(unsafe {
//        slice::from_raw_parts(vk_path, vk_path_len)
//    }));
//
//    let result = if enforce_membership {
//        deserialize_from_file_checked(vk_path)
//    } else {
//        deserialize_from_file(vk_path)
//    };
//
//    match result{
//        Some(vk) => Box::into_raw(Box::new(vk)),
//        None => null_mut(),
//    }
//}
//
//#[cfg(target_os = "windows")]
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
//    vk_path: *const u16,
//    vk_path_len: usize,
//    enforce_membership: bool,
//) -> *mut SCVk
//{
//    // Read file path
//    let path_str = OsString::from_wide(unsafe {
//        slice::from_raw_parts(vk_path, vk_path_len)
//    });
//    let vk_path = Path::new(&path_str);
//
//    let result = if enforce_membership {
//        deserialize_from_file_checked(vk_path)
//    } else {
//        deserialize_from_file(vk_path)
//    };
//
//    match result{
//        Some(vk) => Box::into_raw(Box::new(vk)),
//        None => null_mut(),
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_vk(
//    sc_vk_bytes: *const [c_uchar; VK_SIZE],
//    enforce_membership: bool,
//) -> *mut SCVk {
//    if enforce_membership {
//        deserialize_to_raw_pointer_checked(&(unsafe { &*sc_vk_bytes })[..])
//    } else {
//        deserialize_to_raw_pointer(&(unsafe { &*sc_vk_bytes })[..])
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_sc_vk_free(_sc_vk: *mut SCVk) { }
//
//#[no_mangle]
//pub extern "C" fn zendoo_verify_sc_proof(
//    _end_epoch_mc_b_hash: *const [c_uchar; 32],
//    _prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
//    _bt_list: *const BackwardTransfer,
//    _bt_list_len: usize,
//    _quality: u64,
//    _constant: *const FieldElement,
//    _proofdata: *const FieldElement,
//    _sc_proof: *const SCProof,
//    _vk:       *const SCVk,
//) -> bool { true }
//
////********************Poseidon hash functions********************
//
//#[no_mangle]
//pub extern "C" fn zendoo_init_poseidon_hash(
//    personalization: *const *const FieldElement,
//    personalization_len: usize,
//) -> *mut FieldHash {
//
//    let uh = if !personalization.is_null(){
//        init_poseidon_hash(Some(read_double_raw_pointer(personalization, personalization_len).as_slice()))
//    } else {
//        init_poseidon_hash(None)
//    };
//
//    Box::into_raw(Box::new(uh))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_update_poseidon_hash(
//    fe: *const FieldElement,
//    digest: *mut FieldHash
//){
//
//    let input = read_raw_pointer(fe);
//
//    let digest = read_mut_raw_pointer(digest);
//
//    update_poseidon_hash(digest, input);
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_finalize_poseidon_hash(
//    digest: *const FieldHash
//) -> *mut FieldElement {
//
//    let digest = read_raw_pointer(digest);
//
//    let output = finalize_poseidon_hash(digest);
//
//    Box::into_raw(Box::new(output))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_reset_poseidon_hash(
//    digest: *mut FieldHash,
//    personalization: *const *const FieldElement,
//    personalization_len: usize,
//) {
//
//    let digest = read_mut_raw_pointer(digest);
//
//    if !personalization.is_null(){
//        reset_poseidon_hash(digest, Some(read_double_raw_pointer(personalization, personalization_len).as_slice()));
//    } else {
//        reset_poseidon_hash(digest, None);
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_free_poseidon_hash(
//    digest: *mut FieldHash
//) { free_pointer(digest) }
//
//#[deprecated]
//#[no_mangle]
//pub extern "C" fn zendoo_compute_poseidon_hash(
//    input: *const *const FieldElement,
//    input_len: usize,
//) -> *mut FieldElement {
//
//    // Read message
//    let message = read_double_raw_pointer(input, input_len);
//
//    // Compute hash
//    let mut digest = init_poseidon_hash(None);
//    for fe in message.into_iter(){
//        digest.update(fe);
//    }
//
//    //Return pointer to hash
//    Box::into_raw(Box::new(digest.finalize()))
//}
//
//// ********************Merkle Tree functions********************
//#[no_mangle]
//pub extern "C" fn zendoo_new_ginger_mht(
//    height: usize,
//    processing_step: usize,
//) -> *mut GingerMHT {
//
//    let gmt = new_ginger_mht(height, processing_step);
//    Box::into_raw(Box::new(gmt))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_append_leaf_to_ginger_mht(
//    leaf: *const FieldElement,
//    tree: *mut GingerMHT,
//)
//{
//    let leaf = read_raw_pointer(leaf);
//
//    let tree = read_mut_raw_pointer(tree);
//
//    append_leaf_to_ginger_mht(tree, leaf);
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_finalize_ginger_mht(
//    tree: *const GingerMHT
//) -> *mut GingerMHT
//{
//    let tree = read_raw_pointer(tree);
//
//    let tree_copy = finalize_ginger_mht(tree);
//
//    Box::into_raw(Box::new(tree_copy))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_finalize_ginger_mht_in_place(
//    tree: *mut GingerMHT
//)
//{
//    let tree = read_mut_raw_pointer(tree);
//
//    finalize_ginger_mht_in_place(tree);
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_ginger_mht_root(
//    tree: *const GingerMHT
//) -> *mut FieldElement
//{
//    let tree = read_raw_pointer(tree);
//
//    match get_ginger_mht_root(tree) {
//        Some(root) => Box::into_raw(Box::new(root)),
//        None => null_mut()
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_ginger_merkle_path(
//    tree: *const GingerMHT,
//    leaf_index: usize
//) -> *mut GingerMHTPath
//{
//    let tree = read_raw_pointer(tree);
//
//    match get_ginger_mht_path(tree, leaf_index) {
//        Some(path) => Box::into_raw(Box::new(path)),
//        None => null_mut()
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_ginger_empty_node(
//    height: usize
//) -> *mut FieldElement
//{
//    use primitives::merkle_tree::field_based_mht::parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS;
//
//    let max_height = MHT_PARAMETERS.nodes.len() - 1;
//    assert!(height <= max_height, format!("Empty node not pre-computed for height {}", height));
//
//    let empty_node = MHT_PARAMETERS.nodes[max_height - height].clone();
//
//    Box::into_raw(Box::new(empty_node))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_verify_ginger_merkle_path(
//    path: *const GingerMHTPath,
//    height: usize,
//    leaf: *const FieldElement,
//    root: *const FieldElement,
//) -> bool
//{
//    let path = read_raw_pointer(path);
//
//    let root = read_raw_pointer(root);
//
//    let leaf = read_raw_pointer(leaf);
//
//    match verify_ginger_merkle_path(path, height, leaf, root) {
//        Ok(result) => result,
//        Err(e) => {
//            set_last_error(e, CRYPTO_ERROR);
//            false
//        }
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_free_ginger_merkle_path(
//    path: *mut GingerMHTPath
//) { free_pointer(path) }
//
//#[no_mangle]
//pub extern "C" fn zendoo_reset_ginger_mht(
//    tree: *mut GingerMHT
//)
//{
//    let tree = read_mut_raw_pointer(tree);
//
//    reset_ginger_mht(tree);
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_free_ginger_mht(
//    tree: *mut GingerMHT
//) { free_pointer(tree) }
//
////***************Test functions*******************
//
//#[cfg(feature = "mc-test-circuit")]
//pub mod mc_test_circuit;
//#[cfg(feature = "mc-test-circuit")]
//pub use self::mc_test_circuit::*;
//use primitives::FieldBasedHash;
//use cctp_primitives::utils::serialization::{deserialize_from_buffer, deserialize_from_buffer_checked, serialize_to_buffer, read_from_file};
//use cctp_primitives::utils::data_structures::{ProvingSystem, BitVectorElementsConfig, BackwardTransfer};
//
//#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
//#[no_mangle]
//pub extern "C" fn zendoo_generate_mc_test_params(
//    params_dir: *const u16,
//    params_dir_len: usize,
//) -> bool {
//
//    // Read params_dir
//    let params_str = OsString::from_wide(unsafe {
//        slice::from_raw_parts(params_dir, params_dir_len)
//    });
//    let params_dir = Path::new(&params_str);
//
//    match ginger_calls::generate_test_mc_parameters(params_dir) {
//        Ok(()) => true,
//        Err(e) => {
//            set_last_error(e, CRYPTO_ERROR);
//            false
//        }
//    }
//}
//
//#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
//#[no_mangle]
//pub extern "C" fn zendoo_generate_mc_test_params(
//    params_dir: *const u8,
//    params_dir_len: usize,
//) -> bool {
//
//    // Read params_dir
//    let params_dir = Path::new(OsStr::from_bytes(unsafe {
//        slice::from_raw_parts(params_dir, params_dir_len)
//    }));
//
//    match ginger_calls::generate_test_mc_parameters(params_dir) {
//        Ok(()) => true,
//        Err(e) => {
//            set_last_error(e, CRYPTO_ERROR);
//            false
//        }
//    }
//}
//
//#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
//    proof_path: *const u8,
//    proof_path_len: usize,
//) -> *mut SCProof
//{
//    // Read file path
//    let proof_path = Path::new(OsStr::from_bytes(unsafe {
//        slice::from_raw_parts(proof_path, proof_path_len)
//    }));
//
//    match deserialize_from_file(proof_path){
//        Some(proof) => Box::into_raw(Box::new(proof)),
//        None => null_mut(),
//    }
//}
//
//#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
//#[no_mangle]
//pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
//    proof_path: *const u16,
//    proof_path_len: usize,
//) -> *mut SCProof
//{
//    // Read file path
//    let path_str = OsString::from_wide(unsafe {
//        slice::from_raw_parts(proof_path, proof_path_len)
//    });
//    let proof_path = Path::new(&path_str);
//
//    match deserialize_from_file(proof_path){
//        Some(proof) => Box::into_raw(Box::new(proof)),
//        None => null_mut(),
//    }
//}
//
//#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
//#[no_mangle]
//pub extern "C" fn zendoo_create_mc_test_proof(
//    end_epoch_mc_b_hash: *const [c_uchar; 32],
//    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
//    bt_list: *const BackwardTransfer,
//    bt_list_len: usize,
//    quality: u64,
//    constant: *const FieldElement,
//    pk_path: *const u8,
//    pk_path_len: usize,
//    proof_path: *const u8,
//    proof_path_len: usize,
//) -> bool
//{
//    //Read end_epoch_mc_b_hash
//    let end_epoch_mc_b_hash = read_raw_pointer(end_epoch_mc_b_hash);
//
//    //Read prev_end_epoch_mc_b_hash
//    let prev_end_epoch_mc_b_hash = read_raw_pointer(prev_end_epoch_mc_b_hash);
//
//    //Read bt_list
//    let bt_list = if !bt_list.is_null() {
//        unsafe { slice::from_raw_parts(bt_list, bt_list_len) }
//    } else {
//        &[]
//    };
//
//    //Read constant
//    let constant = read_raw_pointer(constant);
//
//    //Read pk path
//    let pk_path = Path::new(OsStr::from_bytes(unsafe {
//        slice::from_raw_parts(pk_path, pk_path_len)
//    }));
//
//    //Read path to which save the proof
//    let proof_path = Path::new(OsStr::from_bytes(unsafe {
//        slice::from_raw_parts(proof_path, proof_path_len)
//    }));
//
//    //Generate proof and vk
//    match ginger_calls::create_test_mc_proof(
//        end_epoch_mc_b_hash,
//        prev_end_epoch_mc_b_hash,
//        bt_list,
//        quality,
//        constant,
//        pk_path,
//        proof_path,
//    ) {
//        Ok(()) => true,
//        Err(e) => {
//            set_last_error(e, CRYPTO_ERROR);
//            false
//        }
//    }
//}
//
//#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
//#[no_mangle]
//pub extern "C" fn zendoo_create_mc_test_proof(
//    end_epoch_mc_b_hash: *const [c_uchar; 32],
//    prev_end_epoch_mc_b_hash: *const [c_uchar; 32],
//    bt_list: *const BackwardTransfer,
//    bt_list_len: usize,
//    quality: u64,
//    constant: *const FieldElement,
//    pk_path: *const u16,
//    pk_path_len: usize,
//    proof_path: *const u16,
//    proof_path_len: usize,
//) -> bool
//{
//    //Read end_epoch_mc_b_hash
//    let end_epoch_mc_b_hash = read_raw_pointer(end_epoch_mc_b_hash);
//
//    //Read prev_end_epoch_mc_b_hash
//    let prev_end_epoch_mc_b_hash = read_raw_pointer(prev_end_epoch_mc_b_hash);
//
//    //Read bt_list
//    let bt_list = if !bt_list.is_null() {
//        unsafe { slice::from_raw_parts(bt_list, bt_list_len) }
//    } else {
//        &[]
//    };
//
//    //Read constant
//    let constant = read_raw_pointer(constant);
//
//    //Read pk path
//    let path_str = OsString::from_wide(unsafe {
//        slice::from_raw_parts(pk_path, pk_path_len)
//    });
//    let pk_path = Path::new(&path_str);
//
//    //Read path to which save the proof
//    let path_str = OsString::from_wide(unsafe {
//        slice::from_raw_parts(proof_path, proof_path_len)
//    });
//    let proof_path = Path::new(&path_str);
//
//    //Generate proof and vk
//    match ginger_calls::create_test_mc_proof(
//        end_epoch_mc_b_hash,
//        prev_end_epoch_mc_b_hash,
//        bt_list,
//        quality,
//        constant,
//        pk_path,
//        proof_path,
//    ) {
//        Ok(()) => true,
//        Err(e) => {
//            set_last_error(e, CRYPTO_ERROR);
//            false
//        }
//    }
//}
//
//fn check_equal<T: PartialEq>(val_1: *const T, val_2: *const T) -> bool {
//    let val_1 = unsafe { &*val_1 };
//    let val_2 = unsafe { &*val_2 };
//    val_1 == val_2
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_random_field() -> *mut FieldElement {
//    let mut rng = OsRng;
//    let random_f = FieldElement::rand(&mut rng);
//    Box::into_raw(Box::new(random_f))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_get_field_from_long(value: u64) -> *mut FieldElement {
//    let fe = FieldElement::from(value);
//    Box::into_raw(Box::new(fe))
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_field_assert_eq(
//    field_1: *const FieldElement,
//    field_2: *const FieldElement,
//) -> bool {
//    check_equal(field_1, field_2)
//}
//
//#[no_mangle]
//pub extern "C" fn zendoo_sc_vk_assert_eq(
//    sc_vk_1: *const SCVk,
//    sc_vk_2: *const SCVk,
//) -> bool {
//    check_equal(sc_vk_1, sc_vk_2)
//}
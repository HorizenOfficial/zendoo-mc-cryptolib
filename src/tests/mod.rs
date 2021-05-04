use algebra::{
    bytes::{FromBytes, ToBytes},
    curves::mnt4753::MNT4 as PairingCurve,
};

use proof_systems::groth16::Proof;

use crate::{zendoo_deserialize_field, zendoo_deserialize_sc_proof, zendoo_verify_sc_proof, zendoo_serialize_field, zendoo_sc_proof_free, zendoo_field_free, BackwardTransfer, zendoo_field_assert_eq, zendoo_deserialize_sc_vk_from_file, zendoo_sc_vk_free, zendoo_serialize_sc_proof, zendoo_init_poseidon_hash, zendoo_update_poseidon_hash, zendoo_finalize_poseidon_hash, zendoo_free_poseidon_hash, zendoo_new_ginger_mht, zendoo_append_leaf_to_ginger_mht, zendoo_get_field_from_long, zendoo_finalize_ginger_mht, zendoo_get_ginger_mht_root, zendoo_finalize_ginger_mht_in_place, zendoo_free_ginger_mht, zendoo_get_ginger_merkle_path, zendoo_verify_ginger_merkle_path, zendoo_free_ginger_merkle_path};

use std::{fmt::Debug, fs::File, ptr::null};

fn assert_slice_equals<T: Eq + Debug>(s1: &[T], s2: &[T]) {
    for (i1, i2) in s1.iter().zip(s2.iter()) {
        assert_eq!(i1, i2);
    }
}

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(not(target_os = "windows"))]
fn path_as_ptr(path: &str) -> *const u8 { path.as_ptr() }

#[cfg(target_os = "windows")]
fn path_as_ptr(path: &str) -> *const u16 {
    let tmp: Vec<u16> = OsString::from(path).encode_wide().collect();
    tmp.as_ptr()
}

#[test]
fn verify_zkproof_test() {

    let mut file = File::open("./test_files/sample_proof").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp, true);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        157, 219, 85, 159, 75, 56, 146, 21, 107, 239, 76, 31, 208, 213, 230, 24, 44, 74, 250, 66,
        71, 23, 106, 4, 138, 157, 28, 43, 158, 39, 152, 91
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        74, 229, 219, 59, 25, 231, 227, 68, 3, 118, 194, 58, 99, 219, 112, 39, 73, 202, 238, 140,
        114, 144, 253, 32, 237, 117, 117, 60, 200, 70, 187, 171
    ];

    let constant_bytes: [u8; 96] = [
        234, 144, 148, 15, 127, 44, 243, 131, 152, 238, 209, 246, 126, 175, 154, 42, 208, 215, 180,
        233, 20, 153, 7, 10, 180, 78, 89, 9, 9, 160, 1, 42, 91, 202, 221, 104, 241, 231, 8, 59, 174,
        159, 27, 108, 74, 80, 118, 192, 127, 238, 216, 167, 72, 15, 61, 97, 121, 13, 48, 143, 255,
        165, 228, 6, 121, 210, 112, 228, 161, 214, 233, 137, 108, 184, 80, 27, 213, 72, 110, 7, 200,
        194, 23, 95, 102, 236, 181, 230, 139, 215, 104, 22, 214, 70, 0, 0
    ];

    let constant = zendoo_deserialize_field(&constant_bytes);
    drop(constant_bytes);

    let quality = 2;

    //Create dummy bt
    let bt_num = 10;
    let mut bt_list = vec![];
    for _ in 0..bt_num {
        bt_list.push(BackwardTransfer {
            pk_dest: [0u8; 20],
            amount: 0,
        });
    }

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/sample_vk"),
        22,
        true
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality - 1,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Free memory
    zendoo_sc_proof_free(zkp_ptr);
    zendoo_sc_vk_free(vk);
    zendoo_field_free(constant);
}

#[test]
fn verify_zkproof_no_bwt_test() {

    let mut file = File::open("./test_files/sample_proof_no_bwt").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp, true);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        8, 57, 79, 205, 58, 30, 190, 170, 144, 137, 231, 236, 172, 54, 173, 50, 69, 208, 163, 134,
        201, 131, 129, 223, 143, 76, 119, 48, 95, 6, 141, 17
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        172, 64, 135, 162, 30, 208, 207, 7, 107, 205, 4, 141, 230, 6, 119, 131, 112, 98, 170, 234,
        70, 66, 95, 11, 159, 178, 50, 37, 95, 187, 147, 1
    ];

    let constant_bytes: [u8; 96] = [
        53, 15, 18, 36, 121, 179, 90, 14, 215, 218, 231, 181, 9, 186, 122, 78, 227, 142, 190, 43,
        134, 218, 178, 160, 251, 246, 207, 130, 247, 53, 246, 68, 251, 126, 22, 250, 0, 135, 243,
        13, 97, 76, 166, 142, 143, 19, 69, 66, 225, 142, 210, 176, 253, 197, 145, 68, 142, 4, 96,
        91, 23, 39, 56, 43, 96, 115, 57, 59, 34, 62, 156, 221, 27, 174, 134, 170, 26, 86, 112, 176,
        126, 207, 29, 213, 99, 3, 183, 43, 191, 43, 211, 110, 177, 152, 0, 0
    ];

    let constant = zendoo_deserialize_field(&constant_bytes);
    drop(constant_bytes);

    let quality = 2;

    //Create empty bt list
    let bt_list = vec![];

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/sample_vk_no_bwt"),
        29,
        true
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        0,
        quality,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        0,
        quality - 1,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Free memory
    zendoo_sc_proof_free(zkp_ptr);
    zendoo_sc_vk_free(vk);
    zendoo_field_free(constant);
}

#[cfg(feature = "mc-test-circuit")]
#[test]
fn create_verify_mc_test_proof(){

    use crate::{
        zendoo_generate_mc_test_params, zendoo_get_random_field, zendoo_create_mc_test_proof,
        zendoo_deserialize_sc_proof_from_file,
    };
    use rand::rngs::OsRng;
    use rand::Rng;

    let mut rng = OsRng::default();

    //Generate params
    assert!(zendoo_generate_mc_test_params(path_as_ptr("./test_files"), 12));

    //Generate random inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        28, 207, 62, 204, 135, 33, 168, 143, 231, 177, 64, 181, 184, 237, 93, 185, 196, 115, 241,
        65, 176, 205, 254, 83, 216, 229, 119, 73, 184, 217, 26, 109
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        64, 236, 160, 62, 217, 6, 240, 243, 184, 32, 158, 223, 218, 177, 165, 121, 12, 124, 153,
        137, 218, 208, 152, 125, 187, 145, 172, 244, 223, 220, 234, 195
    ];

    let quality: u64 = rng.gen();

    let bt_num: usize = rng.gen_range(0, 11);
    let mut bt_list = vec![];
    for _ in 0..bt_num {
        bt_list.push(BackwardTransfer {
            pk_dest: [0u8; 20],
            amount: 0,
        });
    }

    let constant = zendoo_get_random_field();

    let pk_path = path_as_ptr("./test_files/test_mc_pk");
    let proof_path = path_as_ptr("./test_files/test_mc_proof");

    //Create proof
    assert!(zendoo_create_mc_test_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        pk_path,
        23,
        proof_path,
        26
    ));

    //Verify proof

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/test_mc_vk"),
        23,
        true,
    );

    //Get proof
    let proof = zendoo_deserialize_sc_proof_from_file(
        path_as_ptr("./test_files/test_mc_proof"),
        26
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        null(),
        proof,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality - 1,
        constant,
        null(),
        proof,
        vk
    ));
}

#[test]
fn merkle_tree_test() {
    let height = 5;
    let expected_root_bytes: [u8; 96] = [
        192, 138, 102, 85, 151, 8, 139, 184, 209, 249, 171, 182, 227, 80, 52, 215, 32, 37, 145, 166,
        74, 136, 40, 200, 213, 72, 124, 101, 91, 235, 114, 0, 147, 61, 180, 29, 183, 111, 247, 2,
        169, 12, 179, 173, 87, 88, 187, 229, 26, 139, 80, 228, 125, 246, 145, 141, 43, 19, 148, 94,
        190, 140, 20, 123, 208, 132, 48, 243, 14, 2, 48, 106, 100, 13, 41, 254, 129, 225, 168, 23,
        72, 215, 207, 255, 98, 156, 102, 215, 201, 158, 10, 123, 107, 238, 0, 0
    ];
    let expected_root = zendoo_deserialize_field(&expected_root_bytes);

    // Generate leaves
    let leaves_len = 32;
    let mut leaves = vec![];
    for i in 0..leaves_len {
        leaves.push(zendoo_get_field_from_long(i as u64));
    }

    // Create tree
    let tree = zendoo_new_ginger_mht(height, leaves_len);

    // Add leaves to tree
    for &leaf in leaves.iter(){
        zendoo_append_leaf_to_ginger_mht(leaf, tree);
    }

    // Finalize tree and assert root equality
    zendoo_finalize_ginger_mht_in_place(tree);
    let root = zendoo_get_ginger_mht_root(tree);
    assert!(zendoo_field_assert_eq(root, expected_root));

    // It is the same by calling zendoo_finalize_ginger_mht
    let tree_copy = zendoo_finalize_ginger_mht(tree);
    let root_copy = zendoo_get_ginger_mht_root(tree_copy);
    assert!(zendoo_field_assert_eq(root, root_copy));

    //Test merkle paths
    for (i, leaf) in leaves.clone().into_iter().skip(500).enumerate() {
        let path = zendoo_get_ginger_merkle_path(tree, i);
        assert!(zendoo_verify_ginger_merkle_path(path, height, leaf, root));
        zendoo_free_ginger_merkle_path(path);
    }

    // Free memory
    zendoo_field_free(expected_root);
    for leaf in leaves.into_iter(){
        zendoo_field_free(leaf);
    }
    zendoo_free_ginger_mht(tree);
    zendoo_field_free(root);

    zendoo_free_ginger_mht(tree_copy);
    zendoo_field_free(root_copy);
}

#[test]
fn poseidon_hash_test() {
    let lhs: [u8; 96] = [
        138, 206, 199, 243, 195, 254, 25, 94, 236, 155, 232, 182, 89, 123, 162, 207, 102, 52, 178,
        128, 55, 248, 234, 95, 33, 196, 170, 12, 118, 16, 124, 96, 47, 203, 160, 167, 144, 153,
        161, 86, 213, 126, 95, 76, 27, 98, 34, 111, 144, 36, 205, 124, 200, 168, 29, 196, 67, 210,
        100, 154, 38, 79, 178, 191, 246, 115, 84, 232, 87, 12, 34, 72, 88, 23, 236, 142, 237, 45,
        11, 148, 91, 112, 156, 47, 68, 229, 216, 56, 238, 98, 41, 243, 225, 192, 0, 0,
    ];

    let rhs: [u8; 96] = [
        199, 130, 235, 52, 44, 219, 5, 195, 71, 154, 54, 121, 3, 11, 111, 160, 86, 212, 189, 66,
        235, 236, 240, 242, 126, 248, 116, 0, 48, 95, 133, 85, 73, 150, 110, 169, 16, 88, 136, 34,
        106, 7, 38, 176, 46, 89, 163, 49, 162, 222, 182, 42, 200, 240, 149, 226, 173, 203, 148,
        194, 207, 59, 44, 185, 67, 134, 107, 221, 188, 208, 122, 212, 200, 42, 227, 3, 23, 59, 31,
        37, 91, 64, 69, 196, 74, 195, 24, 5, 165, 25, 101, 215, 45, 92, 1, 0,
    ];

    let hash: [u8; 96] = [
        53, 2, 235, 12, 255, 18, 125, 167, 223, 32, 245, 103, 38, 74, 43, 73, 254, 189, 174, 137,
        20, 90, 195, 107, 202, 24, 151, 136, 85, 23, 9, 93, 207, 33, 229, 200, 178, 225, 221, 127,
        18, 250, 108, 56, 86, 94, 171, 1, 76, 21, 237, 254, 26, 235, 196, 14, 18, 129, 101, 158,
        136, 103, 147, 147, 239, 140, 163, 94, 245, 147, 110, 28, 93, 231, 66, 7, 111, 11, 202, 99,
        146, 211, 117, 143, 224, 99, 183, 108, 157, 200, 119, 169, 180, 148, 0, 0,
    ];

    let lhs_field = zendoo_deserialize_field(&lhs);
    let rhs_field = zendoo_deserialize_field(&rhs);
    let expected_hash = zendoo_deserialize_field(&hash);

    //Test field serialization/deserialization
    let mut lhs_serialized = [0u8; 96];
    zendoo_serialize_field(lhs_field, &mut lhs_serialized);
    assert_slice_equals(&lhs, &lhs_serialized);
    drop(lhs_serialized);

    let uh = zendoo_init_poseidon_hash(null(), 0);

    // Call to finalize keeps the state untouched
    zendoo_update_poseidon_hash(lhs_field, uh);
    let temp_hash = zendoo_finalize_poseidon_hash(uh);
    zendoo_update_poseidon_hash(rhs_field, uh);

    let actual_hash = zendoo_finalize_poseidon_hash(uh);
    assert!(zendoo_field_assert_eq(actual_hash, expected_hash));
    zendoo_field_free(actual_hash);

    // finalize() is idempotent
    let actual_hash_2 = zendoo_finalize_poseidon_hash(uh);
    assert!(zendoo_field_assert_eq(actual_hash_2, expected_hash));
    zendoo_field_free(actual_hash_2);

    zendoo_free_poseidon_hash(uh);
    zendoo_field_free(expected_hash);
    zendoo_field_free(temp_hash);

    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);
}

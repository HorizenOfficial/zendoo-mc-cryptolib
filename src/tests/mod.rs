use algebra::{
    bytes::{FromBytes, ToBytes},
    curves::mnt4753::MNT4 as PairingCurve,
};

use proof_systems::groth16::Proof;

use crate::{zendoo_deserialize_field, zendoo_deserialize_sc_proof, zendoo_verify_sc_proof, zendoo_serialize_field, zendoo_sc_proof_free, zendoo_field_free, BackwardTransfer, zendoo_field_assert_eq, zendoo_deserialize_sc_vk_from_file, zendoo_sc_vk_free, zendoo_serialize_sc_proof, zendoo_init_poseidon_hash, zendoo_update_poseidon_hash, zendoo_finalize_poseidon_hash, zendoo_free_poseidon_hash, zendoo_new_ginger_ramt, zendoo_append_leaf_to_ginger_ramt, zendoo_get_field_from_long, zendoo_finalize_ginger_ramt, zendoo_get_ginger_ramt_root, zendoo_finalize_ginger_ramt_in_place, zendoo_free_ginger_ramt};

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

//#[test]
fn verify_zkproof_test() {

    let mut file = File::open("./test_files/sample_proof").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        78, 85, 161, 67, 167, 192, 185, 56, 133, 49, 134, 253, 133, 165, 182, 80, 152, 93, 203, 77,
        165, 13, 67, 0, 64, 200, 185, 46, 93, 135, 238, 70
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        68, 214, 34, 70, 20, 109, 48, 39, 210, 156, 109, 60, 139, 15, 102, 79, 79, 2, 87, 190, 118,
        38, 54, 18, 170, 67, 212, 205, 183, 115, 182, 198
    ];

    let constant_bytes: [u8; 96] = [
        170, 190, 140, 27, 234, 135, 240, 226, 158, 16, 29, 161, 178, 36, 69, 34, 29, 75, 195, 247,
        29, 93, 92, 48, 214, 102, 70, 134, 68, 165, 170, 201, 119, 162, 19, 254, 229, 115, 80, 248,
        106, 182, 164, 40, 21, 154, 15, 177, 158, 16, 172, 169, 189, 253, 206, 182, 72, 183, 128,
        160, 182, 39, 98, 76, 95, 198, 62, 39, 87, 213, 251, 12, 154, 180, 125, 231, 222, 73, 129,
        120, 144, 197, 116, 248, 95, 206, 147, 108, 252, 125, 79, 118, 57, 26, 0, 0
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

//#[test]
fn verify_zkproof_no_bwt_test() {

    let mut file = File::open("./test_files/sample_proof_no_bwt").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        28, 207, 62, 204, 135, 33, 168, 143, 231, 177, 64, 181, 184, 237, 93, 185, 196, 115, 241,
        65, 176, 205, 254, 83, 216, 229, 119, 73, 184, 217, 26, 109
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        64, 236, 160, 62, 217, 6, 240, 243, 184, 32, 158, 223, 218, 177, 165, 121, 12, 124, 153,
        137, 218, 208, 152, 125, 187, 145, 172, 244, 223, 220, 234, 195
    ];

    let constant_bytes: [u8; 96] = [
        249, 199, 228, 179, 227, 163, 140, 243, 174, 240, 187, 245, 152, 245, 74, 136, 36, 142, 231,
        196, 162, 148, 139, 157, 198, 117, 186, 83, 72, 103, 121, 253, 5, 64, 230, 173, 84, 236, 12,
        3, 199, 26, 171, 58, 141, 171, 85, 151, 209, 228, 76, 0, 21, 241, 65, 100, 50, 194, 8, 163,
        121, 129, 242, 124, 166, 105, 158, 76, 146, 169, 188, 243, 188, 82, 176, 244, 255, 122, 125,
        90, 154, 45, 12, 223, 62, 156, 140, 20, 35, 83, 55, 111, 47, 10, 1, 0
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
    let height = 10;
    let expected_root_bytes: [u8; 96] = [
        231, 64, 42, 251, 206, 22, 102, 105, 222, 145, 252, 133, 62, 169, 60, 150, 50, 133, 187, 38,
        47, 246, 192, 170, 161, 204, 152, 177, 20, 209, 217, 101, 34, 159, 246, 176, 23, 223, 62,
        191, 103, 165, 210, 114, 179, 110, 140, 252, 250, 167, 106, 31, 7, 178, 109, 108, 20, 239,
        162, 121, 99, 207, 137, 224, 124, 212, 65, 229, 5, 112, 116, 75, 145, 11, 77, 252, 134, 37,
        127, 54, 244, 236, 68, 129, 16, 191, 196, 6, 17, 185, 138, 98, 183, 153, 1, 0
    ];
    let expected_root = zendoo_deserialize_field(&expected_root_bytes);

    // Generate leaves
    let leaves_len = 512;
    let mut leaves = vec![];
    for i in 0..leaves_len {
        leaves.push(zendoo_get_field_from_long(i as u64));
    }

    // Create tree
    let tree = zendoo_new_ginger_ramt(height);

    // Add leaves to tree
    for &leaf in leaves.iter(){
        zendoo_append_leaf_to_ginger_ramt(leaf, tree);
    }

    // Finalize tree and assert root equality
    zendoo_finalize_ginger_ramt_in_place(tree);
    let root = zendoo_get_ginger_ramt_root(tree);
    assert!(zendoo_field_assert_eq(root, expected_root));

    // It is the same by calling zendoo_finalize_ginger_ramt
    let tree_copy = zendoo_finalize_ginger_ramt(tree);
    let root_copy = zendoo_get_ginger_ramt_root(tree_copy);
    assert!(zendoo_field_assert_eq(root, root_copy));

    // Free memory

    zendoo_field_free(expected_root);
    for leaf in leaves.into_iter(){
        zendoo_field_free(leaf);
    }
    zendoo_free_ginger_ramt(tree);
    zendoo_field_free(root);

    zendoo_free_ginger_ramt(tree_copy);
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

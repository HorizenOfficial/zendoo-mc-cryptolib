use algebra::{
    bytes::{FromBytes, ToBytes},
    curves::mnt4753::MNT4 as PairingCurve,
    fields::mnt4753::Fr,
    to_bytes, UniformRand,
};

use proof_systems::groth16::Proof;
use rand::rngs::OsRng;

use crate::{zendoo_deserialize_field, zendoo_deserialize_sc_proof, zendoo_verify_sc_proof, zendoo_serialize_field, ginger_mt_new, ginger_mt_get_root, ginger_mt_get_merkle_path, ginger_mt_verify_merkle_path, GingerMerkleTree, ginger_mt_free, ginger_mt_path_free, zendoo_sc_proof_free, zendoo_field_free, BackwardTransfer, zendoo_compute_poseidon_hash, zendoo_field_assert_eq, zendoo_deserialize_sc_vk_from_file, zendoo_sc_vk_free, zendoo_serialize_sc_proof};

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
        204, 105, 194, 216, 9, 69, 112, 49, 125, 186, 124, 147, 158, 2, 146, 250, 127, 197, 209, 248, 215, 186, 225,
        102, 132, 41, 139, 88, 243, 24, 225, 45
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        77, 107, 100, 149, 66, 133, 64, 12, 129, 179, 101, 205, 224, 222, 215, 10, 94, 82, 185, 91, 180, 22, 32, 249,
        191, 61, 233, 132, 6, 243, 175, 160
    ];

    let constant_bytes: [u8; 96] = [
        216, 139, 118, 158, 134, 237, 170, 166, 34, 216, 197, 252, 233, 45, 222, 30, 137, 228, 171, 146, 94, 23, 111,
        156, 75, 68, 89, 85, 96, 101, 93, 201, 184, 249, 10, 153, 243, 178, 182, 206, 142, 116, 96, 124, 247, 29, 209,
        33, 52, 217, 110, 145, 19, 27, 198, 93, 55, 184, 137, 54, 172, 83, 73, 255, 0, 57, 85, 59, 73, 168, 63, 79,
        143, 194, 252, 188, 20, 253, 178, 233, 138, 226, 93, 204, 3, 113, 38, 52, 212, 214, 204, 247, 87, 2, 0, 0
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
        200, 100, 76, 16, 225, 149, 155, 252, 61, 173, 237, 209, 206, 10, 20, 247, 200, 41, 133, 21,
        126, 58, 115, 243, 185, 125, 66, 26, 226, 4, 24, 22
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        3, 125, 99, 155, 58, 194, 83, 62, 30, 80, 251, 250, 115, 65, 252, 10, 183, 32, 164, 159,
        238, 237, 100, 96, 227, 163, 108, 249, 193, 81, 182, 77
    ];

    let constant_bytes: [u8; 96] = [
        50, 121, 119, 120, 18, 130, 90, 56, 28, 219, 172, 115, 102, 55, 207, 79, 69, 68, 3, 24, 114,
        85, 25, 114, 134, 126, 63, 218, 34, 21, 131, 160, 107, 89, 19, 120, 24, 233, 246, 74, 96, 225,
        137, 228, 197, 136, 159, 214, 8, 240, 129, 182, 122, 173, 115, 152, 193, 27, 63, 95, 231, 2,
        128, 224, 63, 184, 130, 233, 147, 254, 252, 151, 210, 191, 227, 0, 46, 38, 123, 35, 56, 231,
        178, 44, 143, 98, 192, 3, 108, 7, 192, 182, 100, 148, 1, 0
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
    let mut rng = OsRng::default();

    //Generate random field elements
    let mut fes = vec![];
    for _ in 0..16 {
        fes.push(Fr::rand(&mut rng));
    }

    //Get native Merkle Tree
    let native_tree = GingerMerkleTree::new(fes.as_slice()).unwrap();

    //Get Merkle Tree from lib
    let mut fes_ptr = vec![];
    let fes_b = to_bytes!(fes).unwrap();
    for i in 0..16 {
        let mut fe = [0u8; 96];
        fes_b[(i * 96)..((i + 1) * 96)]
            .to_vec()
            .write(&mut fe[..])
            .unwrap();
        fes_ptr.push(zendoo_deserialize_field(&fe) as *const Fr)
    }
    let tree = ginger_mt_new(fes_ptr.as_ptr(), 16);

    //Get root and compare the two trees
    let root = ginger_mt_get_root(tree);

    assert_eq!(unsafe { *root }, native_tree.root());

    for i in 0..16 {
        //Get native Merkle Path for a leaf
        let native_mp = native_tree.generate_proof(i, &fes[i]).unwrap();

        //Get Merkle Path from lib
        let path = ginger_mt_get_merkle_path(fes_ptr[i], i, tree);

        for (native_path, path) in native_mp.path.iter().zip(unsafe { &*path }.path.iter()) {
            assert_eq!(native_path, path);
        }

        //Verify that both merkle paths are correct
        assert!(native_mp.verify(&native_tree.root(), &fes[i]).unwrap());
        assert!(ginger_mt_verify_merkle_path(fes_ptr[i], root, path));

        //Free path
        ginger_mt_path_free(path);
    }

    //Free memory
    ginger_mt_free(tree);
    zendoo_field_free(root);
    for i in 0..16 {
        zendoo_field_free(fes_ptr[i] as *mut Fr);
    }
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

    let hash_input = &[lhs_field as *const Fr, rhs_field as *const Fr];
    let actual_hash = zendoo_compute_poseidon_hash(hash_input.as_ptr(), 2);

    assert!(zendoo_field_assert_eq(expected_hash, actual_hash));

    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);
    zendoo_field_free(expected_hash);
    zendoo_field_free(actual_hash);
}

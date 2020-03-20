use algebra::{curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::G1Projective,
}, fields::{
    mnt4753::Fr,
}, to_bytes, bytes::{
    ToBytes, FromBytes,
}, UniformRand, ProjectiveCurve};

use primitives::
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    };

use proof_systems::groth16::Proof;
use rand::rngs::OsRng;

use crate::{
    zendoo_verify_zkproof,
    zendoo_compute_keys_hash_commitment,
    zendoo_compute_merkle_root, ZendooMcFieldBasedMerkleTree,
};

use std::fs::File;

const VK_PATH: &str = "./test_files/vk";
const PI_LEN: usize = 4;

#[test]
fn verify_zkproof_test() {

    let mut file = File::open("./test_files/good_proof").unwrap();
    let good_proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    let mut file = File::open("./test_files/good_public_inputs").unwrap();
    let mut good_public_inputs = vec![];
    for _ in 0..PI_LEN {good_public_inputs.push(Fr::read(&mut file).unwrap())}

    let mut file = File::open("./test_files/bad_proof").unwrap();
    let bad_proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    let mut file = File::open("./test_files/bad_public_inputs").unwrap();
    let mut bad_public_inputs = vec![];
    for _ in 0..PI_LEN {bad_public_inputs.push(Fr::read(&mut file).unwrap())}

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];
    good_proof.write(&mut zkp[..]).unwrap();

    let inputs = to_bytes!(good_public_inputs).unwrap();
    assert_eq!(inputs.len(), 96 * 4);

    assert!(zendoo_verify_zkproof(
        VK_PATH.as_ptr(),
        VK_PATH.len(),
        &zkp,
        inputs.as_ptr(),
        inputs.len(),
    ));

    //Negative case
    let mut zkp = [0u8; 771];
    bad_proof.write(&mut zkp[..]).unwrap();

    let inputs = to_bytes!(bad_public_inputs).unwrap();
    assert_eq!(inputs.len(), 96 * 4);

    assert!(!zendoo_verify_zkproof(
        VK_PATH.as_ptr(),
        VK_PATH.len(),
        &zkp,
        inputs.as_ptr(),
        inputs.len(),
    ));
}

#[test]
fn compute_hash_commitment_test() {
    let mut rng = OsRng::default();

    //Generate random affine points
    let mut pks = vec![];
    for _ in 0..16 {pks.push(G1Projective::rand(&mut rng).into_affine());}

    //Evaluate hash over their x coordinates
    let pks_x = pks.iter().map(|pk| pk.x).collect::<Vec<_>>();
    let native_h_cm = FrHash::evaluate(pks_x.as_slice()).unwrap();
    let mut pks_b = to_bytes!(pks).unwrap();
    assert_eq!(pks_b.len(), 193 * 16);

    let mut zendoo_h_cm_b = [0u8; 96];

    //Verify correct hash computation from Rust FFI and consistency with the native Rust function
    assert!(zendoo_compute_keys_hash_commitment(
        pks_b.as_ptr(),
        pks_b.len(),
        &mut zendoo_h_cm_b,
    ));
    let zendoo_h_cm = Fr::read(&zendoo_h_cm_b[..]).unwrap();
    assert_eq!(native_h_cm, zendoo_h_cm);

    //Change one of the points
    pks_b = pks_b[..193 * 15].to_vec();
    pks_b.extend_from_slice(to_bytes!(G1Projective::rand(&mut rng).into_affine()).unwrap().as_slice());

    //Verify correct hash computation and result not consistent anymore with the native Rust function
    assert!(zendoo_compute_keys_hash_commitment(
        pks_b.as_ptr(),
        pks_b.len(),
        &mut zendoo_h_cm_b,
    ));
    let zendoo_h_cm = Fr::read(&zendoo_h_cm_b[..]).unwrap();
    assert_ne!(native_h_cm, zendoo_h_cm);
}

#[test]
fn compute_merkle_root_test() {
    let mut rng = OsRng::default();

    //Generate random field elements
    let mut leaves = vec![];
    for _ in 0..16 {leaves.push(Fr::rand(&mut rng));}

    //Compute Merkle Root
    let native_mr = ZendooMcFieldBasedMerkleTree::new(leaves.as_slice())
        .unwrap()
        .root();
    let mut leaves_b = to_bytes!(leaves).unwrap();
    assert_eq!(leaves_b.len(), 96 * 16);

    let mut zendoo_mr_b = [0u8; 96];

    //Verify correct hash computation from Rust FFI and consistency with the native Rust function
    assert!(zendoo_compute_merkle_root(
        leaves_b.as_ptr(),
        leaves_b.len(),
        &mut zendoo_mr_b,
    ));
    let zendoo_mr = Fr::read(&zendoo_mr_b[..]).unwrap();
    assert_eq!(native_mr, zendoo_mr);

    //Change one of the leaves
    leaves_b = leaves_b[..96 * 15].to_vec();
    leaves_b.extend_from_slice(to_bytes!(Fr::rand(&mut rng)).unwrap().as_slice());

    //Verify correct Merkle Root computation and result not consistent anymore with the native Rust function
    assert!(zendoo_compute_merkle_root(
        leaves_b.as_ptr(),
        leaves_b.len(),
        &mut zendoo_mr_b,
    ));
    let zendoo_mr = Fr::read(&zendoo_mr_b[..]).unwrap();
    assert_ne!(native_mr, zendoo_mr);
}
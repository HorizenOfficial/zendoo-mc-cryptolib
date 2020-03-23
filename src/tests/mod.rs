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
    ginger_mt_new, ginger_mt_get_root, ginger_mt_get_merkle_path, ginger_mt_verify_merkle_path,
    ginger_mt_free, ginger_mt_path_free,
    GingerMerkleTree,
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
    let mut fes = vec![];
    for _ in 0..100 {fes.push(Fr::rand(&mut rng));}

    let mut fes_b = vec![];
    fes.iter().for_each(|fe| fes_b.extend_from_slice(to_bytes!(fe).unwrap().as_slice()));

    //Get native Merkle Tree
    let native_tree = GingerMerkleTree::new(fes.as_slice()).unwrap();

    //Get Merkle Tree from lib
    let tree = ginger_mt_new(
        fes_b.as_ptr(),
        fes_b.len(),
    );

    assert!(!tree.is_null());

    //Get root and compare the two trees
    let mut root = [0u8; 96];
    assert!(ginger_mt_get_root(
        tree,
        &mut root,
    ));

    let root_f = Fr::read(&root[..]).unwrap();
    assert_eq!(root_f, native_tree.root());

    //Get native Merkle Path for a leaf
    let native_mp = native_tree.generate_proof(0, &fes[0]).unwrap();

    //Get Merkle Path from lib
    let mut leaf = [0u8; 96];
    leaf.copy_from_slice(&fes_b[..96]);
    let path = ginger_mt_get_merkle_path(
        &mut leaf,
        0,
        tree
    );
    assert!(!path.is_null());

    //Verify path is null if errors (i.e. let's pass an invalid index)
    let wrong_path = ginger_mt_get_merkle_path(
        &mut leaf,
        leaf.len(),
        tree
    );
    assert!(wrong_path.is_null());

    //Verify that both merkle paths are correct
    assert!(native_mp.verify(&native_tree.root(), &fes[0]).unwrap());
    assert!(ginger_mt_verify_merkle_path(
        &leaf,
        &root,
        path
    ));

    //Deallocate tree and merkle path
    ginger_mt_free(tree);
    ginger_mt_path_free(path);
}
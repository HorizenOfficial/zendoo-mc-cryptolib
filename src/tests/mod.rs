use algebra::{curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Projective, G1Affine},
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

use crate::{zendoo_deserialize_field, zendoo_deserialize_pk, deserialize_ginger_zk_proof,
            verify_ginger_zk_proof, zendoo_compute_keys_hash_commitment, ginger_mt_new,
            ginger_mt_get_root, ginger_mt_get_merkle_path, ginger_mt_verify_merkle_path,
            GingerMerkleTree, ginger_zk_proof_free, zendoo_field_free, zendoo_pk_free,
            ginger_mt_free, ginger_mt_path_free
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
    let zkp_ptr = deserialize_ginger_zk_proof(&zkp);

    let inputs = to_bytes!(good_public_inputs).unwrap();
    let mut inputs_ptr = vec![];
    for i in 0..PI_LEN {
        let mut input = [0u8; 96];
        inputs[(i * 96)..((i + 1) * 96)].to_vec().write(&mut input[..]).unwrap();
        inputs_ptr.push(zendoo_deserialize_field(&input) as *const Fr)
    }

    assert!(verify_ginger_zk_proof(
        VK_PATH.as_ptr(),
        VK_PATH.len(),
        zkp_ptr,
        inputs_ptr.as_ptr(),
        PI_LEN,
    ));

    //Free memory
    ginger_zk_proof_free(zkp_ptr);
    for i in 0..PI_LEN {
        zendoo_field_free(inputs_ptr[i] as *mut Fr);
    }

    //Negative case
    let mut zkp = [0u8; 771];
    bad_proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = deserialize_ginger_zk_proof(&zkp);

    let inputs = to_bytes!(bad_public_inputs).unwrap();
    let mut inputs_ptr = vec![];
    for i in 0..PI_LEN {
        let mut input = [0u8; 96];
        inputs[(i * 96)..((i + 1) * 96)].to_vec().write(&mut input[..]).unwrap();
        inputs_ptr.push(zendoo_deserialize_field(&input) as *const Fr)
    }

    assert!(!verify_ginger_zk_proof(
        VK_PATH.as_ptr(),
        VK_PATH.len(),
        zkp_ptr,
        inputs_ptr.as_ptr(),
        PI_LEN,
    ));

    //Free memory
    ginger_zk_proof_free(zkp_ptr);
    for i in 0..PI_LEN {
        zendoo_field_free(inputs_ptr[i] as *mut Fr);
    }
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

    let mut pks_ptr = vec![];
    for i in 0..16 {
        let mut pk = [0u8; 193];
        pks_b[(i * 193)..((i + 1) * 193)].to_vec().write(&mut pk[..]).unwrap();
        pks_ptr.push(zendoo_deserialize_pk(&pk) as *const G1Affine)
    }

    //Verify correct hash computation from Rust FFI and consistency with the native Rust function
    let zendoo_h_cm = zendoo_compute_keys_hash_commitment(
        pks_ptr.as_ptr(),
        16,
    );
    assert_eq!(native_h_cm, unsafe{*zendoo_h_cm});

    //Free memory
    zendoo_field_free(zendoo_h_cm);
    for i in 0..16 {
        zendoo_pk_free(pks_ptr[i] as *mut G1Affine);
    }

    //Change one of the points
    pks_b = pks_b[..193 * 15].to_vec();
    pks_b.extend_from_slice(to_bytes!(G1Projective::rand(&mut rng).into_affine()).unwrap().as_slice());

    let mut pks_ptr = vec![];
    for i in 0..16 {
        let mut pk = [0u8; 193];
        pks_b[(i * 193)..((i + 1) * 193)].to_vec().write(&mut pk[..]).unwrap();
        pks_ptr.push(zendoo_deserialize_pk(&pk) as *const G1Affine)
    }

    //Verify correct hash computation and result not consistent anymore with the native Rust function
    let zendoo_h_cm = zendoo_compute_keys_hash_commitment(
        pks_ptr.as_ptr(),
        16,
    );
    assert_ne!(native_h_cm, unsafe{*zendoo_h_cm});

    //Free memory
    zendoo_field_free(zendoo_h_cm);
    for i in 0..16 {
        zendoo_pk_free(pks_ptr[i] as *mut G1Affine);
    }
}

#[test]
fn merkle_tree_test() {
    let mut rng = OsRng::default();

    //Generate random field elements
    let mut fes = vec![];
    for _ in 0..16 {fes.push(Fr::rand(&mut rng));}

    //Get native Merkle Tree
    let native_tree = GingerMerkleTree::new(fes.as_slice()).unwrap();

    //Get Merkle Tree from lib
    let mut fes_ptr = vec![];
    let fes_b = to_bytes!(fes).unwrap();
    for i in 0..16 {
        let mut fe = [0u8; 96];
        fes_b[(i * 96)..((i + 1) * 96)].to_vec().write(&mut fe[..]).unwrap();
        fes_ptr.push(zendoo_deserialize_field(&fe) as *const Fr)
    }
    let tree = ginger_mt_new(
        fes_ptr.as_ptr(),
        16,
    );

    //Get root and compare the two trees
    let root = ginger_mt_get_root(tree);

    assert_eq!(unsafe{*root}, native_tree.root());

    for i in 0..16 {
        //Get native Merkle Path for a leaf
        let native_mp = native_tree.generate_proof(i, &fes[i]).unwrap();

        //Get Merkle Path from lib
        let path = ginger_mt_get_merkle_path(
            fes_ptr[i],
            i,
            tree
        );

        for (native_path, path) in native_mp.path.iter().zip(unsafe{&*path}.path.iter()){
            assert_eq!(native_path, path);
        }

        //Verify that both merkle paths are correct
        assert!(native_mp.verify(&native_tree.root(), &fes[i]).unwrap());
        assert!(ginger_mt_verify_merkle_path(
            fes_ptr[i],
            root,
            path
        ));

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
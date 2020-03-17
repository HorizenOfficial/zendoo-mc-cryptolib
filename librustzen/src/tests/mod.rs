use algebra::{curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{
        G1Projective, G1Affine,
    },
}, fields::{
    mnt4753::Fr,
}, to_bytes, bytes::{
    ToBytes, FromBytes,
}, UniformRand, ProjectiveCurve, AffineCurve};

use crypto_primitives::{
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    },
    signature::{
        FieldBasedSignatureScheme,
        schnorr::{
            field_impl::{FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme},
        }
    },
};

use groth16::Proof;
use rand::rngs::OsRng;

use crate::{
    librustzen_verify_proof,
    librustzen_compute_hash_commitment,
    librustzen_sign_keygen, librustzen_sign_key_verify, librustzen_sign_message, librustzen_sign_verify,
    librustzen_get_random_fr,
};

use std::fs::File;

const VK_PATH: &str = "./test_files/vk";
const PI_LEN: usize = 4;

#[test]
fn verify_proof_test() {

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

    assert!(librustzen_verify_proof(
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

    assert!(!librustzen_verify_proof(
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

    let mut librustzen_h_cm_b = [0u8; 96];

    //Verify correct hash computation from Rust FFI and consistency with the native Rust function
    assert!(librustzen_compute_hash_commitment(
        pks_b.as_ptr(),
        pks_b.len(),
        &mut librustzen_h_cm_b,
    ));
    let librustzen_h_cm = Fr::read(&librustzen_h_cm_b[..]).unwrap();
    assert_eq!(native_h_cm, librustzen_h_cm);

    //Change one of the points
    pks_b = pks_b[..193 * 15].to_vec();
    pks_b.extend_from_slice(to_bytes!(G1Projective::rand(&mut rng).into_affine()).unwrap().as_slice());

    //Verify correct hash computation and result not consistent anymore with the native Rust function
    assert!(librustzen_compute_hash_commitment(
        pks_b.as_ptr(),
        pks_b.len(),
        &mut librustzen_h_cm_b,
    ));
    let librustzen_h_cm = Fr::read(&librustzen_h_cm_b[..]).unwrap();
    assert_ne!(native_h_cm, librustzen_h_cm);
}

#[test]
fn sign_and_verify_test(){
    type SchnorrSig = FieldBasedSchnorrSignature<Fr>;
    type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, FrHash>;

    let mut random_f = [0u8; 96];

    //Get random field element
    assert!(librustzen_get_random_fr(&mut random_f));

    //Initialize sk and pk
    let mut sk = [0u8; 96];
    let mut pk = [0u8; 193];

    assert!(librustzen_sign_keygen(&mut sk, &mut pk));

    //Verify pk
    assert!(librustzen_sign_key_verify(&pk));

    //Create and verify sig
    let mut sig = [0u8; 192];
    assert!(librustzen_sign_message(random_f.as_ptr(), random_f.len(), &sk, &pk, &mut sig));
    assert!(librustzen_sign_verify(random_f.as_ptr(), random_f.len(), &pk, &sig));

    //Verify native sig
    let native_pk = G1Affine::read(&pk[..]).unwrap().into_projective();
    let native_message = Fr::read(&random_f[..]).unwrap();
    let native_sig = SchnorrSig::read(&sig[..]).unwrap();
    assert!(SchnorrSigScheme::verify(&native_pk, &[native_message], &native_sig).unwrap());

    //Negative tests.
    let mut new_random_f = [0u8; 96];
    assert!(librustzen_get_random_fr(&mut new_random_f));

    // Try to verify signature for a different message
    assert!(!librustzen_sign_verify(new_random_f.as_ptr(), new_random_f.len(), &pk, &sig));

    //Try to verify different signature for a given message
    let mut new_sig = [0u8; 192];
    assert!(librustzen_sign_message(new_random_f.as_ptr(), new_random_f.len(), &sk, &pk, &mut new_sig));
    assert!(!librustzen_sign_verify(random_f.as_ptr(), random_f.len(), &pk, &new_sig));

    //Try to verify signature with a different public key
    let mut new_sk = [0u8; 96];
    let mut new_pk = [0u8; 193];

    assert!(librustzen_sign_keygen(&mut new_sk, &mut new_pk));
    assert!(!librustzen_sign_verify(random_f.as_ptr(), random_f.len(), &new_pk, &sig));
}
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

use circuit::naive_threshold_sig::generate_parameters;

use groth16::Proof;
use rand::{
    Rng, rngs::OsRng
};

use crate::{
    librustzen_naive_threshold_sig_get_null, librustzen_create_naive_threshold_sig_proof,
    librustzen_verify_zkproof,
    librustzen_compute_keys_hash_commitment, librustzen_compute_poseidon_hash,
    librustzen_sign_keygen, librustzen_sign_key_verify, librustzen_sign_message, librustzen_sign_verify,
    librustzen_get_random_fr, librustzen_get_fr_from_int,
};

use std::fs::File;

const VK_PATH: &str = "./test_files/vk";
const PI_LEN: usize = 4;

#[test]
fn random_prove_and_verify_test() {
    let mut rng = OsRng::default();
    let n = 16;

    let params = generate_parameters(n).unwrap();
    let params_path = "./test_files/params";
    let file = File::create(params_path).unwrap();
    params.write(file).unwrap();

    //Generate witnesses for our proof
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);

    //Generate random message to sign
    let mut message = [0u8; 96];
    assert!(librustzen_get_random_fr(&mut message));

    //Generate another random message used to simulate a non-valid signature
    let mut invalid_message = [0u8; 96];
    assert!(librustzen_get_random_fr(&mut invalid_message));

    let mut pks = vec![];
    let mut sigs = vec![];

    for _ in 0..v {

        //Initialize sk and pk
        let mut sk = [0u8; 96];
        let mut pk = [0u8; 193];
        assert!(librustzen_sign_keygen(&mut sk, &mut pk));

        //Sign message
        let mut sig = [0u8; 192];
        assert!(librustzen_sign_message(message.as_ptr(), message.len(), &sk, &pk, &mut sig));

        pks.extend_from_slice(&pk);
        sigs.extend_from_slice(&sig);
    }

    for _ in 0..(n-v){
        //Sample a random boolean and decide if generating a non valid signature or a null one
        let generate_null: bool = rng.gen();
        let (pk, sig) = if generate_null {
            let mut pk = [0u8; 193];
            let mut sig = [0u8; 192];
            assert!(librustzen_naive_threshold_sig_get_null(&mut pk, &mut sig));
            (pk, sig)
        } else {
            let mut sk = [0u8; 96];
            let mut pk = [0u8; 193];
            assert!(librustzen_sign_keygen(&mut sk, &mut pk));

            //Sign invalid message
            let mut sig = [0u8; 192];
            assert!(librustzen_sign_message(invalid_message.as_ptr(), message.len(), &sk, &pk, &mut sig));
            (pk, sig)
        };
        pks.extend_from_slice(&pk);
        sigs.extend_from_slice(&sig);
    }

    assert_eq!(pks.len()/193, n);
    assert_eq!(sigs.len()/192, n);

    //Convert b and t to Fr elements
    let mut threshold = [0u8; 96];
    assert!(librustzen_get_fr_from_int(t, &mut threshold));
    let mut b = [0u8; 96];
    assert!(librustzen_get_fr_from_int(v - t, &mut b));

    //Compute hash commitment H(H(pk) || threshold)

    //Hash all pks
    let mut pks_hash_commitment = [0u8; 96];
    assert!(librustzen_compute_keys_hash_commitment(
        pks.as_ptr(),
        pks.len(),
        &mut pks_hash_commitment,
    ));

    //Hash threshold
    let mut hash_threshold = [0u8; 96];
    assert!(librustzen_compute_poseidon_hash(
        threshold.as_ptr(),
        threshold.len(),
        &mut hash_threshold,
    ));

    //H(pks_hash_commitment, hash_threshold)
    let mut hash_input = vec![];
    hash_input.extend_from_slice(&pks_hash_commitment);
    hash_input.extend_from_slice(&hash_threshold);
    let mut hash_commitment = [0u8; 96];
    assert!(librustzen_compute_poseidon_hash(
        hash_input.as_ptr(),
        hash_input.len(),
        &mut hash_commitment,
    ));

    //Create proof
    let mut zkp = [0u8; 771];
    assert!(librustzen_create_naive_threshold_sig_proof(
        params_path.as_ptr(),
        params_path.len(),
        pks.as_ptr(),
        pks.len(),
        sigs.as_ptr(),
        sigs.len(),
        &threshold,
        &b,
        &message,
        &hash_commitment,
        n,
        &mut zkp
    ));

    //Verify proof

    //Build public inputs
    let mut public_inputs = vec![];
    public_inputs.extend_from_slice(&hash_commitment);
    public_inputs.extend_from_slice(&message);

    let vk_path = "./test_files/new_vk";

    assert!(librustzen_verify_zkproof(
        vk_path.as_ptr(),
        vk_path.len(),
        &zkp,
        public_inputs.as_ptr(),
        public_inputs.len(),
    ));

    //Let's change public inputs and check that proof verification doesn't pass
    let mut wrong_public_inputs = vec![];
    let mut r1 = [0u8; 96];
    assert!(librustzen_get_random_fr(&mut r1));
    let mut r2 = [0u8; 96];
    assert!(librustzen_get_random_fr(&mut r2));
    wrong_public_inputs.extend_from_slice(&r1);
    wrong_public_inputs.extend_from_slice(&r2);

    assert!(!librustzen_verify_zkproof(
        vk_path.as_ptr(),
        vk_path.len(),
        &zkp,
        wrong_public_inputs.as_ptr(),
        wrong_public_inputs.len(),
    ));
}

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

    assert!(librustzen_verify_zkproof(
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

    assert!(!librustzen_verify_zkproof(
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
    assert!(librustzen_compute_keys_hash_commitment(
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
    assert!(librustzen_compute_keys_hash_commitment(
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
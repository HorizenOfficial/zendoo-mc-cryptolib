use algebra::{fields::{
    mnt4753::Fr,
    mnt4753::Fq as Fs,
}, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Projective, G1Affine},
}, bytes::{FromBytes, ToBytes},
   AffineCurve, ProjectiveCurve, UniformRand,
};

use crypto_primitives::{
    signature::{
        FieldBasedSignatureScheme,
        schnorr::field_impl::{
            FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme
        },
    },
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    },
};

use groth16::{Parameters, Proof, verifier::verify_proof, prepare_verifying_key, VerifyingKey, create_random_proof};

use rand::rngs::OsRng;

use libc::c_uchar;
use std::{
    path::Path, slice, ffi::OsStr, os::unix::ffi::OsStrExt, fs::File,
};

//Sig types
type SchnorrSig = FieldBasedSchnorrSignature<Fr>;
type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, FrHash>;

pub mod generic_circuit;

#[cfg(test)]
pub mod tests;

// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const FS_SIZE: usize = FR_SIZE; // 96
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const HASH_SIZE:        usize = FR_SIZE;                // 96
const SIG_SIZE:         usize = 2 * FR_SIZE;            // 192
const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771

// ***********UTILITY FUNCTIONS*************

/// Reads a raw Fr from a [u8; FR_SIZE].
fn read_fr(from: &[u8; FR_SIZE]) -> Option<Fr> {
    match Fr::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads a raw Fs from a [u8; FS_SIZE].
fn read_fs(from: &[u8; FS_SIZE]) -> Option<Fs> {
    match Fs::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads as many FrReprs as FR_SIZE-byte chunks contained in `from`
/// TODO: Probably there is a smarter way to pass a vector of field elements
fn read_frs_from_slice(from: &[u8]) -> Option<Vec<Fr>> {
    let mut fes = vec![];
    for chunk in from.chunks(FR_SIZE) {

        //Pad to reach expected field's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..FR_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        let mut const_chunk = [0u8; FR_SIZE];
        chunk.write(&mut const_chunk[..]).expect("Should be able to write fe bytes into a slice");
        match read_fr(&const_chunk) {
            Some(fe) => fes.push(fe),
            None => return None,
        };
    }
    Some(fes)
}

/// Reads as many G1 Affine points as G1_SIZE-byte chunks contained in `from`
/// TODO: Probably there is a smarter way to pass a vector of curve points
fn read_points_from_slice(from: &[u8]) -> Option<Vec<G1Affine>>
{
    let mut points = vec![];
    for chunk in from.chunks(G1_SIZE) {

        //Pad to reach expected point's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..G1_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        match G1Affine::read(chunk.as_slice()) {
            Ok(p) => points.push(p),
            Err(_) => return None,
        };
    }
    Some(points)
}

fn read_params(params_path: *const u8, params_path_len: usize) -> Parameters<PairingCurve>
{
    // Read params path
    let params_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(params_path, params_path_len)
    }));

    // Load params from file
    let mut params_fs = File::open(params_path).expect("couldn't load params file");

    Parameters::<PairingCurve>::read(&mut params_fs)
        .expect("couldn't deserialize params file")
}

fn read_vk(vk_path: *const u8, vk_path_len: usize) -> VerifyingKey<PairingCurve>
{
    // Read vk path
    let vk_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(vk_path, vk_path_len)
    }));

    // Load vk from file
    let mut vk_fs = File::open(vk_path).expect("couldn't load vk file");

    VerifyingKey::<PairingCurve>::read(&mut vk_fs)
        .expect("couldn't deserialize vk file")
}

//**********ZK SNARK FUNCTIONS*************

use generic_circuit::GingerCircuit;

#[no_mangle]
pub extern "C" fn librustzen_empty_circuit_instance() -> *mut GingerCircuit
{
    Box::into_raw(Box::new(GingerCircuit::new_empty_circuit()))
}

#[no_mangle]
pub extern "C" fn librustzen_create_zk_proof(
    params_path:     *const u8,
    params_path_len: usize,
    circuit:         *mut GingerCircuit,
    zkp:             *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {

    //Load params from file
    let params = read_params(params_path, params_path_len);

    //Get circuit
    let c = unsafe { &*circuit };

    //Create proof
    let mut rng = OsRng::default();
    let proof = match create_random_proof((*c).clone(), &params, &mut rng) {
        Ok(proof) => proof,
        Err(_) => return false,
    };

    //Write out the proof
    proof.write(&mut (unsafe { &mut *zkp })[..])
        .expect(format!("result should be {} bytes", GROTH_PROOF_SIZE).as_str());

    //Free the memory from the circuit instance.
    //Note: Is it ok to automatically do it ? I don't see any use case for not doing it,
    //and the downside is that we will have two functions for each circuit, one for
    //getting an istance of it through a pointer, and the other one to free the
    //memory
    drop(unsafe { Box::from_raw(circuit) });

    true
}

#[no_mangle]
pub extern "C" fn librustzen_verify_zkproof
(
    vk_path:            *const u8,
    vk_path_len:        usize,
    zkp:                *const [c_uchar; GROTH_PROOF_SIZE],
    public_inputs:      *const c_uchar,
    public_inputs_len:  usize,
) -> bool
{
    //Read public inputs
    let public_inputs_raw = unsafe { slice::from_raw_parts(public_inputs, public_inputs_len) };
    let public_inputs = match read_frs_from_slice(public_inputs_raw) {
        Some(public_inputs) => public_inputs,
        None => return false,
    };

    // Deserialize the proof
    let zkp = match Proof::<PairingCurve>::read(&(unsafe { &*zkp })[..]) {
        Ok(zkp) => zkp,
        Err(_) => return false,
    };

    //Load Vk
    let vk = read_vk(vk_path, vk_path_len);
    let pvk = prepare_verifying_key(&vk);

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        // No error, and proof verification successful
        Ok(true) => true,
        // Any other case
        _ => false,
    }
}

//*******SCHNORR SIG**********

// The EcVrfScheme interface wants the pk into projective for different reasons,
// but I let the Rust FFI exposing it in Affine, because it's FR_SIZE bytes less
#[no_mangle]
pub extern "C" fn librustzen_sign_keygen(
    sk_result:             *mut [c_uchar; FS_SIZE],
    pk_result:             *mut [c_uchar; G1_SIZE],
) -> bool
{
    //Generate a random (pk, sk) pair
    let mut rng = OsRng::default();
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);

    // Write out the pk in affine coordinates
    pk.into_affine().write(&mut (unsafe { &mut *pk_result })[..])
        .expect(format!("pk should be {} bytes", G1_SIZE).as_str());

    //Write out the sk
    sk.write(&mut (unsafe { &mut *sk_result })[..])
        .expect(format!("result should be {} bytes", FS_SIZE).as_str());

    true
}

#[no_mangle]
pub extern "C" fn librustzen_sign_key_verify(
    pk:             *const [c_uchar; G1_SIZE],
) -> bool
{
    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    SchnorrSigScheme::keyverify(&pk)
}

#[no_mangle]
pub extern "C" fn librustzen_sign_message(
    message:        *const c_uchar,
    message_len:    usize,
    sk:             *const [c_uchar; FS_SIZE], //MNT4Fq
    pk:             *const [c_uchar; G1_SIZE],
    result:         *mut   [c_uchar; SIG_SIZE],
) -> bool
{
    //Read sk
    let sk = match read_fs(unsafe { &*sk }) {
        Some(sk) => sk,
        None => return false,
    };

    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Sign message
    let mut rng = OsRng::default();
    let sig = match SchnorrSigScheme::sign(&mut rng, &pk, &sk, fes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Write out signature
    sig.write(&mut (unsafe { &mut *result })[..])
        .expect(format!("result should be {} bytes", SIG_SIZE).as_str());

    true
}

#[no_mangle]
pub extern "C" fn librustzen_sign_verify(
    message:        *const c_uchar,
    message_len:    usize,
    pk:             *const [c_uchar; G1_SIZE],
    sig:            *const [c_uchar; SIG_SIZE],
) -> bool
{
    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Read sig
    let sig = match SchnorrSig::read(&(unsafe { &*sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    match SchnorrSigScheme::verify(&pk, fes.as_slice(), &sig) {
        Ok(result) => result,
        Err(_) => return false,
    }
}

// **********HASH UTILS***************

#[no_mangle]
pub extern "C" fn librustzen_compute_poseidon_hash(
    input:        *const c_uchar,
    input_len:    usize,
    result:       *mut   [c_uchar; HASH_SIZE],
) -> bool
{
    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(input, input_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Compute hash
    let hash = match FrHash::evaluate(fes.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    hash.write(&mut (unsafe { &mut *result })[..])
        .expect(format!("result should be {} bytes", HASH_SIZE).as_str());

    true
}

#[no_mangle]
pub extern "C" fn librustzen_compute_keys_hash_commitment(
    pks:        *const c_uchar,
    pks_len:    usize,
    h_cm:       *mut [c_uchar; HASH_SIZE],
) -> bool
{
    let pks_bytes = unsafe { slice::from_raw_parts(pks, pks_len) };
    let pks_x = match read_points_from_slice(pks_bytes) {
        Some(pks) => pks.iter().map(|pk| pk.x).collect::<Vec<_>>(),
        None => return false,
    };

    //Compute hash
    let hash = match FrHash::evaluate(pks_x.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    hash.write(&mut (unsafe { &mut *h_cm })[..])
        .expect(format!("result should be {} bytes", HASH_SIZE).as_str());

    true
}

//***************Test functions*******************
#[no_mangle]
pub extern "C" fn librustzen_get_random_fr(
    result: *mut [c_uchar; FR_SIZE]
) -> bool {
    let mut rng = OsRng::default();
    let random_f = Fr::rand(&mut rng);
    random_f.write(&mut (unsafe { &mut *result })[..])
        .expect(format!("result should be {} bytes", FR_SIZE).as_str());
    true
}

use crypto_primitives::{
    vrf::{
            FieldBasedVrf,
            ecvrf::{
                FieldBasedEcVrf, FieldBasedEcVrfProof,
            }
        },
    crh::bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters},
};

use circuit::constants::{
    VRFParams, VRFWindow,
};

use lazy_static::*;

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G1Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<G1Projective>{generators: params.group_hash_generators}
    };
}

//Hash types
type GroupHash = BoweHopwoodPedersenCRH<G1Projective, VRFWindow>;


//Vrf types
type EcVrfProof = FieldBasedEcVrfProof<Fr, G1Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, G1Projective, FrHash, GroupHash>;


const VRF_PROOF_SIZE:   usize = G1_SIZE + 2 * FR_SIZE;  // 385
const VRF_OUTPUT_SIZE:  usize = HASH_SIZE;              // 96


// ***********VRF UTILS************

// The EcVrfScheme interface wants the pk into projective for different reasons,
// but I let the Rust FFI exposing it in Affine, because it's FR_SIZE bytes less
#[no_mangle]
pub extern "C" fn librustzen_vrf_keygen(
    sk_result:             *mut [c_uchar; FS_SIZE],
    pk_result:             *mut [c_uchar; G1_SIZE],
) -> bool
{
    //Generate a random (pk, sk) pair
    let mut rng = OsRng::default();
    let (pk, sk) = EcVrfScheme::keygen(&mut rng);

    // Write out the pk in affine coordinates
    pk.into_affine().write(&mut (unsafe { &mut *pk_result })[..])
        .expect(format!("pk should be {} bytes", G1_SIZE).as_str());

    //Write out the sk
    sk.write(&mut (unsafe { &mut *sk_result })[..])
        .expect(format!("result should be {} bytes", FS_SIZE).as_str());
    true
}

#[no_mangle]
pub extern "C" fn librustzen_vrf_key_verify(
    pk:             *const [c_uchar; G1_SIZE],
) -> bool
{
    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {

        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    EcVrfScheme::keyverify(&pk)
}

#[no_mangle]
pub extern "C" fn librustzen_vrf_create_proof(
    message:        *const c_uchar,
    message_len:    usize,
    sk:             *const [c_uchar; FS_SIZE],
    pk:             *const [c_uchar; G1_SIZE],
    result:         *mut   [c_uchar; VRF_PROOF_SIZE],
) -> bool
{
    //Read sk
    let sk = match read_fs(unsafe { &*sk }) {
        Some(sk) => sk,
        None => return false,
    };

    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Create proof for message
    let mut rng = OsRng::default();
    let proof = match EcVrfScheme::prove(&mut rng, &VRF_GH_PARAMS, &pk, &sk, fes.as_slice()) {
        Ok(proof) => proof,
        Err(_) => return false,
    };

    // Write out signature
    proof.write(&mut (unsafe { &mut *result })[..])
        .expect("result should be 385 bytes");

    true
}

//Verify the proof and write out the vrf output
#[no_mangle]
pub extern "C" fn librustzen_vrf_proof_to_hash(
    message:        *const c_uchar,
    message_len:    usize,
    pk:             *const [c_uchar; G1_SIZE],
    proof:          *const [c_uchar; VRF_PROOF_SIZE],
    result:         *mut   [c_uchar; VRF_OUTPUT_SIZE],
) -> bool
{
    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Read proof
    let proof = match EcVrfProof::read(&(unsafe { &*proof })[..]) {
        Ok(proof) => proof,
        Err(_) => return false,
    };

    //Verify proof
    let vrf_out = match EcVrfScheme::verify(&VRF_GH_PARAMS, &pk, fes.as_slice(), &proof) {
        Ok(result) => result,
        Err(_) => return false,
    };

    //Write out VRF output
    vrf_out.write(&mut (unsafe { &mut *result })[..])
        .expect(format!("result should be {} bytes", VRF_OUTPUT_SIZE).as_str());
    true
}

//Just verify the proof
#[no_mangle]
pub extern "C" fn librustzen_vrf_proof_verify(
    message:        *const c_uchar,
    message_len:    usize,
    pk:             *const [c_uchar; G1_SIZE],
    proof:          *const [c_uchar; VRF_PROOF_SIZE],
) -> bool
{
    //Read pk
    let pk = match G1Affine::read(&(unsafe { &*pk })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => return false,
    };

    //Read message as an array of Fr elements
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    let fes = match read_frs_from_slice(message) {
        Some(fes) => fes,
        None => return false,
    };

    //Read proof
    let proof = match EcVrfProof::read(&(unsafe { &*proof })[..]) {
        Ok(proof) => proof,
        Err(_) => return false,
    };

    //Verify proof
    match EcVrfScheme::verify(&VRF_GH_PARAMS, &pk, fes.as_slice(), &proof) {
        Ok(_) => true,
        Err(_) => false,
    }
}
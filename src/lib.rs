use algebra::{
    fields::mnt4753::Fr,
    curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::G1Affine,
}, bytes::{FromBytes, ToBytes},
   UniformRand,
};

use primitives::{
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    },
    merkle_tree::field_based_mht::{
        FieldBasedMerkleHashTree, FieldBasedMerkleTreeConfig, FieldBasedMerkleTreePath
    },
};

use proof_systems::groth16::{Proof, verifier::verify_proof, prepare_verifying_key, VerifyingKey};

use rand::rngs::OsRng;
use libc::c_uchar;
use std::{
    path::Path, slice, ffi::OsStr, os::unix::ffi::OsStrExt, fs::File, ptr::null_mut,
};

#[cfg(test)]
pub mod tests;

// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const HASH_SIZE:        usize = FR_SIZE;                // 96
const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771

// ************TYPES**********************

pub struct ZendooMcFieldBasedMerkleTreeParams;

impl FieldBasedMerkleTreeConfig for ZendooMcFieldBasedMerkleTreeParams {
    const HASH_LEAVES: bool = true;
    const HEIGHT: usize = 32;
    type H = FrHash;
}

type GingerMerkleTree = FieldBasedMerkleHashTree<ZendooMcFieldBasedMerkleTreeParams>;
type GingerMerkleTreePath = FieldBasedMerkleTreePath<ZendooMcFieldBasedMerkleTreeParams>;


// ***********UTILITY FUNCTIONS*************

/// Reads a raw Fr from a [u8; FR_SIZE].
fn read_fr(from: &[u8; FR_SIZE]) -> Option<Fr> {
    match Fr::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads as many FrReprs as FR_SIZE-byte chunks contained in `from`
/// TODO: Probably there is an easier way to pass a vector of field elements
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
/// TODO: Probably there is an easier way to pass a vector of curve points
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

//********************SNARK functions********************

#[no_mangle]
pub extern "C" fn zendoo_verify_zkproof
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

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_compute_poseidon_hash(
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
pub extern "C" fn zendoo_compute_keys_hash_commitment(
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

// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn ginger_mt_new(
    leaves:        *const c_uchar,
    leaves_len:    usize,
) -> *mut GingerMerkleTree
{
    //Read field elements
    let leaves_bytes = unsafe { slice::from_raw_parts(leaves, leaves_len) };
    let leaves = match read_frs_from_slice(leaves_bytes) {
        Some(fes) => fes,
        None => return null_mut(),
    };

    //Generate tree and compute Merkle Root
    let gmt = match GingerMerkleTree::new(&leaves) {
        Ok(tree) => tree,
        Err(_) => return null_mut(),
    };

    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_root(
    tree:   *const GingerMerkleTree,
    mr:     *mut [c_uchar; HASH_SIZE]
) -> bool
{
    if tree.is_null() { return false }
    let root = unsafe { &*tree }.root();
    root.write(&mut (unsafe { &mut *mr })[..])
        .expect(format!("result should be {} bytes", HASH_SIZE).as_str());
    true
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_merkle_path(
    leaf:       *const [c_uchar; FR_SIZE],
    leaf_index: usize,
    tree:       *const GingerMerkleTree,
) -> *mut GingerMerkleTreePath
{
    if tree.is_null() { return null_mut() }
    let tree = unsafe { &*tree };

    //Read leaf
    let leaf = match read_fr(unsafe { &*leaf }) {
        Some(leaf) => leaf,
        None => return null_mut(),
    };

    //Compute Merkle Path
    let mp = match tree.generate_proof(leaf_index, &leaf) {
        Ok(path) => path,
        Err(_) => return null_mut(),
    };

    Box::into_raw(Box::new(mp))
}

#[no_mangle]
pub extern "C" fn ginger_mt_verify_merkle_path(
    leaf:       *const [c_uchar; FR_SIZE],
    mr:         *const [c_uchar; HASH_SIZE],
    path:       *const GingerMerkleTreePath,
) -> bool
{
    if path.is_null() { return false }
    let path = unsafe { &*path };

    //Read leaf
    let leaf = match read_fr(unsafe { &*leaf }) {
        Some(leaf) => leaf,
        None => return false,
    };

    //Read root
    let root = match read_fr(unsafe { &*mr }) {
        Some(root) => root,
        None => return false,
    };

    // Verify leaf belonging
    match path.verify(&root, &leaf) {
        Ok(true) => true,
        _ => false,
    }
}

#[no_mangle]
pub extern "C" fn ginger_mt_free(tree: *mut GingerMerkleTree) {
    if tree.is_null() { return }
    drop(unsafe { Box::from_raw(tree) });
}

#[no_mangle]
pub extern "C" fn ginger_mt_path_free(path: *mut GingerMerkleTreePath) {
    if path.is_null()  { return }
    drop(unsafe { Box::from_raw(path) });
}

//***************Test functions*******************
#[no_mangle]
pub extern "C" fn zendoo_get_random_fr(
    result: *mut [c_uchar; FR_SIZE]
) -> bool {
    let mut rng = OsRng::default();
    let random_f = Fr::rand(&mut rng);
    random_f.write(&mut (unsafe { &mut *result })[..])
        .expect(format!("result should be {} bytes", FR_SIZE).as_str());
    true
}
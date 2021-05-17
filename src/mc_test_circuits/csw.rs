use algebra::ToConstraintField;
use primitives::FieldBasedHash;
use proof_systems::darlin::data_structures::{FinalDarlinDeferredData, FinalDarlinProof};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError,
};
use r1cs_std::{
    fields::FieldGadget,
    alloc::AllocGadget,
    eq::EqGadget,
    Assignment,
    instantiated::tweedle::FrGadget,
};
use r1cs_crypto::crh::{poseidon::tweedle::TweedleFrPoseidonHashGadget, FieldBasedHashGadget};
use cctp_primitives::{
    type_mapping::FieldElement,
    proving_system::{
        ProvingSystem, ZendooProverKey, ZendooProof, ZendooVerifierKey,
        error::ProvingSystemError, init::{get_g1_committer_key, get_g2_committer_key},
        verifier::UserInputs
    },
    utils::serialization::deserialize_from_buffer,
};
use crate::type_mapping::*;
use rand::rngs::OsRng;

type FieldElementGadget = FrGadget;
type FieldHashGadget = TweedleFrPoseidonHashGadget;

fn enforce_csw_inputs_hash_gadget<CS: ConstraintSystem<FieldElement>>(
    mut cs:                                 CS,
    amount:                                 Option<FieldElement>,
    sc_id:                                  Option<FieldElement>,
    pub_key_hash:                           Option<FieldElement>,
    cert_data_hash:                         Option<FieldElement>,
    end_cumulative_sc_tx_comm_tree_root:    Option<FieldElement>
) -> Result<(), SynthesisError>
{
    //Alloc witnesses
    let amount_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc amount"),
        || amount.ok_or(SynthesisError::AssignmentMissing)
    )?;

    let sc_id_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc sc_id"),
        || sc_id.ok_or(SynthesisError::AssignmentMissing)
    )?;

    let pub_key_hash_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc pub_key_hash"),
        || pub_key_hash.ok_or(SynthesisError::AssignmentMissing)
    )?;

    let cert_data_hash_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc cert_data_hash"),
        || cert_data_hash.ok_or(SynthesisError::AssignmentMissing)
    )?;

    let end_cumulative_sc_tx_comm_tree_root_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc end_cumulative_sc_tx_comm_tree_root"),
        || end_cumulative_sc_tx_comm_tree_root.ok_or(SynthesisError::AssignmentMissing)
    )?;

    // Enforce hash
    let actual_hash_g = FieldHashGadget::enforce_hash_constant_length(
        cs.ns(|| "H(witnesses)"),
        &[amount_g, sc_id_g, pub_key_hash_g, cert_data_hash_g, end_cumulative_sc_tx_comm_tree_root_g]
    )?;

    //Alloc public input hash
    let expected_hash_g = FieldElementGadget::alloc_input(
        cs.ns(|| "alloc expected H(witnesses) as public input"),
        || Ok(actual_hash_g.get_value().get()?)
    )?;

    //Enforce equality
    actual_hash_g.enforce_equal(
        cs.ns(|| "actual_hash_g == expected_hash_g"),
        &expected_hash_g
    )?;
    Ok(())
}

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct CSWTestCircuit {
    amount:                                 Option<FieldElement>,
    sc_id:                                  Option<FieldElement>,
    pub_key_hash:                           Option<FieldElement>,
    cert_data_hash:                         Option<FieldElement>,
    end_cumulative_sc_tx_comm_tree_root:    Option<FieldElement>
}

impl ConstraintSynthesizer<FieldElement> for CSWTestCircuit {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        enforce_csw_inputs_hash_gadget(
            cs.ns(|| "enforce H(witnesses) == pub_ins"),
            self.amount, self.sc_id, self.pub_key_hash, self.cert_data_hash,
            self.end_cumulative_sc_tx_comm_tree_root
        )
    }
}

pub struct CSWTestProofUserInputs<'a> {
    pub amount:                                     u64,
    pub sc_id:                                      &'a FieldElement,
    pub pub_key_hash:                               &'a [u8; UINT_160_SIZE],
    pub cert_data_hash:                             &'a FieldElement,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a FieldElement,
}

impl<'a> UserInputs for CSWTestProofUserInputs<'a> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {

        // Pad with 0s until FIELD_SIZE
        let mut pub_key_hash = self.pub_key_hash.to_vec();
        pub_key_hash.append(&mut vec![0u8; FIELD_SIZE - UINT_160_SIZE]);

        let hash_fes = FieldHash::init_constant_length(5, None)
            .update(FieldElement::from(self.amount))
            .update(*self.sc_id)
            .update(deserialize_from_buffer::<FieldElement>(&pub_key_hash).unwrap())
            .update(*self.cert_data_hash)
            .update(*self.end_cumulative_sc_tx_commitment_tree_root)
            .finalize()
            .unwrap();
        Ok(vec![hash_fes])
    }
}

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct CSWTestCircuitWithAccumulators {
    amount:                                 Option<FieldElement>,
    sc_id:                                  Option<FieldElement>,
    pub_key_hash:                           Option<FieldElement>,
    cert_data_hash:                         Option<FieldElement>,
    end_cumulative_sc_tx_comm_tree_root:    Option<FieldElement>,
    custom_fields:                          Vec<FieldElement>, // Represents deferred data
}

impl ConstraintSynthesizer<FieldElement> for CSWTestCircuitWithAccumulators {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // convert the FinalDarlinDeferred efficiently to circuit inputs
        let deferred_as_native_fes = self.custom_fields;

        // Alloc deferred data as public input
        let mut deferred_input_gs = Vec::new();
        for (i, fe) in deferred_as_native_fes.iter().enumerate() {
            let ins_g = FieldElementGadget::alloc_input(
                cs.ns(|| format!("Alloc input deferred elem {}", i)),
                || Ok(fe)
            )?;
            deferred_input_gs.push(ins_g);
        }

        // Alloc deferred data as witness
        let mut deferred_gs = Vec::new();
        for (i, fe) in deferred_as_native_fes.into_iter().enumerate() {
            let witness_g = FieldElementGadget::alloc(
                cs.ns(|| format!("Alloc deferred elem {}", i)),
                || Ok(fe)
            )?;
            deferred_gs.push(witness_g);
        }

        // Enforce the system inputs to the circuit to be equal to the allocated `deferred`.
        // This is a simple way to allow test cases where sys data (i.e. the deferred
        // accumulators) are wrong.
        for (i, (deferred_w, deferred_ins)) in deferred_input_gs.into_iter().zip(deferred_gs).enumerate() {
            deferred_w.enforce_equal(
                cs.ns(|| format!("enforce deferred equal {}", i)),
                &deferred_ins
            )?;
        }

        enforce_csw_inputs_hash_gadget(
            cs.ns(|| "enforce H(witnesses) == pub_ins"),
            self.amount, self.sc_id, self.pub_key_hash, self.cert_data_hash,
            self.end_cumulative_sc_tx_comm_tree_root
        )?;

        Ok(())
    }
}

pub struct CSWTestProofWithAccumulatorsUserInputs<'a> {
    pub amount:                                     u64,
    pub sc_id:                                      &'a FieldElement,
    pub pub_key_hash:                               &'a [u8; UINT_160_SIZE],
    pub cert_data_hash:                             &'a FieldElement,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a FieldElement,
}

impl<'a> UserInputs for CSWTestProofWithAccumulatorsUserInputs<'a> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {

        // Pad with 0s until FIELD_SIZE
        let mut pub_key_hash = self.pub_key_hash.to_vec();
        pub_key_hash.append(&mut vec![0u8; FIELD_SIZE - UINT_160_SIZE]);

        Ok(vec![FieldHash::init_constant_length(5, None)
            .update(FieldElement::from(self.amount))
            .update(*self.sc_id)
            .update(deserialize_from_buffer::<FieldElement>(&pub_key_hash).unwrap())
            .update(*self.cert_data_hash)
            .update(*self.end_cumulative_sc_tx_commitment_tree_root)
            .finalize()
            .unwrap()])
    }
}

pub fn generate_parameters(ps: ProvingSystem) -> Result<(ZendooProverKey, ZendooVerifierKey), ProvingSystemError>
{
    let ck_g1 = get_g1_committer_key()?;
    match ps {
        ProvingSystem::Undefined => Err(ProvingSystemError::UndefinedProvingSystem),
        ProvingSystem::Darlin => {
            let ck_g2 = get_g2_committer_key()?;
            let circ = CSWTestCircuitWithAccumulators {
                amount: None,
                sc_id: None,
                pub_key_hash: None,
                cert_data_hash: None,
                end_cumulative_sc_tx_comm_tree_root: None,
                custom_fields: FinalDarlinDeferredData::<G1, G2>::generate_random::<_, Digest>(
                    &mut rand::thread_rng(),
                    ck_g1.as_ref().unwrap(),
                    ck_g2.as_ref().unwrap(),
                ).to_field_elements().unwrap()
            };
            let (pk, vk) =  CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circ)
                .map_err(|e| ProvingSystemError::SetupFailed(e.to_string()))?;
            Ok((ZendooProverKey::Darlin(pk), ZendooVerifierKey::Darlin(vk)))
        },
        ProvingSystem::CoboundaryMarlin => {
            let circ = CSWTestCircuit {
                amount: None,
                sc_id: None,
                pub_key_hash: None,
                cert_data_hash: None,
                end_cumulative_sc_tx_comm_tree_root: None,
            };
            let (pk, vk) =  CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circ)
                .map_err(|e| ProvingSystemError::SetupFailed(e.to_string()))?;
            Ok((ZendooProverKey::CoboundaryMarlin(pk), ZendooVerifierKey::CoboundaryMarlin(vk)))
        }
    }
}

pub fn generate_proof(
    pk:                                         &ZendooProverKey,
    zk:                                         bool,
    amount:                                     u64,
    sc_id:                                      &FieldElement,
    pub_key_hash:                               &[u8; UINT_160_SIZE],
    cert_data_hash:                             &FieldElement,
    end_cumulative_sc_tx_commitment_tree_root:  &FieldElement,
) -> Result<ZendooProof, ProvingSystemError> {
    let rng = &mut OsRng;
    let ck_g1 = get_g1_committer_key()?;

    // Pad with 0s until FIELD_SIZE
    let mut pub_key_hash = pub_key_hash.to_vec();
    pub_key_hash.append(&mut vec![0u8; FIELD_SIZE - UINT_160_SIZE]);
    let pub_key_hash_fe = deserialize_from_buffer::<FieldElement>(pub_key_hash.as_slice()).unwrap();

    let amount = FieldElement::from(amount);

    match pk {
        ZendooProverKey::Darlin(pk) => {
            let ck_g2 = get_g2_committer_key()?;
            let deferred = FinalDarlinDeferredData::<G1, G2>::generate_random::<_, Digest>(
                rng,
                ck_g1.as_ref().unwrap(),
                ck_g2.as_ref().unwrap(),
            );
            let deferred_fes = deferred.to_field_elements().unwrap();
            let circ = CSWTestCircuitWithAccumulators {
                amount: Some(amount),
                sc_id: Some(*sc_id),
                pub_key_hash: Some(pub_key_hash_fe),
                cert_data_hash: Some(*cert_data_hash),
                end_cumulative_sc_tx_comm_tree_root: Some(*end_cumulative_sc_tx_commitment_tree_root),
                custom_fields: deferred_fes.clone()
            };
            let proof = CoboundaryMarlin::prove(
                pk,
                ck_g1.as_ref().unwrap(),
                circ,
                zk,
                if zk { Some(rng) } else { None }
            ).map_err(|e| ProvingSystemError::ProofCreationFailed(e.to_string()))?;
            let darlin_proof = FinalDarlinProof::<G1, G2, Digest> {
                proof: MarlinProof(proof),
                deferred
            };
            Ok(ZendooProof::Darlin(darlin_proof))
        },
        ZendooProverKey::CoboundaryMarlin(pk) => {
            let circ = CSWTestCircuit {
                amount: Some(amount),
                sc_id: Some(*sc_id),
                pub_key_hash: Some(pub_key_hash_fe),
                cert_data_hash: Some(*cert_data_hash),
                end_cumulative_sc_tx_comm_tree_root: Some(*end_cumulative_sc_tx_commitment_tree_root),
            };
            let proof = CoboundaryMarlin::prove(
                pk,
                ck_g1.as_ref().unwrap(),
                circ,
                zk,
                if zk { Some(rng) } else { None }
            ).map_err(|e| ProvingSystemError::ProofCreationFailed(e.to_string()))?;
            Ok(ZendooProof::CoboundaryMarlin(MarlinProof(proof)))
        }
    }
}
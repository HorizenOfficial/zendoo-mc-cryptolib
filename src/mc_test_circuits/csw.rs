use algebra::ToConstraintField;
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
        error::ProvingSystemError, init::{get_g1_committer_key, get_g2_committer_key}
    }
};
use crate::type_mapping::*;
use rand::rngs::OsRng;
use cctp_primitives::proving_system::verifier::UserInputs;
use primitives::FieldBasedHash;
use cctp_primitives::utils::data_structures::BackwardTransfer;
use cctp_primitives::utils::get_bt_merkle_root;

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
        enforce_cert_inputs_hash_gadget(
            cs.ns(|| "enforce H(witnesses) == pub_ins"),
            self.amount, self.sc_id, self.pub_key_hash, self.cert_data_hash,
            self.end_cumulative_sc_tx_comm_tree_root
        )
    }
}

pub struct CSWTestProofUserInputs {
    amount:                               u32,
    sc_id:
    ft_min_amount:                        u64,
    btr_fee:                              u64,
    quality:                              u64,
    constant:                             FieldElement,
    end_cumulative_sc_tx_comm_tree_root:  FieldElement,
}

impl UserInputs for CertTestProofUserInputs {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        let hash_fes = FieldHash::init_constant_length(7, None)
            .update(FieldElement::from(self.epoch_number))
            .update(self.end_cumulative_sc_tx_comm_tree_root)
            .update(get_bt_merkle_root(self.bt_list.as_slice()).unwrap())
            .update(FieldElement::from(self.ft_min_amount))
            .update(FieldElement::from(self.btr_fee))
            .update(FieldElement::from(self.quality))
            .update(self.constant)
            .finalize()
            .unwrap();
        Ok(vec![hash_fes])
    }
}

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct CertTestCircuitWithAccumulators {
    epoch_number:                         Option<FieldElement>,
    end_cumulative_sc_tx_comm_tree_root:  Option<FieldElement>,
    mr_bt:                                Option<FieldElement>,
    ft_min_amount:                        Option<FieldElement>,
    btr_fee:                              Option<FieldElement>,
    quality:                              Option<FieldElement>,
    constant:                             Option<FieldElement>,
    custom_fields:                        Vec<FieldElement>, // Represents deferred data
}

impl ConstraintSynthesizer<FieldElement> for CertTestCircuitWithAccumulators {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        enforce_cert_inputs_hash_gadget(
            cs.ns(|| "enforce H(witnesses) == pub_ins"),
            self.epoch_number, self.end_cumulative_sc_tx_comm_tree_root, self.mr_bt,
            self.ft_min_amount, self.btr_fee, self.quality, self.constant
        )?;

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

        Ok(())
    }
}

pub struct CertTestProofWithAccumulatorsUserInputs {
    epoch_number:                         u32,
    end_cumulative_sc_tx_comm_tree_root:  FieldElement,
    bt_list:                              Vec<BackwardTransfer>,
    ft_min_amount:                        u64,
    btr_fee:                              u64,
    quality:                              u64,
    constant:                             FieldElement,
    proof_data:                           Vec<FieldElement>,
}

impl UserInputs for CertTestProofWithAccumulatorsUserInputs {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        let mut hash_fes = vec![FieldHash::init_constant_length(7, None)
            .update(FieldElement::from(self.epoch_number))
            .update(self.end_cumulative_sc_tx_comm_tree_root)
            .update(get_bt_merkle_root(self.bt_list.as_slice()).unwrap())
            .update(FieldElement::from(self.ft_min_amount))
            .update(FieldElement::from(self.btr_fee))
            .update(FieldElement::from(self.quality))
            .update(self.constant)
            .finalize()
            .unwrap()];
        hash_fes.extend_from_slice(self.proof_data.as_slice());
        Ok(hash_fes)
    }
}

pub fn generate_parameters(ps: ProvingSystem) -> Result<(ZendooProverKey, ZendooVerifierKey), ProvingSystemError>
{
    let ck_g1 = get_g1_committer_key()?;
    match ps {
        ProvingSystem::Undefined => Err(ProvingSystemError::UndefinedProvingSystem),
        ProvingSystem::Darlin => {
            let ck_g2 = get_g2_committer_key()?;
            let circ = CertTestCircuitWithAccumulators {
                epoch_number: None,
                end_cumulative_sc_tx_comm_tree_root: None,
                mr_bt: None,
                ft_min_amount: None,
                btr_fee: None,
                quality: None,
                constant: None,
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
            let circ = CertTestCircuit {
                epoch_number: None,
                end_cumulative_sc_tx_comm_tree_root: None,
                mr_bt: None,
                ft_min_amount: None,
                btr_fee: None,
                quality: None,
                constant: None,
            };
            let (pk, vk) =  CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circ)
                .map_err(|e| ProvingSystemError::SetupFailed(e.to_string()))?;
            Ok((ZendooProverKey::CoboundaryMarlin(pk), ZendooVerifierKey::CoboundaryMarlin(vk)))
        }
    }
}

pub fn generate_proof(
    pk:                                   &ZendooProverKey,
    zk:                                   bool,
    epoch_number:                         u32,
    end_cumulative_sc_tx_comm_tree_root:  FieldElement,
    bt_list:                              Vec<BackwardTransfer>,
    ft_min_amount:                        u64,
    btr_fee:                              u64,
    quality:                              u64,
    constant:                             FieldElement,
) -> Result<(Option<Vec<FieldElement>>, ZendooProof), ProvingSystemError> {
    let rng = &mut OsRng;
    let ck_g1 = get_g1_committer_key()?;

    // Read input param into field elements
    let epoch_number = FieldElement::from(epoch_number);
    let mr_bt = get_bt_merkle_root(bt_list.as_slice()).unwrap();
    let ft_min_amount = FieldElement::from(ft_min_amount);
    let btr_fee = FieldElement::from(btr_fee);
    let quality = FieldElement::from(quality);

    match pk {
        ZendooProverKey::Darlin(pk) => {
            let ck_g2 = get_g2_committer_key()?;
            let deferred = FinalDarlinDeferredData::<G1, G2>::generate_random::<_, Digest>(
                rng,
                ck_g1.as_ref().unwrap(),
                ck_g2.as_ref().unwrap(),
            );
            let deferred_fes = deferred.to_field_elements().unwrap();
            let circ = CertTestCircuitWithAccumulators {
                epoch_number: Some(epoch_number),
                end_cumulative_sc_tx_comm_tree_root: Some(end_cumulative_sc_tx_comm_tree_root),
                mr_bt: Some(mr_bt),
                ft_min_amount: Some(ft_min_amount),
                btr_fee: Some(btr_fee),
                quality: Some(quality),
                constant: Some(constant),
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
            Ok((Some(deferred_fes), ZendooProof::Darlin(darlin_proof)))
        },
        ZendooProverKey::CoboundaryMarlin(pk) => {
            let circ = CertTestCircuit {
                epoch_number: Some(epoch_number),
                end_cumulative_sc_tx_comm_tree_root: Some(end_cumulative_sc_tx_comm_tree_root),
                mr_bt: Some(mr_bt),
                ft_min_amount: Some(ft_min_amount),
                btr_fee: Some(btr_fee),
                quality: Some(quality),
                constant: Some(constant),
            };
            let proof = CoboundaryMarlin::prove(
                pk,
                ck_g1.as_ref().unwrap(),
                circ,
                zk,
                if zk { Some(rng) } else { None }
            ).map_err(|e| ProvingSystemError::ProofCreationFailed(e.to_string()))?;
            Ok((None, ZendooProof::CoboundaryMarlin(MarlinProof(proof))))
        }
    }
}
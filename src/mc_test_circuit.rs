use algebra::{
    fields::mnt4753::Fr as MNT4Fr,
    curves::mnt4753::MNT4,
    PrimeField,
};

use proof_systems::groth16::{
    generator::generate_random_parameters, Parameters,
    prover::create_random_proof, Proof,
};

use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError,
};
use r1cs_std::{
    fields::{
        fp::FpGadget, FieldGadget,
    },
    alloc::AllocGadget,
    eq::EqGadget,
    Assignment,
};

use r1cs_crypto::crh::{MNT4PoseidonHashGadget, FieldBasedHashGadget};

use std::marker::PhantomData;
use rand::rngs::OsRng;

type MNT4FrGadget = FpGadget<MNT4Fr>;

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct MCTestCircuit<F: PrimeField>{
    end_epoch_mc_b_hash:      Option<MNT4Fr>,
    prev_end_epoch_mc_b_hash: Option<MNT4Fr>,
    mr_bt:                    Option<MNT4Fr>,
    quality:                  Option<MNT4Fr>,
    constant:                 Option<MNT4Fr>,
    proofdata:                Option<MNT4Fr>,
    _field:                   PhantomData<F>

}

impl<F: PrimeField> MCTestCircuit<F> {
    pub fn create_proof(
        end_epoch_mc_b_hash:      MNT4Fr,
        prev_end_epoch_mc_b_hash: MNT4Fr,
        mr_bt:                    MNT4Fr,
        quality:                  MNT4Fr,
        constant:                 MNT4Fr,
        proofdata:                MNT4Fr,
        params:                   Parameters<MNT4>
    ) -> Result<Proof<MNT4>, SynthesisError> {
        let c = Self{
            end_epoch_mc_b_hash:      Some(end_epoch_mc_b_hash),
            prev_end_epoch_mc_b_hash: Some(prev_end_epoch_mc_b_hash),
            mr_bt:                    Some(mr_bt),
            quality:                  Some(quality),
            constant:                 Some(constant),
            proofdata:                Some(proofdata),
            _field:                   PhantomData,
        };
        let mut rng = OsRng::default();
        let proof = create_random_proof(c, &params, &mut rng)?;
        Ok(proof)
    }

    pub fn generate_parameters() -> Result<Parameters<MNT4>, SynthesisError>
    {
        //Generate parameters, generate and save to file proof and verification key
        let mut rng = OsRng::default();

        // Create parameters for our circuit
        let params = {
            let c = MCTestCircuit::<MNT4Fr> {
                end_epoch_mc_b_hash:      None,
                prev_end_epoch_mc_b_hash: None,
                mr_bt:                    None,
                quality:                  None,
                constant:                 None,
                proofdata:                None,
                _field:                   PhantomData,
            };
            generate_random_parameters::<MNT4, _, _>(c, &mut rng)
        }?;

        Ok(params)
    }
}

impl<F: PrimeField> ConstraintSynthesizer<MNT4Fr> for MCTestCircuit<F> {
    fn generate_constraints<CS: ConstraintSystem<MNT4Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        //Alloc witnesses
        let end_epoch_mc_b_hash_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc end_epoch_mc_b_hash"),
            || self.end_epoch_mc_b_hash.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let prev_end_epoch_mc_b_hash_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc prev_end_epoch_mc_b_hash"),
            || self.prev_end_epoch_mc_b_hash.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let mr_bt_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc mr_bt"),
            || self.mr_bt.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let quality_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc quality"),
            || self.quality.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let constant_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc constant"),
            || self.constant.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let proofdata_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc proofdata"),
            || self.proofdata.ok_or(SynthesisError::AssignmentMissing)
        )?;

        //Enforce hash of witnesses
        let actual_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(witnesses)"),
            &[
                end_epoch_mc_b_hash_g, prev_end_epoch_mc_b_hash_g,
                mr_bt_g, quality_g, constant_g, proofdata_g
            ]
        )?;

        //Alloc public input hash
        let expected_hash_g = MNT4FrGadget::alloc_input(
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
}


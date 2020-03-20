use algebra::{
    fields::mnt4753::Fr,
    Field, PrimeField,
};
use r1cs_core::{
    ConstraintSystem, ConstraintSynthesizer, SynthesisError,
};
use circuit::naive_threshold_sig::NaiveTresholdSignature;
use std::marker::PhantomData;

//Just for test
#[derive(Clone)]
pub struct EmptyCircuit<F: Field>{
    _field: PhantomData<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for EmptyCircuit<ConstraintF> {
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        _cs: &mut CS,
    ) -> Result<(), SynthesisError> { Ok(()) }
}

#[derive(Clone)]
pub enum Circuit<F: PrimeField> {
    EmptyCircuit(EmptyCircuit<F>),
    NaiveTresholdSignature(NaiveTresholdSignature<F>),
}

// Will hold all the functions to create the circuits.
// The input for each function will be the witnesses/
// public inputs required by each circuit.
// There will be a corresponding FFI functions for each
// of these, returning a pointer to an instance of `Circuit`
// enum with the actual type of circuit.
impl Circuit<Fr> {

    pub fn new_empty_circuit() -> Self {
        Circuit::EmptyCircuit(EmptyCircuit::<Fr>{_field: PhantomData})
    }

    pub fn new_naive_threshold_signature_circuit() -> Self {
        Circuit::NaiveTresholdSignature(NaiveTresholdSignature::<Fr>::default())
    }
}

// We implement ConstraintSynthesizer trait so that everything works when
// passing the generic `Circuit` enum instance to create_random_proof
impl ConstraintSynthesizer<Fr> for Circuit<Fr> {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, _cs: &mut CS) -> Result<(), SynthesisError> {
        match self {
            Circuit::EmptyCircuit(ec) => ec.generate_constraints(_cs),
            Circuit::NaiveTresholdSignature(nes) => nes.generate_constraints(_cs)
        }
    }
}

pub type GingerCircuit = Circuit<Fr>;
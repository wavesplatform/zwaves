use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::pedersen_hash::{Personalization};

use bellman::groth16::{Proof, generate_random_parameters, truncate_verifying_key, create_random_proof};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::PrimeField;
use rand::os::OsRng;
use rand::Rng;

use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use crate::circuit::merkle_proof;



#[derive(Clone)]
pub struct CompressDemo<E: JubjubEngine> {
    pub params: Box<E::Params>,
    pub left: Option<E::Fr>,
    pub right: Option<E::Fr>,
    pub root: Option<E::Fr>
}

impl <E: JubjubEngine> Circuit<E> for CompressDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let root = AllocatedNum::alloc(cs.namespace(|| "signal public input root"), || self.root.ok_or(SynthesisError::AssignmentMissing))?;
        root.inputize(cs.namespace(|| "image inputize"));
        let left = AllocatedNum::alloc(cs.namespace(|| "signal public input left"), || self.left.ok_or(SynthesisError::AssignmentMissing))?;
        let right = AllocatedNum::alloc(cs.namespace(|| "signal public input right"), || self.right.ok_or(SynthesisError::AssignmentMissing))?;

        let root_calculated = merkle_proof::compress(
            cs.namespace(|| "image_calculated <== merkle_proof(...)"),
            Personalization::NoteCommitment,
            left,
            right,
            &self.params
        )?.clone();

        cs.enforce(|| "root_calculated === root", |lc| lc + root.get_variable(), |lc| lc + CS::one(), |lc| lc + root_calculated.get_variable());

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::PedersenHasherBls12;
    use sapling_crypto::circuit::test::TestConstraintSystem;


    #[test]
    pub fn test_compress_witness(){

        let rng = &mut OsRng::new().unwrap();
        let hasher = PedersenHasherBls12::default();

        let left = Fr::from_str("171").unwrap();
        let right = Fr::from_str("299").unwrap();
        let root = hasher.compress(&left, &right, Personalization::NoteCommitment);


        let c = CompressDemo::<Bls12> {
            params: Box::new(JubjubBls12::new()),
            left: Some(left),
            right: Some(right),
            root: Some(root)
        };


        let mut cs = TestConstraintSystem::<Bls12>::new();
        c.synthesize(&mut cs).unwrap();


        if (!cs.is_satisfied()) {
            let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
            assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
        }



    }

}
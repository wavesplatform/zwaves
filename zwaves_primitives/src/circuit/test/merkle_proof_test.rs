use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};

use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::PrimeField;
use rand::os::OsRng;
use rand::Rng;

use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use crate::circuit::merkle_proof;



#[derive(Clone)]
pub struct MerkleProofDemo<E: JubjubEngine> {
    pub params: Box<E::Params>,
    pub proof: Vec<(Option<E::Fr>, Option<bool>)>,
    pub leaf: Option<E::Fr>,
    pub root: Option<E::Fr>
}

impl <E: JubjubEngine> Circuit<E> for MerkleProofDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let root = AllocatedNum::alloc(cs.namespace(|| "signal public input root"), || self.root.ok_or(SynthesisError::AssignmentMissing))?;
        root.inputize(cs.namespace(|| "image inputize"));
        let leaf = AllocatedNum::alloc(cs.namespace(|| "signal public input leaf"), || self.leaf.ok_or(SynthesisError::AssignmentMissing))?;

        let proof : Vec<_>= self.proof.into_iter().enumerate().map(|e| {
            let (i, (s, r)) = e;
            let signal_s = AllocatedNum::alloc(cs.namespace(|| format!("signal public input sibling[{:?}]", i)), || s.ok_or(SynthesisError::AssignmentMissing)).unwrap();
            let signal_r = Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("signal public input path[{:?}]", i)), r).unwrap());
            (signal_s, signal_r)
        }).collect();

        let root_calculated = merkle_proof::merkle_proof(
            cs.namespace(|| "image_calculated <== merkle_proof(...)"),
            &proof,
            &leaf,
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
    pub fn test_merkle_proof_witness(){
        let hasher = PedersenHasherBls12::default();

        let proof_length = hasher.merkle_proof_defaults.len();
        let elements_len = 23;


        let elements : Vec<_> =  (0..elements_len).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
        
        let proof_defaults = hasher.merkle_proof_defaults.clone();
        let sibling = hasher.update_merkle_proof(&proof_defaults, 0, &elements).unwrap();
        let root = hasher.root(&sibling, elements_len, hasher.merkle_proof_defaults[0]).unwrap();

        let proof : Vec<_> = (0..proof_length).map( |i| {
            (Some(sibling[i]), Some((elements_len & (1<<i))!=0))
        }).collect();

        let c = MerkleProofDemo::<Bls12> {
            params: Box::new(JubjubBls12::new()),
            proof: proof,
            leaf: Some(hasher.merkle_proof_defaults[0]),
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
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::os::OsRng;
use rand::Rng;
use sapling_crypto::constants;

use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use zwaves_primitives::circuit::transactions;
use zwaves_primitives::transactions::NoteData;
use zwaves_primitives::fieldtools;


use blake2_rfc::blake2s::Blake2s;
use byteorder::{LittleEndian, WriteBytesExt};
use itertools::Itertools;


const MERKLE_PROOF_LEN:usize = 48;






pub fn alloc_note_data<E: JubjubEngine, CS:ConstraintSystem<E>>(
    mut cs: CS, 
    data: Option<NoteData<E>>) -> Result<transactions::Note<E>, SynthesisError> {
        Ok(match data {
            Some(data) => {
                transactions::Note {
                    asset_id: AllocatedNum::alloc(cs.namespace(|| "alloc asset_id"), || Ok(data.asset_id)).unwrap(),
                    amount: AllocatedNum::alloc(cs.namespace(|| "alloc amount"), || Ok(data.amount)).unwrap(),
                    native_amount: AllocatedNum::alloc(cs.namespace(|| "alloc native_amount"), || Ok(data.native_amount)).unwrap(),
                    txid: AllocatedNum::alloc(cs.namespace(|| "alloc txid"), || Ok(data.txid)).unwrap(),
                    owner: AllocatedNum::alloc(cs.namespace(|| "alloc owner"), || Ok(data.owner)).unwrap()
                }
            },
            None => {
                transactions::Note {
                    asset_id: AllocatedNum::alloc(cs.namespace(|| "alloc asset_id"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    amount: AllocatedNum::alloc(cs.namespace(|| "alloc amount"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    native_amount: AllocatedNum::alloc(cs.namespace(|| "alloc native_amount"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    txid: AllocatedNum::alloc(cs.namespace(|| "alloc txid"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    owner: AllocatedNum::alloc(cs.namespace(|| "alloc owner"), || Err(SynthesisError::AssignmentMissing)).unwrap()
                }
            }
        })
}





#[derive(Clone)]
pub struct Deposit<'a, E: JubjubEngine> {
    pub data: Option<NoteData<E>>,
    pub params: &'a E::Params
}



impl <'a, E: JubjubEngine> Circuit<E> for Deposit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {

        let out_note = alloc_note_data(cs.namespace(|| "alloc note data"), self.data.clone())?;
        let out_hash = transactions::note_hash(cs.namespace(|| "hashing input"), &out_note, self.params)?;

        
        out_hash.inputize(cs.namespace(|| "inputize out_hash"))?;
        out_note.asset_id.inputize(cs.namespace(|| "inputize asset_id"))?;
        out_note.amount.inputize(cs.namespace(|| "inputize amount"))?;
        out_note.native_amount.inputize(cs.namespace(|| "inputize native_amount"))?;

        Ok(())
    }
}


#[cfg(test)]
mod circuit_test {
    use super::*;
    use sapling_crypto::circuit::test::TestConstraintSystem;
    use sapling_crypto::jubjub::{JubjubBls12, JubjubParams};
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use pairing::{Field};
    use rand::os::OsRng;
    use rand::Rng;

    use zwaves_primitives::fieldtools;

    #[test]
    fn test_deposit() -> Result<(), SynthesisError> {
        let rng = &mut OsRng::new().unwrap();
        let params = JubjubBls12::new();


        let circuit = Deposit::<Bls12> {data: None, params: &params };
        let zkparams = generate_random_parameters(circuit, rng)?;

        let pvk = prepare_verifying_key(&zkparams.vk);

        let note = NoteData::<Bls12> {
            asset_id: Fr::one(),
            amount: Fr::one(),
            native_amount: Fr::one(),
            txid: rng.gen(),
            owner: rng.gen()
        };

        let note_hash = zwaves_primitives::transactions::note_hash(&note, &params);

        let circuit = Deposit::<Bls12> {
            data: Some(note.clone()),
            params: &params
        };

        let proof = create_random_proof(circuit, &zkparams, rng)?;

        let result = verify_proof(
            &pvk,
            &proof,
            &[note_hash, note.asset_id, note.amount, note.native_amount]
        ).unwrap();
        assert!(result, "Proof is correct");
        Ok(())
    }

    #[test]
    fn test_deposit_witness() -> Result<(), SynthesisError> {

        let rng = &mut OsRng::new().unwrap();
        let params = JubjubBls12::new();

        let note = NoteData::<Bls12> {
            asset_id: Fr::one(),
            amount: Fr::one(),
            native_amount: Fr::one(),
            txid: rng.gen(),
            owner: rng.gen()
        };

        let note_hash = zwaves_primitives::transactions::note_hash(&note, &params);

        let circuit = Deposit::<Bls12> {
            data: Some(note.clone()),
            params: &params
        };
    
    
        let mut cs = TestConstraintSystem::<Bls12>::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(cs.inputs[1].0==note_hash, "note hash not satisfied");
    
        if !cs.is_satisfied() {
            let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
            assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
        }

 

        Ok(())
    }

}



#[derive(Clone)]
pub struct TransferData<E: JubjubEngine> {
    pub in_note: [NoteData<E>; 2],
    pub in_nullifier: [E::Fr; 2],
    pub in_proof: [([E::Fr; MERKLE_PROOF_LEN], u64); 2],
    pub out_note: [NoteData<E>; 2],
    pub sk: E::Fr
}

#[derive(Clone)]
pub struct Transfer<E: JubjubEngine> {
    pub data: Option<TransferData<E>>,
    pub params: Box<E::Params>
}


impl <E: JubjubEngine> Circuit<E> for Transfer<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let in_note = match self.data {
            Some(ref data) => [
                alloc_note_data(cs.namespace(|| "alloc in_note[0]"), Some(data.in_note[0].clone())).unwrap(),
                alloc_note_data(cs.namespace(|| "alloc in_note[1]"), Some(data.in_note[1].clone())).unwrap()
            ],
            None => [
                alloc_note_data(cs.namespace(|| "alloc in_note[0]"), None).unwrap(),
                alloc_note_data(cs.namespace(|| "alloc in_note[1]"), None).unwrap()
            ]
        };

        let out_note = match self.data {
            Some(ref data) => [
                alloc_note_data(cs.namespace(|| "alloc out_note[0]"), Some(data.out_note[0].clone())).unwrap(),
                alloc_note_data(cs.namespace(|| "alloc out_note[1]"), Some(data.out_note[1].clone())).unwrap()
            ],
            None => [
                alloc_note_data(cs.namespace(|| "alloc out_note[0]"), None).unwrap(),
                alloc_note_data(cs.namespace(|| "alloc out_note[1]"), None).unwrap()
            ]
        };

        Ok(())
    }
}
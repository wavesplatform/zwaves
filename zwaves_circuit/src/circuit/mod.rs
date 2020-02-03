use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{Boolean, AllocatedBit};
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
use arrayvec::ArrayVec;

pub const MERKLE_PROOF_LEN:usize = 48;
pub static FEE:&str = "1";






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

pub fn alloc_proof_data<E: JubjubEngine, CS:ConstraintSystem<E>>(
    mut cs: CS, 
    data: Option<Vec<(E::Fr, bool)>>) -> Result<Vec<(AllocatedNum<E>, Boolean)>, SynthesisError> {
    Ok(match data {
        Some(data) => {
            data.iter().enumerate().map(|(i, (sibling, path))| 
                (
                    AllocatedNum::alloc(cs.namespace(|| format!("sibling[{}]", i)), || Ok(sibling.clone())).unwrap(),
                    Boolean::Is(AllocatedBit::alloc(cs.namespace(|| format!("path[{}]", i)), Some(path.clone())).unwrap())
                )
            ).collect::<Vec<(AllocatedNum<E>, Boolean)>>()
        },
        None => {
            (0..MERKLE_PROOF_LEN).map(|i| 
                (
                    AllocatedNum::alloc(cs.namespace(|| format!("sibling[{}]", i)), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    Boolean::Is(AllocatedBit::alloc(cs.namespace(|| format!("path[{}]", i)), None).unwrap())
                )
            ).collect::<Vec<(AllocatedNum<E>, Boolean)>>()
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


/*
    mut cs: CS,
    in_note: [Note<E>; 2],
    in_nullifier: [AllocatedNum<E>; 2],
    in_proof: [&[(AllocatedNum<E>, Boolean)]; 2],

    out_hash: [AllocatedNum<E>; 2],
    out_note: [Note<E>; 2],

    root_hash: AllocatedNum<E>,
    sk: AllocatedNum<E>,
    params: &E::Params
*/


#[derive(Clone)]
pub struct Transfer<'a, E: JubjubEngine> {
    pub in_note: [Option<NoteData<E>>; 2],
    pub out_note: [Option<NoteData<E>>; 2],
  
    pub in_proof: [Option<Vec<(E::Fr, bool)>>; 2],
    
    pub root_hash: Option<E::Fr>,
    pub sk: Option<E::Fr>,

    pub params: &'a E::Params
}


impl <'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let in_note = (0..2).map(|i| alloc_note_data(cs.namespace(|| format!("alloc note data in_note[{}]", i)), self.in_note[i].clone()))
            .collect::<Result<ArrayVec<[transactions::Note<E>;2]>, SynthesisError>>()?;
        
        let out_note = (0..2).map(|i| alloc_note_data(cs.namespace(|| format!("alloc note data out_note[{}]", i)), self.out_note[i].clone()))
            .collect::<Result<ArrayVec<[transactions::Note<E>;2]>, SynthesisError>>()?;

        let in_proof = (0..2).map(|i| alloc_proof_data(cs.namespace(|| format!("alloc proof data in_proof[{}]", i)), self.in_proof[i].clone()))
        .collect::<Result<ArrayVec<[Vec<(AllocatedNum<E>, Boolean)>;2]>, SynthesisError>>()?;

        let root_hash = AllocatedNum::alloc(cs.namespace(|| "alloc root_hash"), || self.root_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let sk = AllocatedNum::alloc(cs.namespace(|| "alloc sk"), || self.sk.ok_or(SynthesisError::AssignmentMissing))?;

        let fee = <E::Fr as PrimeField>::from_str(FEE).unwrap();
        let (out_hash, nf) = transactions::transfer(cs.namespace(|| "transfer"),
            &in_note,
            &in_proof,
            &out_note,
            &root_hash,
            &sk,
            &fee,
            self.params)?;

        root_hash.inputize(cs.namespace(|| "root_hash inputize")).unwrap();

        out_hash.iter().enumerate().for_each(|(i, n)| 
            n.inputize(cs.namespace(|| format!("inputize out_hash[{}]", i))).unwrap()
        );

        nf.iter().enumerate().for_each(|(i, n)| 
            n.inputize(cs.namespace(|| format!("inputize nf[{}]", i))).unwrap()
        );
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


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

pub fn alloc_fr_vec<E: JubjubEngine, CS:ConstraintSystem<E>>(
    mut cs: CS, 
    data: Option<Vec<E::Fr>>,
    size: usize) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    Ok(match data {
        Some(data) => {
            assert!(data.len() == size, "vector length should be equal default length");
            data.iter().enumerate().map(|(i, item)| 
                AllocatedNum::alloc(cs.namespace(|| format!("item[{}]", i)), || Ok(item.clone())).unwrap()
            ).collect::<Vec<_>>()
        },
        None => (0..size).map(|i| AllocatedNum::alloc(cs.namespace(|| format!("item[{}]", i)), || Err(SynthesisError::AssignmentMissing)).unwrap()).collect::<Vec<_>>()
    })
}


#[derive(Clone)]
pub struct Transfer<'a, E: JubjubEngine> {
    pub receiver: Option<E::Fr>,
    pub in_note: [Option<NoteData<E>>; 2],
    pub in_proof: [Option<Vec<(E::Fr, bool)>>; 2],
    pub out_note: [Option<NoteData<E>>; 2],
    pub root_hash: Option<E::Fr>,
    pub sk: Option<E::Fr>,
    pub packed_asset: Option<E::Fr>,
    pub params: &'a E::Params
}


impl <'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let receiver = AllocatedNum::alloc(cs.namespace(|| "allocate receiver"), || self.receiver.ok_or(SynthesisError::AssignmentMissing)).unwrap();
        receiver.inputize(cs.namespace(|| "inputize receiver")).unwrap();


        let in_note = (0..2).map(|i| alloc_note_data(cs.namespace(|| format!("alloc note data in_note[{}]", i)), self.in_note[i].clone()))
            .collect::<Result<ArrayVec<[transactions::Note<E>;2]>, SynthesisError>>()?;
        
        let out_note = (0..2).map(|i| alloc_note_data(cs.namespace(|| format!("alloc note data out_note[{}]", i)), self.out_note[i].clone()))
            .collect::<Result<ArrayVec<[transactions::Note<E>;2]>, SynthesisError>>()?;

        let in_proof = (0..2).map(|i| alloc_proof_data(cs.namespace(|| format!("alloc proof data in_proof[{}]", i)), self.in_proof[i].clone()))
        .collect::<Result<ArrayVec<[Vec<(AllocatedNum<E>, Boolean)>;2]>, SynthesisError>>()?;

        let root_hash = AllocatedNum::alloc(cs.namespace(|| "alloc root_hash"), || self.root_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let sk = AllocatedNum::alloc(cs.namespace(|| "alloc sk"), || self.sk.ok_or(SynthesisError::AssignmentMissing))?;

        let packed_asset = AllocatedNum::alloc(cs.namespace(|| "alloc packed_asset"), || self.packed_asset.ok_or(SynthesisError::AssignmentMissing))?;

        let (out_hash, nf) = transactions::transfer(cs.namespace(|| "transfer"),
            &in_note,
            &in_proof,
            &out_note,
            &root_hash,
            &sk,
            &packed_asset,
            self.params)?;

        root_hash.inputize(cs.namespace(|| "root_hash inputize")).unwrap();
        packed_asset.inputize(cs.namespace(|| "packed asset inputize")).unwrap();

        out_hash.iter().enumerate().for_each(|(i, n)| 
            n.inputize(cs.namespace(|| format!("inputize out_hash[{}]", i))).unwrap()
        );

        nf.iter().enumerate().for_each(|(i, n)| 
            n.inputize(cs.namespace(|| format!("inputize nf[{}]", i))).unwrap()
        );
        Ok(())
    }

}


#[derive(Clone)]
pub struct UtxoAccumulator<'a, E: JubjubEngine> {
    pub note_hashes: [Option<E::Fr>; 2],
    pub index: Option<E::Fr>,
    pub old_proof: Option<Vec<E::Fr>>,
    pub new_proof: Option<Vec<E::Fr>>,
    pub params: &'a E::Params
}



impl <'a, E: JubjubEngine> Circuit<E> for UtxoAccumulator<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let note_hashes = (0..2).map(|i| {
            let n = AllocatedNum::alloc(cs.namespace(|| format!("alloc note_hashes[{}]", i)), || self.note_hashes[i].ok_or(SynthesisError::AssignmentMissing)).unwrap();
            n.inputize(cs.namespace(|| format!("inputize note_hashes[{}]", i))).unwrap();
            n
        }).collect::<Vec<_>>();


        let index = AllocatedNum::alloc(cs.namespace(|| "allocate index"), || self.index.ok_or(SynthesisError::AssignmentMissing)).unwrap();
        index.inputize(cs.namespace(|| "inputize index")).unwrap();

        let old_proof = alloc_fr_vec(cs.namespace(|| "alloc old_proof"), self.old_proof, MERKLE_PROOF_LEN-1)?;
        let new_proof = alloc_fr_vec(cs.namespace(|| "alloc new_proof"), self.new_proof, MERKLE_PROOF_LEN-1)?;

        let (old_root, new_root) = transactions::utxo_accumulator(cs.namespace(|| "process dual merkle proofs"), &note_hashes, &index, &old_proof, &new_proof, self.params)?;
        
        old_root.inputize(cs.namespace(|| "inputize old_root"))?;
        new_root.inputize(cs.namespace(|| "inputize new_root"))?;

        Ok(())
    }
}
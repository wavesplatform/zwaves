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
use zwaves_primitives::circuit::note;
use zwaves_primitives::circuit::transactions;
use zwaves_primitives::fieldtools;


use blake2_rfc::blake2s::Blake2s;
use byteorder::{LittleEndian, WriteBytesExt};


use itertools::Itertools;


const MERKLE_PROOF_LEN:usize = 48;


#[derive(Clone)]
pub struct NoteData<E: JubjubEngine> {
    pub asset_id: E::Fr,
    pub amount: E::Fr,
    pub native_amount: E::Fr,
    pub txid: E::Fr,
    pub owner: E::Fr
}





pub fn note_hash<E: JubjubEngine>(data: &NoteData<E>, params: &E::Params) -> E::Fr {


    let total_bits = [data.asset_id, data.amount, data.native_amount, data.txid, data.owner].iter()
    .zip([64, 64, 64, E::Fr::NUM_BITS, E::Fr::NUM_BITS].iter())
        .flat_map(|(e, &sz)| fieldtools::fr_to_repr_bool(e).take(sz as usize))
        .collect::<Vec<bool>>();
    pedersen_hash::<E, _>(Personalization::NoteCommitment, total_bits.into_iter(), &params).into_xy().0
}

pub fn nullifier<E: JubjubEngine>(note_hash: &E::Fr, sk: &E::Fr) -> E::Fr {
    let mut h = Blake2s::with_params(32, &[], &[], constants::PRF_NF_PERSONALIZATION);
    let data = fieldtools::fr_to_repr_u8(note_hash).into_iter().chain(fieldtools::fr_to_repr_u8(sk)).collect::<Vec<u8>>();
    h.update(&data);

    let mut res = E::Fr::char().clone();

    let hash_result = h.finalize();
    
    let limbs = hash_result.as_ref().iter().chunks(8).into_iter()
        .map(|e| e.enumerate().fold(0u64, |x, (i, &y)| x + ((y as u64)<< (i*8)))).collect::<Vec<u64>>();

    res.as_mut().iter_mut().zip(limbs.iter()).for_each(|(target, &value)| *target = value);

    fieldtools::affine(res)
}


pub fn alloc_note_data<E: JubjubEngine, CS:ConstraintSystem<E>, R: ::rand::Rng>(
    rng: &mut R,
    mut cs: CS, 
    data: Option<NoteData<E>>) -> Result<note::Note<E>, SynthesisError> {
        Ok(match data {
            Some(data) => {
                note::Note {
                    asset_id: AllocatedNum::alloc(cs.namespace(|| "alloc asset_id"), || Ok(data.asset_id)).unwrap(),
                    amount: AllocatedNum::alloc(cs.namespace(|| "alloc amount"), || Ok(data.amount)).unwrap(),
                    native_amount: AllocatedNum::alloc(cs.namespace(|| "alloc native_amount"), || Ok(data.native_amount)).unwrap(),
                    txid: AllocatedNum::alloc(cs.namespace(|| "alloc txid"), || Ok(data.txid)).unwrap(),
                    owner: AllocatedNum::alloc(cs.namespace(|| "alloc owner"), || Ok(data.owner)).unwrap()
                }
            },
            None => {
                note::Note {
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
pub struct Deposit<E: JubjubEngine> {
    pub data: Option<NoteData<E>>,
    pub params: Box<E::Params>
}



impl <E: JubjubEngine> Circuit<E> for Deposit<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let rng = &mut OsRng::new().unwrap();

        let out_note = alloc_note_data(rng, cs.namespace(|| "alloc note data"), self.data.clone())?;
        let out_hash = note::note_hash(cs.namespace(|| "hashing input"), &out_note, &self.params)?;

        out_note.asset_id.inputize(cs.namespace(|| "inputize asset_id"))?;
        out_note.amount.inputize(cs.namespace(|| "inputize amount"))?;
        out_note.native_amount.inputize(cs.namespace(|| "inputize native_amount"))?;
        out_hash.inputize(cs.namespace(|| "inputize out_hash"))?;

        Ok(())
    }
}



// in_note: [note::Note<E>; 2],
// in_nullifier: [AllocatedNum<E>; 2],
// in_proof: [&[(AllocatedNum<E>, Boolean)]; 2],

// out_hash: [AllocatedNum<E>; 2],
// out_note: [note::Note<E>; 2],

// root_hash: AllocatedNum<E>,
// sk: AllocatedNum<E>,






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
        let rng = &mut OsRng::new().unwrap();
        let in_note = match self.data {
            Some(ref data) => [
                alloc_note_data(rng, cs.namespace(|| "alloc in_note[0]"), Some(data.in_note[0].clone())).unwrap(),
                alloc_note_data(rng, cs.namespace(|| "alloc in_note[1]"), Some(data.in_note[1].clone())).unwrap()
            ],
            None => [
                alloc_note_data(rng, cs.namespace(|| "alloc in_note[0]"), None).unwrap(),
                alloc_note_data(rng, cs.namespace(|| "alloc in_note[1]"), None).unwrap()
            ]
        };

        let out_note = match self.data {
            Some(ref data) => [
                alloc_note_data(rng, cs.namespace(|| "alloc out_note[0]"), Some(data.out_note[0].clone())).unwrap(),
                alloc_note_data(rng, cs.namespace(|| "alloc out_note[1]"), Some(data.out_note[1].clone())).unwrap()
            ],
            None => [
                alloc_note_data(rng, cs.namespace(|| "alloc out_note[0]"), None).unwrap(),
                alloc_note_data(rng, cs.namespace(|| "alloc out_note[1]"), None).unwrap()
            ]
        };

        Ok(())
    }
}
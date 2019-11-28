use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField};
use rand::os::OsRng;
use rand::Rng;
use sapling_crypto::constants;

use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use zwaves_primitives::circuit::note;
use zwaves_primitives::circuit::transactions;
use zwaves_primitives::bit_iterator::BitIteratorLe;
use zwaves_primitives::byte_iterator::ByteIteratorLe;

use blake2_rfc::blake2s::Blake2s;
use byteorder::{LittleEndian, WriteBytesExt};


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
    let mut total_bits : Vec<bool> = vec![];
    total_bits.extend(BitIteratorLe::new(data.asset_id.into_repr()).take(64));
    total_bits.extend(BitIteratorLe::new(data.amount.into_repr()).take(64));
    total_bits.extend(BitIteratorLe::new(data.native_amount.into_repr()).take(64));
    total_bits.extend(BitIteratorLe::new(data.txid.into_repr()).take(E::Fr::NUM_BITS as usize));
    total_bits.extend(BitIteratorLe::new(data.owner.into_repr()).take(E::Fr::NUM_BITS as usize));
    pedersen_hash::<E, _>(Personalization::NoteCommitment, total_bits.into_iter(), &params).into_xy().0
}

pub fn nullifier<E: JubjubEngine>(note_hash: &E::Fr, sk: &E::Fr) -> E::Fr {
    let mut h = Blake2s::with_params(32, &[], &[], constants::PRF_NF_PERSONALIZATION);
    let mut data: Vec<_> = ByteIteratorLe::new(note_hash.into_repr()).collect();
    
    

    h.update(&data);

    let hash_result = h.finalize();
    // TODO convert hash_result into E::Fr
    E::Fr::from_str("1").unwrap()

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
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12, FixedGenerators};
use pairing::{PrimeField, PrimeFieldRepr};
use sapling_crypto::constants;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use sapling_crypto::jubjub::edwards::{Point};
use sapling_crypto::jubjub::{PrimeOrder, Unknown};
use crate::fieldtools;
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
        .flat_map(|(e, &sz)| fieldtools::fr_to_repr_bool(e).into_iter().take(sz as usize))
        .collect::<Vec<bool>>();
    pedersen_hash::<E, _>(Personalization::NoteCommitment, total_bits.into_iter(), &params).into_xy().0
}

pub fn pubkey<E: JubjubEngine>(sk: &E::Fr, params: &E::Params) -> E::Fr {
    params.generator(FixedGenerators::SpendingKeyGenerator).mul(fieldtools::f2f::<E::Fr, E::Fs>(sk), params).into_xy().0
}

pub fn edh<E: JubjubEngine>(pk_x: &E::Fr, sk: &E::Fr, params: &E::Params) -> Option<E::Fr> {
    let p = Point::<E, Unknown>::get_for_x(pk_x.clone(), params)?;
    Some(p.mul(fieldtools::f2f::<E::Fr, E::Fs>(sk), params).into_xy().0)
}

pub fn nullifier<E: JubjubEngine>(note_hash: &E::Fr, sk: &E::Fr, params: &E::Params) -> E::Fr {
    
    let sk_multiplied = params.generator(FixedGenerators::ProofGenerationKey).mul(fieldtools::f2f::<E::Fr, E::Fs>(sk), params).into_xy().0;

    let mut h = Blake2s::with_params(32, &[], &[], constants::PRF_NF_PERSONALIZATION);


    let data = fieldtools::fr_to_repr_u8(note_hash).into_iter().chain(fieldtools::fr_to_repr_u8(&sk_multiplied)).collect::<Vec<u8>>();
    h.update(&data);

    let mut res = E::Fr::char();

    let hash_result = h.finalize();
    
    let limbs = hash_result.as_ref().iter().chunks(8).into_iter()
        .map(|e| e.enumerate().fold(0u64, |x, (i, &y)| x + ((y as u64)<< (i*8)))).collect::<Vec<u64>>();

    res.as_mut().iter_mut().zip(limbs.iter()).for_each(|(target, &value)| *target = value);

    fieldtools::affine(res)
}

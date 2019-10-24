
use pairing::{Engine, Field, PrimeField, PrimeFieldRepr, BitIterator};

use bellman::{SynthesisError, ConstraintSystem, LinearCombination, Variable};

use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};



pub struct Note<E: JubjubEngine> {
    assetId: AllocatedNum<E>,
    amount: AllocatedNum<E>,
    nativeAmount: AllocatedNum<E>,
    txid: AllocatedNum<E>,
    owner: AllocatedNum<E>
}


pub fn note_hash<E: JubjubEngine, CS>(
    mut cs: CS,
    note: Note,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    let mut total_bits = vec![];
    total_bits.extend(note.assetId.into_bits_le_limited(cs.namespace(|| "bitify assetId into 16 bits"), 16)?);
    total_bits.extend(note.amount.into_bits_le_limited(cs.namespace(|| "bitify amount into 64 bits"), 64)?);
    total_bits.extend(note.nativeAmount.into_bits_le_limited(cs.namespace(|| "bitify nativeAmount into 64 bits"), 64)?);
    total_bits.extend(note.txid.into_bits_le_limited(cs.namespace(|| "bitify txId into 254 bits"), 254)?);
    total_bits.extend(note.owner.into_bits_le_strict(cs.namespace(|| "bitify owner"))?);
    assert_eq!(total_bits.len()==653);

    let res = pedersen_hash::pedersen_hash(
                cs.namespace(|| "res <== pedersen_hash(total_bits)"),
                pedersen_hash::Personalization::NoteCommitment,
                &total_bits,
                params
            )?.get_x().clone();

    Ok(res);
}

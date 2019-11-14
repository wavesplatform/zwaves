use bellman::{SynthesisError, ConstraintSystem};

use sapling_crypto::jubjub::{JubjubEngine};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum};

use crate::circuit::bitify::from_bits_le_to_num_limited;

pub struct Note<E: JubjubEngine> {
    pub asset_id: AllocatedNum<E>,       // 64 bits
    pub amount: AllocatedNum<E>,        // 64 bits
    pub native_amount: AllocatedNum<E>,  // 64 bits
    pub txid: AllocatedNum<E>,          // 254 bits
    pub owner: AllocatedNum<E>          // 255 bits
}


pub fn asset_unpack<E: JubjubEngine, CS>(
    mut cs: CS,
    packed_asset: &AllocatedNum<E>
) -> Result<(AllocatedNum<E>, AllocatedNum<E>, AllocatedNum<E>), SynthesisError>
where CS: ConstraintSystem<E>
{
    let packed_asset_bits = packed_asset.into_bits_le_limited(cs.namespace(|| "bitify packed_asset"), 192)?;

    let asset_id = from_bits_le_to_num_limited(cs.namespace(|| "preparing asset_id"), &packed_asset_bits[0..64], 64)?;
    let amount = from_bits_le_to_num_limited(cs.namespace(|| "preparing amount"), &packed_asset_bits[64..128], 64)?;
    let native_amount = from_bits_le_to_num_limited(cs.namespace(|| "preparing native_amount"), &packed_asset_bits[128..196], 64)?;

    Ok((asset_id, amount, native_amount))
}


pub fn note_hash<E: JubjubEngine, CS>(
    mut cs: CS,
    note: &Note<E>,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    let mut total_bits = vec![];
    total_bits.extend(note.asset_id.into_bits_le_limited(cs.namespace(|| "bitify assetId into 64 bits"), 64)?);
    total_bits.extend(note.amount.into_bits_le_limited(cs.namespace(|| "bitify amount into 64 bits"), 64)?);
    total_bits.extend(note.native_amount.into_bits_le_limited(cs.namespace(|| "bitify nativeAmount into 64 bits"), 64)?);
    total_bits.extend(note.txid.into_bits_le_limited(cs.namespace(|| "bitify txId into 254 bits"), 254)?);
    total_bits.extend(note.owner.into_bits_le_strict(cs.namespace(|| "bitify owner"))?);
    assert!(total_bits.len()==701);

    let res = pedersen_hash::pedersen_hash(
                cs.namespace(|| "res <== pedersen_hash(total_bits)"),
                pedersen_hash::Personalization::NoteCommitment,
                &total_bits,
                params
            )?.get_x().clone();

    Ok(res)
}

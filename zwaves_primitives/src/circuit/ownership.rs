use bellman::{SynthesisError, ConstraintSystem};

use sapling_crypto::jubjub::{FixedGenerators, JubjubEngine};
use sapling_crypto::circuit::{ecc, blake2s};
use sapling_crypto::circuit::num::{AllocatedNum};
use sapling_crypto::circuit::boolean::{Boolean};
use sapling_crypto::constants;

use crate::circuit::bitify::from_bits_le_to_num;

pub fn pubkey<E: JubjubEngine, CS>(
    mut cs: CS,
    sk: &[Boolean],
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    let res = ecc::fixed_base_multiplication(
        cs.namespace(|| "public key computation"),
        FixedGenerators::SpendingKeyGenerator,
        &sk,
        params
    )?.get_x().clone();

    Ok(res)
}





pub fn nullifier<E: JubjubEngine, CS>(
    mut cs: CS,
    note_hash: &AllocatedNum<E>,
    sk: &[Boolean],
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    let note_hash = note_hash.into_bits_le_strict(cs.namespace(|| "note_hash bitification"))?;
    
    let sk_repr = ecc::fixed_base_multiplication(
        cs.namespace(|| "public key computation"),
        FixedGenerators::ProofGenerationKey,
        &sk,
        params
    )?.get_x().into_bits_le_strict(cs.namespace(|| "priv key repr bitification"))?;

    let mut nf_preimage = vec![];
    nf_preimage.extend(note_hash);
    nf_preimage.extend(sk_repr);

    let nf_bitrepr = blake2s::blake2s(
        cs.namespace(|| "nf computation"),
        &nf_preimage,
        constants::PRF_NF_PERSONALIZATION
    )?;

    let nf = from_bits_le_to_num(cs.namespace(|| "compress nf_bitrepr"), &nf_bitrepr)?;
    Ok(nf)
}
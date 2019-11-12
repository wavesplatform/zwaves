
use pairing::{Engine, Field, PrimeField, PrimeFieldRepr, BitIterator};

use bellman::{SynthesisError, ConstraintSystem, LinearCombination, Variable};

use sapling_crypto::jubjub::{FixedGenerators, JubjubEngine, JubjubParams, JubjubBls12, edwards, PrimeOrder};
use sapling_crypto::circuit::{pedersen_hash, ecc, blake2s};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use sapling_crypto::constants;

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


pub fn from_bits_le_to_num<E: JubjubEngine, CS>(
    mut cs: CS,
    bits: &[Boolean]
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    assert!(bits.len() == E::Fr::NUM_BITS as usize);

    let mut num = Num::<E>::zero();
    let mut coeff = E::Fr::one();

    for bit in bits.into_iter() {
            num = num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff.double();
    }

    let res = AllocatedNum::alloc(cs.namespace(|| "packed bits"), || num.get_value().ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce(|| "checking resulting variable", |_| num.lc(E::Fr::one()), |lc| lc + CS::one(), |lc| lc + res.get_variable());
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
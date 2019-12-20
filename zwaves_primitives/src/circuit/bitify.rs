
use pairing::{Field, PrimeField};

use bellman::{SynthesisError, ConstraintSystem};

use sapling_crypto::jubjub::{JubjubEngine};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{Boolean};




pub fn from_bits_le_to_num<E: JubjubEngine, CS>(
    mut cs: CS,
    bits: &[Boolean]
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{

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


pub fn from_bits_le_to_num_limited<E: JubjubEngine, CS>(
    mut cs: CS,
    bits: &[Boolean],
    len: usize
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    assert!(bits.len() == len);

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
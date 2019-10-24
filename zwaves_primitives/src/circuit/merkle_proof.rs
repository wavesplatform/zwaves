
use pairing::{Engine, Field, PrimeField, PrimeFieldRepr, BitIterator};

use bellman::{SynthesisError, ConstraintSystem, LinearCombination, Variable};

use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};




pub fn compress<E: JubjubEngine, CS>(
    mut cs: CS,
    personalization: pedersen_hash::Personalization,
    left:AllocatedNum<E>,
    right:AllocatedNum<E>,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
  let left_bits = left.into_bits_le_strict(cs.namespace(|| "left_bits <== bitify(left)"))?;
  let right_bits = right.into_bits_le_strict(cs.namespace(|| "right_bits <== bitify(right)"))?;
  let mut total_bits = vec![];
  total_bits.extend(left_bits);
  total_bits.extend(right_bits);
  let res = pedersen_hash::pedersen_hash(
            cs.namespace(|| "res <== pedersen_hash(total_bits)"),
            personalization,
            &total_bits,
            params
        )?.get_x().clone();
  Ok(res)
}

pub fn merkle_proof<E: JubjubEngine, CS>(
    mut cs: CS,
    proof: &[(AllocatedNum<E>, Boolean)],
    leaf: AllocatedNum<E>,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
  let mut cur = leaf;

  for (i, e) in proof.into_iter().enumerate() {
    let cur_is_right = e.1.clone();
    let path_element = e.0.clone();

    let (xl, xr) = AllocatedNum::conditionally_reverse(
        cs.namespace(|| "conditional reversal of preimage"),
        &cur,
        &path_element,
        &cur_is_right
    )?;

    cur = compress(cs.namespace(|| "Merkle hash layer"), pedersen_hash::Personalization::MerkleTree(i as usize), xl, xr, params)?;
  }
  Ok(cur)
}
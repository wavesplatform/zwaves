

use bellman::{SynthesisError, ConstraintSystem};

use sapling_crypto::jubjub::{JubjubEngine};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum};
use sapling_crypto::circuit::boolean::{Boolean};




pub fn compress<E: JubjubEngine, CS>(
    mut cs: CS,
    personalization: pedersen_hash::Personalization,
    left:&AllocatedNum<E>,
    right:&AllocatedNum<E>,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
  let left_bits = left.into_bits_le_strict(cs.namespace(|| "left_bits <== bitify(left)"))?;
  let right_bits = right.into_bits_le_strict(cs.namespace(|| "right_bits <== bitify(right)"))?;


  let res = pedersen_hash::pedersen_hash(
            cs.namespace(|| "res <== pedersen_hash(total_bits)"),
            personalization,
            left_bits.iter().chain(right_bits.iter()).cloned().collect::<Vec<_>>().as_slice(),
            params
        )?.get_x().clone();
  Ok(res)
}

pub fn merkle_proof<E: JubjubEngine, CS>(
    mut cs: CS,
    proof: &[(AllocatedNum<E>, Boolean)],
    leaf: &AllocatedNum<E>,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
  let mut cur : AllocatedNum<E> = leaf.clone();

  for (i, e) in proof.into_iter().enumerate() {
    let cur_is_right = e.1.clone();
    let path_element = e.0.clone();

    let (xl, xr) = AllocatedNum::conditionally_reverse(
        cs.namespace(|| format!("conditional reversal of preimage [{}]", i)),
        &cur,
        &path_element,
        &cur_is_right
    )?;

    cur = compress(cs.namespace(|| format!("Merkle hash layer [{}]", i)), pedersen_hash::Personalization::MerkleTree(i as usize), &xl, &xr, params)?;
  }
  Ok(cur)
}


pub fn merkle_proof_shifted<E: JubjubEngine, CS>(
    mut cs: CS,
    proof: &[(AllocatedNum<E>, Boolean)],
    leaf: &AllocatedNum<E>,
    shift: usize,
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
where CS: ConstraintSystem<E>
{
    let mut cur : AllocatedNum<E> = leaf.clone();

    for (i, e) in proof.into_iter().enumerate() {
        let cur_is_right = e.1.clone();
        let path_element = e.0.clone();

        let (xl, xr) = AllocatedNum::conditionally_reverse(
            cs.namespace(|| format!("conditional reversal of preimage [{}]", i)),
            &cur,
            &path_element,
            &cur_is_right
        )?;

        cur = compress(cs.namespace(|| format!("Merkle hash layer [{}]", i)), pedersen_hash::Personalization::MerkleTree(i as usize + shift), &xl, &xr, params)?;
    }
    Ok(cur)
}
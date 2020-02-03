
use pairing::{PrimeField, Field};
use bellman::{SynthesisError, ConstraintSystem};
use sapling_crypto::jubjub::{FixedGenerators, JubjubEngine};
use sapling_crypto::jubjub::fs::{Fs, FsRepr};

use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{Boolean, AllocatedBit};
use sapling_crypto::circuit::{ecc, blake2s, pedersen_hash};
use sapling_crypto::constants;

use crate::circuit::bitify::{from_bits_le_to_num_limited, from_bits_le_to_num};
use crate::circuit::{merkle_proof};

use arrayvec::ArrayVec;

pub struct Note<E: JubjubEngine> {
    pub asset_id: AllocatedNum<E>,       // 64 bits
    pub amount: AllocatedNum<E>,        // 64 bits
    pub native_amount: AllocatedNum<E>,  // 64 bits
    pub txid: AllocatedNum<E>,          // 255 bits
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
    total_bits.extend(note.txid.into_bits_le_strict(cs.namespace(|| "bitify txId"))?);
    total_bits.extend(note.owner.into_bits_le_strict(cs.namespace(|| "bitify owner"))?);
    assert!(total_bits.len()==702);

    let res = pedersen_hash::pedersen_hash(
                cs.namespace(|| "res <== pedersen_hash(total_bits)"),
                pedersen_hash::Personalization::NoteCommitment,
                &total_bits,
                params
            )?.get_x().clone();

    Ok(res)
}


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
    nh: &AllocatedNum<E>,
    sk: &[Boolean],
    params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
{
    let nh = nh.into_bits_le_strict(cs.namespace(|| "note_hash bitification"))?;
    
    let sk_point = ecc::fixed_base_multiplication(
        cs.namespace(|| "public key computation"),
        FixedGenerators::ProofGenerationKey,
        &sk,
        params
    )?;

    let sk_repr = sk_point.get_x();

    
    let sk_bits = sk_repr.into_bits_le_strict(cs.namespace(|| "priv key repr bitification"))?;

    let mut nf_preimage = vec![];
    let nh_len = nh.len();
    let sk_repr_len = sk_bits.len();
    nf_preimage.extend(nh);
    nf_preimage.extend((0..256-nh_len).map(|_| Boolean::Constant(false) ));
    nf_preimage.extend(sk_bits);
    nf_preimage.extend((0..256-sk_repr_len).map(|_| Boolean::Constant(false) ));

    let nf_bitrepr = blake2s::blake2s(
        cs.namespace(|| "nf computation"),
        &nf_preimage,
        constants::PRF_NF_PERSONALIZATION
    )?;


    let nf = from_bits_le_to_num(cs.namespace(|| "compress nf_bitrepr"), &nf_bitrepr)?;
    Ok(nf)
}



pub fn transfer<E: JubjubEngine, CS>(
    mut cs: CS,
    in_note: &[Note<E>],
    in_proof: &[Vec<(AllocatedNum<E>, Boolean)>],
    out_note: &[Note<E>],
    root_hash: &AllocatedNum<E>,
    sk: &AllocatedNum<E>,
    fee: &E::Fr,
    params: &E::Params
) -> Result<(ArrayVec<[AllocatedNum<E>; 2]>, ArrayVec<[AllocatedNum<E>; 2]>), SynthesisError>
    where CS: ConstraintSystem<E>
{
    assert!(in_note.len()==2, "in_note length should be equal 2");
    assert!(in_proof.len()==2, "in_proof length should be equal 2");
    assert!(out_note.len()==2, "out_note length should be equal 2");
    assert!(in_proof[0].len() == in_proof[1].len(), "vectors in proof should be the same length");
    
    let sk_bits = sk.into_bits_le_strict(cs.namespace(|| "bitify sk"))?;
    let pk = pubkey(cs.namespace(|| "pubkey compute"), &sk_bits, params)?;

    let in_hash : Vec<_> = (0..2).map(|i| {
        note_hash(cs.namespace(|| format!("hashing {} input", i)), &in_note[i], params).unwrap()
    }).collect();

    let in_root = (0..2).map( |i| {
        merkle_proof::merkle_proof(
            cs.namespace(|| format!("compute merkle proof for {} input", i)), 
            &in_proof[i], 
            &in_hash[i], 
            params)
    }).collect::<Result<Vec<_>,_>>()?;

    let out_hash = (0..2).map(|i| note_hash(cs.namespace(|| format!("hashing {} output", i)), &out_note[i], params))
        .collect::<Result<ArrayVec<[AllocatedNum<E>;2]>, SynthesisError>>()?;
    
    let nf = (0..2).map(|i| nullifier(
        cs.namespace(|| format!("compute nullifier for {} input", i)), 
        &in_hash[i],
        &sk_bits, 
        params))
        .collect::<Result<ArrayVec<[AllocatedNum<E>;2]>, SynthesisError>>()?;
    

    for i in 0..2 {
        
        
        cs.enforce(
            || format!("cheking ownership for {} input", i),
            |lc| lc + in_note[i].owner.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pk.get_variable()
        );
        cs.enforce(
            || format!("verification of root for {} input", i), 
            |lc| lc + root_hash.get_variable() - in_root[i].get_variable(), 
            |lc| lc + in_note[i].amount.get_variable() + in_note[i].native_amount.get_variable(), 
            |lc| lc);


        cs.enforce(
            || format!("cheking asset id for {}th input and output must be the same", i),
            |lc| lc + in_note[i].asset_id.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + out_note[i].asset_id.get_variable()
        );
    }


    cs.enforce(
        || "verification of native amount sum",
        |lc| lc + in_note[0].native_amount.get_variable() + in_note[1].native_amount.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + out_note[0].native_amount.get_variable() + out_note[1].native_amount.get_variable() + (fee.clone(), CS::one())
    );


    cs.enforce(
        || "verification of first elements amount sum in case with different amount types",
        |lc| lc + in_note[0].amount.get_variable() - out_note[0].amount.get_variable(),
        |lc| lc + in_note[0].asset_id.get_variable() - in_note[1].asset_id.get_variable(),
        |lc| lc 
    );

    (Num::zero() + in_hash[0].clone() - in_hash[1].clone()).assert_nonzero(cs.namespace(|| "doublespend protection"))?;
    

    Ok((out_hash, nf))
}

#[cfg(test)]
mod transactions_test {
    use super::*;
    use sapling_crypto::circuit::test::TestConstraintSystem;
    use sapling_crypto::jubjub::{JubjubBls12, JubjubParams};
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use rand::os::OsRng;
    use rand::Rng;

    use crate::fieldtools;

    #[test]
    fn test_nullifier() -> Result<(), SynthesisError> {
        let rng = &mut OsRng::new().unwrap();
        let params = JubjubBls12::new();


        let mut cs = TestConstraintSystem::<Bls12>::new();

        let nh = rng.gen::<Fr>();
        let sk = rng.gen::<Fr>();


        let nf = crate::transactions::nullifier::<Bls12>(&nh, &sk, &params);


        let nh_a = AllocatedNum::alloc(cs.namespace(|| "var nh_a"), || Ok(nh))?;
        let sk_a = AllocatedNum::alloc(cs.namespace(|| "var sk_a"), || Ok(sk))?;
        let sk_bits = sk_a.into_bits_le_strict(cs.namespace(|| "var sk_bits"))?;

        let nf_a = nullifier(&mut cs, &nh_a, &sk_bits, &params)?;

        if !cs.is_satisfied() {
            let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
            assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
        }
        assert!(nf_a.get_value().unwrap() == nf, "Nf value should be the same");

        Ok(())
    }

}
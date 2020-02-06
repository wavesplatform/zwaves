
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
use std::ops::{Add, Sub};


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
    let native_amount = from_bits_le_to_num_limited(cs.namespace(|| "preparing native_amount"), &packed_asset_bits[128..192], 64)?;

    Ok((asset_id, amount, native_amount))
}



pub fn signed_asset_unpack<E: JubjubEngine, CS>(
    mut cs: CS,
    packed_asset: &AllocatedNum<E>
) -> Result<(AllocatedNum<E>, AllocatedNum<E>, AllocatedNum<E>), SynthesisError>
where CS: ConstraintSystem<E>
{

    let packed_asset_bits = packed_asset.into_bits_le_limited(cs.namespace(|| "bitify packed_asset"), 192)?;

    let asset_id = from_bits_le_to_num_limited(cs.namespace(|| "preparing asset_id"), &packed_asset_bits[0..64], 64)?;
    let amount = from_bits_le_to_num_limited(cs.namespace(|| "preparing amount"), &packed_asset_bits[64..128], 64)?;
    let native_amount = from_bits_le_to_num_limited(cs.namespace(|| "preparing native_amount"), &packed_asset_bits[128..192], 64)?;

    let minus_64_num = E::Fr::from_str("52435875175126190479447740508185965837690552500527637822585211955864871632897").unwrap();

    let mut signed_amount_num = Num::<E>::zero();
    signed_amount_num = signed_amount_num.add_bool_with_coeff(CS::one(), &packed_asset_bits[127], minus_64_num) + amount;
    let signed_amont = AllocatedNum::alloc(cs.namespace(|| "alloc signed amount"), || signed_amount_num.get_value().ok_or(SynthesisError::AssignmentMissing))?;


    let mut signed_native_amount_num = Num::<E>::zero();
    signed_native_amount_num = signed_native_amount_num.add_bool_with_coeff(CS::one(), &packed_asset_bits[191], minus_64_num) + native_amount;
    let signed_native_amount = AllocatedNum::alloc(cs.namespace(|| "alloc signed native_amount"), || signed_native_amount_num.get_value().ok_or(SynthesisError::AssignmentMissing))?;

    Ok((asset_id, signed_amont, signed_native_amount))
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


pub fn utxo_accumulator<E: JubjubEngine, CS>(
    mut cs: CS,
    note_hashes: &[AllocatedNum<E>],
    index: &AllocatedNum<E>,
    old_proof: &[AllocatedNum<E>],
    new_proof: &[AllocatedNum<E>],
    params: &E::Params
) -> Result<(AllocatedNum<E>, AllocatedNum<E>), SynthesisError>
where CS: ConstraintSystem<E> {
    assert!(note_hashes.len() == 2, "should be 2 utxo");
    let prooflen = old_proof.len();
    assert!(new_proof.len() == prooflen, "proof length should be equal");

    let bits = index.into_bits_le_limited(cs.namespace(|| "bitify index"), prooflen+1)?;

    let old_proof = old_proof.iter().zip(bits.iter().skip(1)).map(|(n,b)| (n.clone(), b.clone())).collect::<Vec<_>>();
    let new_proof = new_proof.iter().zip(bits.iter().skip(1)).map(|(n,b)| (n.clone(), b.clone())).collect::<Vec<_>>();
    

    let twozeros = E::Fr::from_str("2844901669415300281300718346195343338354231404922385839670861864158643284316").unwrap();
    let twozeros_num = AllocatedNum::alloc(cs.namespace(|| "alloc twozeros_num"), || Ok(twozeros))?;
    cs.enforce(|| "enforce twozeros_num", |lc| lc + twozeros_num.get_variable(), |lc| lc+CS::one(), |lc| lc + (twozeros, CS::one()));

    let old_root = merkle_proof::merkle_proof_shifted(
        cs.namespace(|| "compute merkle proof"), 
        &old_proof, &twozeros_num, 1, params)?;

    let twonotes = merkle_proof::compress(cs.namespace(|| "compress utxo"), 
        pedersen_hash::Personalization::MerkleTree(0), &note_hashes[0], &note_hashes[1], params)?;

    let new_root = merkle_proof::merkle_proof_shifted(
            cs.namespace(|| "compute merkle proof"), 
            &new_proof, &twonotes, 1, params)?;
    
    

    Ok((old_root, new_root))
}


pub fn transfer<E: JubjubEngine, CS>(
    mut cs: CS,
    in_note: &[Note<E>],
    in_proof: &[Vec<(AllocatedNum<E>, Boolean)>],
    out_note: &[Note<E>],
    root_hash: &AllocatedNum<E>,
    sk: &AllocatedNum<E>,
    packed_asset: &AllocatedNum<E>,
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

    let (asset_id, asset_amount, asset_native_amount) = signed_asset_unpack(cs.namespace(|| "unpacking asset"), packed_asset)?;

    cs.enforce(
        || "check asset_id must be the same as for first input and output for nonzero asset_amount", 
        |lc| lc + in_note[0].asset_id.get_variable() - asset_id.get_variable(), 
        |lc| lc + asset_amount.get_variable(), 
        |lc| lc
    );
    

    cs.enforce(
        || "verification of native amount sum",
        |lc| lc + in_note[0].native_amount.get_variable() + in_note[1].native_amount.get_variable() + asset_native_amount.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + out_note[0].native_amount.get_variable() + out_note[1].native_amount.get_variable()
    );


    cs.enforce(
        || "verification of amount sum",
        |lc| lc + in_note[0].amount.get_variable() + in_note[1].amount.get_variable() + asset_amount.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + out_note[0].amount.get_variable() + out_note[1].amount.get_variable()
    );

    cs.enforce(
        || "verification of second elements amount sum in case with different amount types",
        |lc| lc + in_note[1].amount.get_variable() - out_note[1].amount.get_variable(),
        |lc| lc + in_note[0].asset_id.get_variable() - in_note[1].asset_id.get_variable(),
        |lc| lc 
    );

    (Num::zero() + nf[0].clone() - nf[1].clone()).assert_nonzero(cs.namespace(|| "doublespend protection"))?;
    

    Ok((out_hash, nf))
}


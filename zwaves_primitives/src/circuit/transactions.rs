
use pairing::{PrimeField};

use bellman::{SynthesisError, ConstraintSystem};

use sapling_crypto::jubjub::{JubjubEngine};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{Boolean};



use crate::circuit::{note, ownership, merkle_proof};



pub fn deposit<E: JubjubEngine, CS>(
    mut cs: CS,
    in_note: note::Note<E>,
    in_hash: AllocatedNum<E>,
    params: &E::Params
) -> Result<(), SynthesisError>
    where CS: ConstraintSystem<E>
{
    let in_hash_cmp = note::note_hash(cs.namespace(|| "hashing input"), &in_note, params)?;
    cs.enforce(|| "checking input hash", |lc| lc + in_hash.get_variable(), |lc| lc + CS::one(), |lc| lc + in_hash_cmp.get_variable());
    Ok(())
}


pub fn transfer<E: JubjubEngine, CS>(
    mut cs: CS,
    in_note: [note::Note<E>; 2],
    in_nullifier: [AllocatedNum<E>; 2],
    in_proof: [&[(AllocatedNum<E>, Boolean)]; 2],

    out_hash: [AllocatedNum<E>; 2],
    out_note: [note::Note<E>; 2],

    root_hash: AllocatedNum<E>,
    sk: AllocatedNum<E>,
    params: &E::Params
) -> Result<(), SynthesisError>
    where CS: ConstraintSystem<E>
{
    let fee = E::Fr::from_str("1").unwrap();

    let sk_bits = sk.into_bits_le_strict(cs.namespace(|| "bitify sk"))?;
    let pk = ownership::pubkey(cs.namespace(|| "pubkey compute"), &sk_bits, params)?;

    let in_hash : Vec<_> = (0..1).map(|i| {
        note::note_hash(cs.namespace(|| format!("hashing {} input", i)), &in_note[i], params).unwrap()
    }).collect();

    let in_root : Vec<_> = (0..1).map( |i| {
        merkle_proof::merkle_proof(
            cs.namespace(|| format!("compute merkle proof for {} input", i)), 
            in_proof[i], 
            &in_hash[i], 
            params).unwrap()
    }).collect();

    for i in 0..1 {
        let nf = ownership::nullifier(
            cs.namespace(|| format!("compute nullifier for {} input", i)), 
            &in_hash[i],
            &sk_bits, 
            params).unwrap();
        
        cs.enforce(
            || format!("checking nullifier for {} input", i), 
            |lc| lc + nf.get_variable(), 
            |lc| lc + CS::one(),
            |lc| lc + in_nullifier[i].get_variable()
        );

        
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

        
        let out_hash_cmp = note::note_hash(cs.namespace(|| format!("hashing {} output", i)), &out_note[i], params).unwrap();
        
        cs.enforce(
            || format!("cheking hash for {} output", i),
            |lc| lc + out_hash[i].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + out_hash_cmp.get_variable()
        );


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
        |lc| lc + out_note[0].native_amount.get_variable() + out_note[1].native_amount.get_variable() + (fee, CS::one())
    );


    cs.enforce(
        || "verification of first elements amount sum in case with different amount types",
        |lc| lc + in_note[0].amount.get_variable() - out_note[0].amount.get_variable(),
        |lc| lc + in_note[0].asset_id.get_variable() - in_note[1].asset_id.get_variable(),
        |lc| lc 
    );

    (Num::zero() + in_hash[0].clone() - in_hash[1].clone()).assert_nonzero(cs.namespace(|| "doublespend protection"))?;
    
    Ok(())
}




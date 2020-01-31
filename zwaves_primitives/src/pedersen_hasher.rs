use sapling_crypto::jubjub::{JubjubEngine};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use pairing::{Field, PrimeField};
use crate::fieldtools;

use num::Integer;


pub fn u64_to_bits_le(x:u64) -> Vec<bool> {
    let mut res = Vec::with_capacity(64);
    for i in 0..63 {
        res.push((x & (1u64<<i)) != 0);
    }
    res
}



pub fn hash_bits<E, I>(input: I, params: &E::Params) -> E::Fr 
    where I: IntoIterator<Item=bool>,
    E: JubjubEngine
{
    pedersen_hash::<E, _>(Personalization::NoteCommitment, input, params).into_xy().0
}

pub fn hash<E:JubjubEngine>(data: &E::Fr, params: &E::Params) -> E::Fr {
    hash_bits::<E, _>(fieldtools::fr_to_repr_bool(data).into_iter().take(E::Fr::NUM_BITS as usize), params)
}



pub fn compress<E:JubjubEngine>(left: &E::Fr, right: &E::Fr, p: Personalization, params: &E::Params) -> E::Fr {
    let bits = fieldtools::fr_to_repr_bool(left).into_iter().take(E::Fr::NUM_BITS as usize).chain(
        fieldtools::fr_to_repr_bool(right).into_iter().take(E::Fr::NUM_BITS as usize));

    pedersen_hash::<E, _>(p, bits, params).into_xy().0

}

pub fn merkle_root<E:JubjubEngine>(sibling: &[E::Fr], index:u64, leaf: &E::Fr, params: &E::Params) -> E::Fr {
    let index_bits = u64_to_bits_le(index);

    let mut cur = leaf.clone();
    for i in 0..sibling.len() {
        let (left, right) = if index_bits[i] { (sibling[i], cur) } else { (cur, sibling[i]) };
        cur = compress::<E>(&left, &right, Personalization::MerkleTree(i), params);
    }
    cur
}


pub fn update_merkle_proof<E:JubjubEngine>(sibling: &[E::Fr], index: u64, leaf: &[E::Fr], defaults: &[E::Fr], params: &E::Params) -> Option<Vec<E::Fr>> {
    let proofsz = sibling.len();
    let leafsz = leaf.len();
    let maxproofsz = defaults.len();
    let index2 = index + leafsz as u64;
    
    if proofsz > maxproofsz {
        return None;
    }

    if index2 >= u64::pow(2, proofsz as u32) {
        return None;
    }

    let mut sibling2 = Vec::with_capacity(proofsz);

    if leafsz == 0 {
        for i in 0 .. proofsz {
            sibling2.push(sibling[i]);
        }
    } else {
        let mut offset = if index.is_odd() { 1 } else { 0 };
        let mut buffsz = offset + leafsz;
        let mut buffsz_was_odd = buffsz.is_odd();
        let mut sibling2_i;

        if buffsz_was_odd { 
            buffsz += 1;
        }
        let mut buff = Vec::with_capacity(buffsz);
        
        if offset > 0 {
            buff.push(sibling[0]);
        }
        
        for i in 0 .. leafsz {
            buff.push(leaf[i]);
        }

        if buffsz_was_odd {
            buff.push(defaults[0]);
            buffsz += 1;
        }

        sibling2_i = offset + ((index2 ^ 0x1) - index) as usize;
        sibling2.push(if sibling2_i >= buffsz { defaults[0] } else { buff[sibling2_i] });

        (1..proofsz).for_each( |i| {
            offset = if (index >> i).is_odd() { 1 } else { 0 };
            (0..buffsz>>1).for_each(|j| {
                buff[offset+j] = compress::<E>(&buff[j*2], &buff[j*2+1], Personalization::MerkleTree(i-1), params);
            });

            if offset > 0 {
                buff[0] = sibling[i];
            }

            buffsz = offset + (buffsz>>1);
            buffsz_was_odd = buffsz.is_odd();
            if buffsz_was_odd {
                buff[buffsz] = defaults[i];
                buffsz += 1;
            } 

            sibling2_i = offset + (((index2 >> i) ^ 0x1) - (index >> i)) as usize;
            sibling2.push(if sibling2_i >= buffsz { defaults[i] } else { buff[sibling2_i] }  );
        });
    }

    Some(sibling2)
}

pub fn update_merkle_root_and_proof<E:JubjubEngine>(root: &E::Fr, sibling: &[E::Fr], index: u64, leaf: &[E::Fr], defaults: &[E::Fr], params: &E::Params) -> Option<(E::Fr, Vec<E::Fr>)> {
    let cmp_root = merkle_root::<E>(sibling, index, &E::Fr::zero(), params);
    
    if cmp_root != *root {
        return None;
    }

    let proof = update_merkle_proof::<E>(sibling, index, leaf, defaults, params)?;
    let root = merkle_root::<E>(&proof, index + (leaf.len() as u64), &E::Fr::zero(), params);
    Some((root, proof))
}



pub fn merkle_defaults<E:JubjubEngine>(n:usize, params:&E::Params) -> Vec<E::Fr> {
    (0..n).scan((0, E::Fr::zero()), |state, _| {
        let (i, p) = *state;
        *state = (i+1, compress::<E>(&p, &p, Personalization::MerkleTree(i), params));
        Some(p)
    }).collect()
}



#[cfg(test)]
mod pedersen_hasher_tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use sapling_crypto::jubjub::{JubjubBls12};

    
    #[test]
    fn test_update_merkle_proof() {
        let params = JubjubBls12::new();
        let defaults = merkle_defaults::<Bls12>(48, &params);
        let elements0 : Vec<_> =  (0..23).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();
        let elements1 : Vec<_> =  (23..907).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();
        let elements2 : Vec<_> =  (0..907).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();

        let proof0 = update_merkle_proof::<Bls12>(&defaults, 0, &elements0, &defaults, &params).unwrap();
        let proof1 = update_merkle_proof::<Bls12>(&proof0, elements0.len() as u64, &elements1, &defaults, &params).unwrap();
        let proof2 = update_merkle_proof::<Bls12>(&defaults, 0, &elements2, &defaults, &params).unwrap();
        
        assert!(proof1.into_iter().zip(proof2.into_iter()).all(|(x,y)| x==y), "Proofs must be same");
    }

    #[test]
    fn test_update_merkle_root_and_proof() {
        let params = JubjubBls12::new();
        let defaults = merkle_defaults::<Bls12>(48, &params);

        let elements0 : Vec<_> =  (0..23).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();
        let elements1 : Vec<_> =  (23..907).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();
        let elements2 : Vec<_> =  (0..907).map(|i| hash::<Bls12>(&Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap(), &params)).collect();

        let root_default = merkle_root::<Bls12>(&defaults, 0, &Fr::zero(), &params);

        let (root0, proof0) = update_merkle_root_and_proof::<Bls12>(&root_default, &defaults, 0, &elements0, &defaults, &params).unwrap();
        let (root1, proof1) = update_merkle_root_and_proof::<Bls12>(&root0, &proof0, elements0.len() as u64, &elements1, &defaults, &params).unwrap();
        let (root2, proof2) = update_merkle_root_and_proof::<Bls12>(&root_default, &defaults, 0, &elements2, &defaults, &params).unwrap();

        assert!(proof1.into_iter().zip(proof2.into_iter()).all(|(x,y)| x==y), "Proofs must be same");
        assert!(root1==root2, "Roots must be same");
    }
    
}
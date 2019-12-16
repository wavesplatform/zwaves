use pairing::bls12_381::{Bls12, Fr, FrRepr};

use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use pairing::{Field, PrimeField};
use crate::field::*;

use num::Integer;
use std::io;

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
    hash_bits::<E, _>(fr_to_repr_bool(data).into_iter().take(E::Fr::NUM_BITS as usize), params)
}



pub fn compress<E:JubjubEngine>(left: &E::Fr, right: &E::Fr, p: Personalization, params: &E::Params) -> E::Fr {
    let bits = fr_to_repr_bool(left).into_iter().take(E::Fr::NUM_BITS as usize).chain(
        fr_to_repr_bool(right).into_iter().take(E::Fr::NUM_BITS as usize));

    pedersen_hash::<E, _>(p, bits, params).into_xy().0

}

/*
    pub fn root(&self, sibling: &[E::Fr], index:u64, leaf: E::Fr) -> io::Result<E::Fr> {
        let index_bits = u64_to_bits_le(index);
        let merkle_proof_sz = sibling.len();
        
        if merkle_proof_sz > self.merkle_proof_defaults.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too long merkle proof"));
        }

        let mut cur = leaf;
        for i in 0..self.merkle_proof_defaults.len() {
            let (left, right) = if index_bits[i] { (sibling[i], cur) } else { (cur, sibling[i]) };
            cur = self.compress(&left, &right, Personalization::MerkleTree(i));
        }
        
        Ok(cur)
    }

    pub fn update_merkle_proof(&self, sibling: &[E::Fr], index: u64, leaf: &[E::Fr]) -> io::Result<Vec<E::Fr>> {
        let proofsz = sibling.len();
        let leafsz = leaf.len();
        let maxproofsz = self.merkle_proof_defaults.len();
        let index2 = index + leafsz as u64;
        
        if proofsz > maxproofsz {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too long proof"));
        }

        if index2 > u64::pow(2, proofsz as u32) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many leaves"));
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
                buff.push(self.merkle_proof_defaults[0]);
                buffsz += 1;
            }

            sibling2_i = offset + ((index2 ^ 0x1) - index) as usize;
            sibling2.push(if sibling2_i >= buffsz { self.merkle_proof_defaults[0] } else { buff[sibling2_i] });

            (1..proofsz).for_each( |i| {
                offset = if (index >> i).is_odd() { 1 } else { 0 };
                (0..buffsz>>1).for_each(|j| {
                    buff[offset+j] = self.compress(&buff[j*2], &buff[j*2+1], Personalization::MerkleTree(i-1));
                });

                if offset > 0 {
                    buff[0] = sibling[i];
                }

                buffsz = offset + (buffsz>>1);
                buffsz_was_odd = buffsz.is_odd();
                if buffsz_was_odd {
                    buff[buffsz] = self.merkle_proof_defaults[i];
                    buffsz += 1;
                } 

                sibling2_i = offset + (((index2 >> i) ^ 0x1) - (index >> i)) as usize;
                sibling2.push(if sibling2_i >= buffsz { self.merkle_proof_defaults[0] } else { buff[sibling2_i] }  );
            });
        }
        Ok(sibling2)
    }


    pub fn update_merkle_root_and_proof(&self, root: &E::Fr, sibling: &[E::Fr], index: u64, leaf: &[E::Fr]) -> io::Result<(E::Fr, Vec<E::Fr>)> {
        let cmp_root = self.root(sibling, index, E::Fr::zero())?;
        
        if cmp_root != *root {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong proof"));
        }

        let proof = self.update_merkle_proof(sibling, index, leaf)?;
        let root = self.root(&proof, index + (leaf.len() as u64), E::Fr::zero())?;
        Ok((root, proof))
    }

}


pub type PedersenHasherBls12 = PedersenHasher<Bls12>;

impl Default for PedersenHasherBls12 {
    fn default() -> Self {
        let merkle_proof_maxlen = 48;
        let tmp_hasher = Self {
            params: JubjubBls12::new(),
            merkle_proof_defaults: Vec::with_capacity(0)
        };

        let merkle_proof_defaults: Vec<_> = (0..merkle_proof_maxlen).scan((0, <Bls12 as Engine>::Fr::zero()), |state, _| {
                let (i, p) = *state;
                *state = (i+1, tmp_hasher.compress(&p, &p, Personalization::MerkleTree(i)));
                Some(p)
            }).collect();

        Self {
            params: JubjubBls12::new(),
            merkle_proof_defaults: merkle_proof_defaults
        }
    }
}







#[test]
fn test_update_merkle_proof() {
    let hasher = PedersenHasherBls12::default();
    let elements0 : Vec<_> =  (0..23).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements1 : Vec<_> =  (23..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements2 : Vec<_> =  (0..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();

    let proof_defaults = hasher.merkle_proof_defaults.clone();
    let proof0 = hasher.update_merkle_proof(&proof_defaults, 0, &elements0).unwrap();
    let proof1 = hasher.update_merkle_proof(&proof0, elements0.len() as u64, &elements1).unwrap();
    let proof2 = hasher.update_merkle_proof(&proof_defaults, 0, &elements2).unwrap();
    
    assert!(proof1.into_iter().zip(proof2.into_iter()).all(|(x,y)| x==y), "Proofs must be same");
}

#[test]
fn test_update_merkle_root_and_proof() {
    let hasher = PedersenHasherBls12::default();
    let elements0 : Vec<_> =  (0..23).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements1 : Vec<_> =  (23..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements2 : Vec<_> =  (0..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();

    let proof_defaults = &hasher.merkle_proof_defaults;
    let root_default = hasher.root(proof_defaults, 0, Fr::zero()).unwrap();

    let (root0, proof0) = hasher.update_merkle_root_and_proof(&root_default, proof_defaults, 0, &elements0).unwrap();
    let (root1, proof1) = hasher.update_merkle_root_and_proof(&root0, &proof0, elements0.len() as u64, &elements1).unwrap();
    let (root2, proof2) = hasher.update_merkle_root_and_proof(&root_default, proof_defaults, 0, &elements2).unwrap();

    assert!(proof1.into_iter().zip(proof2.into_iter()).all(|(x,y)| x==y), "Proofs must be same");
    assert!(root1==root2, "Roots must be same");
}

*/

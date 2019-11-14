// Pedersen hash implementation of the Hasher trait

extern crate bellman;
extern crate pairing;
extern crate sapling_crypto;

use pairing::PrimeField;
use pairing::bls12_381::{Bls12, Fr, FrRepr};

use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use crate::bit_iterator::BitIteratorLe;
use self::pairing::{Field, Engine};


use num::Integer;


pub fn u64_to_bits_le(x:u64) -> Vec<bool> {
    let mut res = Vec::with_capacity(64);
    for i in 0..63 {
        res.push((x & (1u64<<i)) != 0);
    }
    res
}

pub struct PedersenHasher<E: JubjubEngine> {
    pub params: E::Params,
    pub merkle_proof_defaults: Vec<E::Fr>
}



impl<E: JubjubEngine> PedersenHasher<E> {
    pub fn hash_bits<I: IntoIterator<Item = bool>>(&self, input: I) -> E::Fr {
        pedersen_hash::<E, _>(Personalization::NoteCommitment, input, &self.params)
        .into_xy()
        .0
    }

    pub fn hash(&self, data: E::Fr) -> E::Fr {
        self.hash_bits(self.get_bits_le_fixed(data, E::Fr::NUM_BITS as usize))
    }


    pub fn get_bits_le_fixed(&self, data: E::Fr, n: usize) -> Vec<bool> {
        let mut r: Vec<bool> = Vec::with_capacity(n);
        r.extend(BitIteratorLe::new(data.into_repr()).take(n));
        let len = r.len();
        r.extend((len..n).map(|_| false));
        r
    }

    pub fn compress(&self, left: &E::Fr, right: &E::Fr, p: Personalization) -> E::Fr {
        let leftbits = self.get_bits_le_fixed(*left, E::Fr::NUM_BITS as usize);
        let rightbits = self.get_bits_le_fixed(*right, E::Fr::NUM_BITS as usize);
        let mut total_bits = vec![];
        total_bits.extend(leftbits);
        total_bits.extend(rightbits);
        pedersen_hash::<E, _>(p, total_bits, &self.params)
        .into_xy()
        .0
    }

    pub fn root(&self, sibling: &[E::Fr], index:u64, leaf: E::Fr) -> E::Fr {
        let index_bits = u64_to_bits_le(index);
        let merkle_proof_sz = sibling.len();
        assert!(merkle_proof_sz <= self.merkle_proof_defaults.len(), "too long merkle proof");
        
        let mut cur = leaf;
        for i in 0..self.merkle_proof_defaults.len() {
            let (left, right) = if index_bits[i] { (sibling[i], cur) } else { (cur, sibling[i]) };
            cur = self.compress(&left, &right, Personalization::MerkleTree(i));
        }
        cur
    }

    pub fn update_merkle_proof(&self, sibling: &[E::Fr], index: u64, leaf: &[E::Fr]) -> Vec<E::Fr> {
        let proofsz = sibling.len();
        let leafsz = leaf.len();
        let maxproofsz = self.merkle_proof_defaults.len();
        let index2 = index + leafsz as u64;
        
        assert!(proofsz <= maxproofsz, "too long proof");
        assert!(index2 <= u64::pow(2, proofsz as u32), "too many leaves");

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
        sibling2
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



fn cmp_slices<T: std::cmp::Eq>(a: &[T], b: &[T]) -> bool {
    (a.len()==b.len()) && (0..a.len()).fold(true, |acc, i| acc && a[i]==b[i])
}




#[test]
fn test_update_merkle_proof() {
    let hasher = PedersenHasherBls12::default();
    let elements0 : Vec<_> =  (0..23).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements1 : Vec<_> =  (23..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements2 : Vec<_> =  (0..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();

    let proof_defaults = hasher.merkle_proof_defaults.clone();
    let proof0 = hasher.update_merkle_proof(&proof_defaults, 0, &elements0);
    let proof1 = hasher.update_merkle_proof(&proof0, elements0.len() as u64, &elements1);
    let proof2 = hasher.update_merkle_proof(&proof_defaults, 0, &elements2);

    assert!(cmp_slices(&proof1, &proof2), "Proofs must be same");
}




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
        res[i] = (x & (1u64<<i)) != 0;
    }
    res
}

pub struct PedersenHasher<E: JubjubEngine> {
    params: E::Params,
    merkle_proof_defaults: Vec<E::Fr>
}

impl<'a, E: JubjubEngine> PedersenHasher<E> {
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
    let input = BitIteratorLe::new(left.into_repr()).take(E::Fr::NUM_BITS as usize).chain(
      BitIteratorLe::new(right.into_repr()).take(E::Fr::NUM_BITS as usize));
    pedersen_hash::<E, _>(p, input, &self.params)
      .into_xy()
      .0
  }

    pub fn root(&self, sibling: Vec<E::Fr>, index:u64, leaf: E::Fr) -> E::Fr {
        let index_bits = u64_to_bits_le(index);
        let merkle_proof_sz = sibling.len();
        assert!(merkle_proof_sz <= self.merkle_proof_defaults.len(), "too long merkle proof");
        
        let mut cur = leaf;
        for i in 0..self.merkle_proof_defaults.len() {
            let (left, right) = if index_bits[i] { (cur, sibling[i]) } else { (sibling[i], cur) };
            cur = self.compress(&left, &right, Personalization::MerkleTree(i));
        }
        cur
    }

    pub fn update_merkle_proof2(&self, sibling: &[E::Fr], index: u64, leaf: &[E::Fr]) -> Vec<E::Fr> {
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


    pub fn update_merkle_proof(&self, path: &[E::Fr], index: u64, elements: &[E::Fr]) -> Vec<E::Fr> {
        let s = elements.len();
        let pathlen = path.len();
        let maxpathlen = self.merkle_proof_defaults.len();

        assert!(pathlen <= maxpathlen);
        assert!((index + s as u64) <= u64::pow(2, pathlen as u32), "too many elements");

        let mut new_path = Vec::with_capacity(pathlen);

        if (s==0) {
            for i in 0..pathlen {
                new_path.push(path[i]);
            }
        } else {

            let mut offset = (index & 0x1) as usize;
            let mut memframesz = s + offset;
            let mut memframe = Vec::with_capacity(memframesz + 1);

            if offset > 0 {
                memframe.push(path[0]);
            } 

            (0..s).for_each(|i| memframe.push(elements[i]));

            if memframesz & 0x1 == 1 {
                memframe.push(path[0]);
            }


            new_path.push(
                if (index + s as u64 - 1) & 0x1 > 0 {
                    if memframesz == 1 { self.merkle_proof_defaults[0] } else { memframe[memframesz-2]}
                } else {
                self.merkle_proof_defaults[0]
                });

            

            (1..pathlen).for_each(|i| {
                offset = ((index >> i) & 0x1) as usize;
                (0..((memframesz + 1) >> 1)).for_each(|j| {
                    let res = self.compress(&memframe[j * 2], &memframe[j * 2 + 1], Personalization::MerkleTree(i-1));
                    memframe[j + offset] = res;
                });

                memframesz = offset + ((memframesz + 1) >> 1);
                if memframesz & 0x1 == 1 {
                    memframe[memframesz] = self.merkle_proof_defaults[i];
                }

                if offset > 0 {
                    memframe[0] = path[i];
                }

                new_path.push(
                    if ((index + s as u64 - 1) >> i) & 0x1 > 0 {
                        if memframesz == 1 { self.merkle_proof_defaults[i] } else { memframe[memframesz-2] }
                    } else {
                        self.merkle_proof_defaults[i]
                    });

            });
        }
        new_path
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
fn test_pedersen_hash() {
    let hasher = PedersenHasherBls12::default();
    let mut hash = hasher.hash(Fr::from_str("6").unwrap());

    println!("testing....");

    for i in 0..63 {
        hash = hasher.compress(&hash, &hash, Personalization::MerkleTree(i));
    }
    println!("Empty root hash: {:?}", hash);

    assert_eq!(hash.to_string(), "Fr(0x01c2bcb36b2d8126d5812ad211bf90706db31f50bf27f77225d558047571e1aa)");
}

fn str_to_bin(i: u32) -> Vec<bool> {
    format!("{:#b}", i).chars().skip(2).map(|v| v == '1').collect()
}

#[test]
fn test_update_merkle_proof() {
    let hasher = PedersenHasherBls12::default();
    let elements0 : Vec<_> =  (0..23).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements1 : Vec<_> =  (23..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();
    let elements2 : Vec<_> =  (0..907).map(|i| hasher.hash(Fr::from_repr(FrRepr([i as u64, 0u64, 0u64, 0u64])).unwrap())).collect();

    let proof_defaults = hasher.merkle_proof_defaults.clone();
    let proof0 = hasher.update_merkle_proof2(&proof_defaults, 0, &elements0);
    let proof1 = hasher.update_merkle_proof2(&proof0, elements0.len() as u64, &elements1);
    let proof2 = hasher.update_merkle_proof2(&proof_defaults, 0, &elements2);

    println!("Proof1: {:?}\n Proof2: {:?}", proof1, proof2);

    let t1 = (0..proof1.len()).fold(true, |acc, i| acc && proof1[i]==proof2[i]);
    let t2 = proof1.len()==proof2.len();
    println!("## {:?} {:?}", t1, t2);
    
    //assert!(t1 && t2, "wrong proof computation");

    //assert_eq!(proof1, proof2, "wrong proof computation");
}



// #[test]
// fn test_root() {
//     let hasher = PedersenHasherBls12::default();

//     let h1 = hasher.hash_bits(str_to_bin(1));
//     let h2 = hasher.hash_bits(str_to_bin(2));
//     let h3 = hasher.hash_bits(str_to_bin(3));
//     let h4 = hasher.hash_bits(str_to_bin(4));
//     let h5 = hasher.hash_bits(str_to_bin(5));

//     let res = hasher.root(vec!(Some((h1, true)), Some((h2, false)), Some((h3, false))), Some(h5));

//     println!("Root hash: {:?}", res);


//     assert_eq!(res.unwrap().to_string(), "Fr(0x238fa29d1378c0e37e6e870168bfb207ec9e61fe6e15e020aca7123da2d3c2e7)");
// }

//           Merkle tree:
//            h14 (root)
//        h12           !h13
//   !h8      h9     h10    h11
// h0 h1  [h2] !h3  h4 h5  h6 h7
// #[test]
// fn test_root_2() {
//     let hasher = PedersenHasherBls12::default();

//     let mut tree: Vec<_> = (1..=15).map(|i| hasher.hash_bits(str_to_bin(i))).collect();

//     tree[8] = hasher.compress(&tree[0], &tree[1], Personalization::MerkleTree(0));
//     tree[9] = hasher.compress(&tree[2], &tree[3], Personalization::MerkleTree(0));
//     tree[10] = hasher.compress(&tree[4], &tree[5], Personalization::MerkleTree(0));
//     tree[11] = hasher.compress(&tree[6], &tree[7], Personalization::MerkleTree(0));

//     tree[12] = hasher.compress(&tree[8], &tree[9], Personalization::MerkleTree(1));
//     tree[13] = hasher.compress(&tree[10], &tree[11], Personalization::MerkleTree(1));

//     tree[14] = hasher.compress(&tree[12], &tree[13], Personalization::MerkleTree(2));

//     let res = hasher.root(vec!(Some((tree[3], false)), Some((tree[8], true)), Some((tree[13], false))), Some(tree[2]));

//     assert_eq!(res.unwrap(), tree[14]);
//     assert_eq!(tree[14].to_string(), "Fr(0x4ae608379b1f4b34616934667566fbd43088b5e36ec4e5330b943ba78c273d39)");
// }

//           Merkle tree:
//            h14 (root)
//        h12           !h13
//   !h8      h9     h10    h11
// h0 h1  !h2 h3  [h4 h5  h6] h7
// #[test]
// fn test_update_merkle_proof() {
//     let hasher = PedersenHasherBls12::default();

//     let mut tree: Vec<_> = (1..=15).map(|i| hasher.hash_bits(str_to_bin(i))).collect();

//     tree[8] = hasher.compress(&tree[0], &tree[1], Personalization::MerkleTree(0));
//     tree[9] = hasher.compress(&tree[2], &tree[3], Personalization::MerkleTree(0));
//     tree[10] = hasher.compress(&<Bls12 as Engine>::Fr::zero(), &<Bls12 as Engine>::Fr::zero(), Personalization::MerkleTree(0));
//     tree[11] = hasher.compress(&<Bls12 as Engine>::Fr::zero(), &tree[7], Personalization::MerkleTree(0));

//     tree[12] = hasher.compress(&tree[8], &tree[9], Personalization::MerkleTree(1));
//     tree[13] = hasher.compress(&tree[10], &tree[11], Personalization::MerkleTree(1));

//     tree[14] = hasher.compress(&tree[12], &tree[13], Personalization::MerkleTree(2));



//     let res = hasher.update_root(&[tree[2], tree[8], tree[13]], 4, &[tree[4], tree[5], tree[6]]);

//     assert_eq!(res.to_string(), "Fr(0x4ae608379b1f4b34616934667566fbd43088b5e36ec4e5330b943ba78c273d39)");
// }

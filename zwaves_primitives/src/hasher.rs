// Pedersen hash implementation of the Hasher trait

extern crate bellman;
extern crate pairing;
extern crate sapling_crypto;

use pairing::bls12_381::{Bls12, Fr};
use pairing::{PrimeField};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use crate::bit_iterator::BitIteratorLe;
pub struct PedersenHasher<E: JubjubEngine> {
params: E::Params,
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
    let input = BitIteratorLe::new(left.into_repr()).take(E::Fr::NUM_BITS as usize).chain(
      BitIteratorLe::new(right.into_repr()).take(E::Fr::NUM_BITS as usize));
    pedersen_hash::<E, _>(p, input, &self.params)
      .into_xy()
      .0
  }

    pub fn root(&self, path: Vec<Option<(E::Fr, bool)>>, list: Option<E::Fr>) -> Option<E::Fr> {
        if list.is_none() || path.iter().any(|s| s.is_none()) {
            None
        } else {
            path.iter().enumerate().fold::<Option<E::Fr>, _>(None, |res, val| {
                let (num, data) = val;
                let (sipling, pos_bit) = data.unwrap();

                let prev_or_list = res.or(list).unwrap();

                let left = if pos_bit {
                    sipling
                } else {
                    prev_or_list
                };

                let right = if pos_bit {
                    prev_or_list
                } else {
                    sipling
                };

                Some(self.compress(&left, &right, Personalization::MerkleTree(num)))
            })
        }
    }
}


pub type PedersenHasherBls12 = PedersenHasher<Bls12>;

impl Default for PedersenHasherBls12 {
    fn default() -> Self {
        Self {
        params: JubjubBls12::new(),
        }
    }
}



#[test]
fn test_pedersen_hash() {
    let hasher = PedersenHasherBls12::default();
    let message = vec![false, false, false, false, false, false, false, false];
    let mut hash = hasher.hash(Fr::from_str("6").unwrap());

    println!("testing....");

    for i in 0..63 {
        hash = hasher.compress(&hash, &hash, Personalization::MerkleTree(i));
    }
    println!("Empty root hash: {:?}", hash);

    assert_eq!(hash.to_string(), "Fr(0x5c34420d29ac16e496bfe0b7f9476a2f62633b83470f5999437549e8f20baedd)");
}

fn str_to_bin(i: u32) -> Vec<bool> {
    format!("{:#b}", i).chars().skip(2).map(|v| v == '1').collect()
}

#[test]
fn test_root() {
    let hasher = PedersenHasherBls12::default();

    let h1 = hasher.hash_bits(str_to_bin(1));
    let h2 = hasher.hash_bits(str_to_bin(2));
    let h3 = hasher.hash_bits(str_to_bin(3));
    let h4 = hasher.hash_bits(str_to_bin(4));
    let h5 = hasher.hash_bits(str_to_bin(5));

    let res = hasher.root(vec!(Some((h1, true)), Some((h2, false)), Some((h3, false))), Some(h5));

    println!("Root hash: {:?}", res);


    assert_eq!(res.unwrap().to_string(), "Fr(0x238fa29d1378c0e37e6e870168bfb207ec9e61fe6e15e020aca7123da2d3c2e7)");
}

//           Merkle tree:
//            h14 (root)
//        h12           !h13
//   !h8      h9     h10    h11
// h0 h1  [h2] !h3  h4 h5  h6 h7
#[test]
fn test_root_2() {
    let hasher = PedersenHasherBls12::default();

    let mut tree: Vec<_> = (1..=15).map(|i| hasher.hash_bits(str_to_bin(i))).collect();

    tree[8] = hasher.compress(&tree[0], &tree[1], Personalization::MerkleTree(0));
    tree[9] = hasher.compress(&tree[2], &tree[3], Personalization::MerkleTree(0));
    tree[10] = hasher.compress(&tree[4], &tree[5], Personalization::MerkleTree(0));
    tree[11] = hasher.compress(&tree[6], &tree[7], Personalization::MerkleTree(0));

    tree[12] = hasher.compress(&tree[8], &tree[9], Personalization::MerkleTree(1));
    tree[13] = hasher.compress(&tree[10], &tree[11], Personalization::MerkleTree(1));

    tree[14] = hasher.compress(&tree[12], &tree[13], Personalization::MerkleTree(2));

    let res = hasher.root(vec!(Some((tree[3], false)), Some((tree[8], true)), Some((tree[13], false))), Some(tree[2]));

    assert_eq!(res.unwrap(), tree[14]);
    assert_eq!(tree[14].to_string(), "Fr(0x4ae608379b1f4b34616934667566fbd43088b5e36ec4e5330b943ba78c273d39)");
}


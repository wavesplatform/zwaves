// Pedersen hash implementation of the Hasher trait

extern crate bellman;
extern crate pairing;
extern crate sapling_crypto;

use pairing::bls12_381::Bls12;
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
            path.iter().rev().enumerate().fold::<Option<E::Fr>, _>(None, |res, val| {
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
    let mut hash = hasher.hash_bits(message);

    println!("testing....");

    for i in 0..63 {
      hash = hasher.compress(&hash, &hash, Personalization::MerkleTree(i));
    }

    println!("Empty root hash: {:?}", hash);
}

#[test]
fn test_root() {
    let hasher = PedersenHasherBls12::default();
    let h1 = hasher.hash_bits("1".chars().map(|c| c == '1'));
    let h2 = hasher.hash_bits("10".chars().map(|c| c == '1'));
    let h3 = hasher.hash_bits("11".chars().map(|c| c == '1'));
    let h4 = hasher.hash_bits("110".chars().map(|c| c == '1'));
    let h5 = hasher.hash_bits("111".chars().map(|c| c == '1'));

    let res = hasher.root(vec!(Some((h1, true)), Some((h2, false)), Some((h3, false))), Some(h5));

    println!("Root hash: {:?}", res);
}
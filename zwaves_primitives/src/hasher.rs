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

  fn get_bits_le_fixed(&self, data: E::Fr, n: usize) -> Vec<bool> {
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
}
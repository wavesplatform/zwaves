extern crate bincode;
extern crate serde;

use bellman::groth16::Proof;

use crate::serialization::objects::*;
use std::io;
use pairing::bls12_381::Bls12;

pub fn serialize(
    p: &Proof<Bls12>
) -> Vec<u8>
{
    let mut v = vec![];
    p.write(&mut v).unwrap();
    v
}

pub fn deserialize(
    bytes: Vec<u8>
) -> io::Result<Proof<Bls12>>
{
    Proof::read(bytes.as_slice())
}
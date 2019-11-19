extern crate bincode;
extern crate serde;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::groth16::{PreparedVerifyingKey, VerifyingKey};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{CurveAffine, Engine};
use std::io;

use crate::serialization::objects::Bls12Fr;

pub fn serialize(
    inputs: Vec<Fr>
) -> Vec<u8>
{
    let frs: Vec<Bls12Fr> = inputs.iter().map(|f| Bls12Fr::from_bls12(*f)).collect();
    bincode::serialize(&frs).unwrap()
}

pub fn deserialize(
    bytes: Vec<u8>
) -> io::Result<Vec<Fr>>
{
    let r: bincode::Result<Vec<Bls12Fr>> = bincode::deserialize(bytes.as_slice());
    r.map(|fr| fr.iter().map(|f| Bls12Fr::to_bls12(*f)).collect())
        .map_err(|e| io::Error::from(io::ErrorKind::InvalidData))
}
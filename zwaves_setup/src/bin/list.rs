use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use pairing::bls12_381::{Bls12, Fr};


use std::fs::File;
use std::io::Read;

use zwaves_circuit::circuit::{Transfer, UtxoAccumulator};
use hex::encode;


fn main() -> std::io::Result<()> {
    let jubjub_params = JubjubBls12::new();


    let params_file = File::open("mpc_params_accumulator")?;
    let mut params = phase2::MPCParameters::read(&params_file, true)?;
    drop(params_file);

    let contributions = params.verify(UtxoAccumulator::<Bls12> {
        params: &jubjub_params,
        note_hashes: [None, None],
        index: None,
        old_proof: None,
        new_proof: None
    }).expect("parameters should be valid!");

    println!("List of all contributions:");

    contributions.into_iter().enumerate().for_each(|(i, h)| {
        println!("{}. {}", i, encode(h.as_ref()));
    });

    

    let params_file = File::open("mpc_params_transfer")?;
    let mut params = phase2::MPCParameters::read(&params_file, true)?;
    drop(params_file);

    let contributions = params.verify(Transfer::<Bls12> {
        params: &jubjub_params,
        receiver: None,
        in_note: [None, None],
        out_note: [None, None],
        in_proof: [None, None],
        root_hash: None,
        packed_asset: None,
        sk: None
    }).expect("parameters should be valid!");

    println!("List of all contributions:");

    contributions.into_iter().enumerate().for_each(|(i, h)| {
        println!("{}. {}", i, encode(h.as_ref()));
    });

    

 
    Ok(())
}

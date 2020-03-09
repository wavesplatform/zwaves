use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use pairing::bls12_381::{Bls12, Fr};
use rand::os::OsRng;
use rand::Rng;

use std::fs::File;
use std::io::{Write, Read};
use zwaves_circuit::circuit::{UtxoAccumulator, Transfer};

use hex::encode;


fn main() -> std::io::Result<()> {
    let rng = &mut OsRng::new().unwrap();
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


    let hash = params.contribute(rng);

    println!("Contributed with hash {}", encode(hash.as_ref()));


    let params_file = File::create("mpc_params_accumulator")?;
    params.write(params_file)?;


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
        sk: None,
        packed_asset:None,
    }).expect("parameters should be valid!");


    let hash = params.contribute(rng);

    println!("Contributed with hash {}", encode(hash.as_ref()));


    let params_file = File::create("mpc_params_transfer")?;
    params.write(params_file)?;


    println!("MPC params saved OK");
    Ok(())
}

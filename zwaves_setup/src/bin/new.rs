use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use pairing::bls12_381::{Bls12, Fr};
use std::fs::File;
use std::io::Write;

use zwaves_circuit::circuit::{UtxoAccumulator, Transfer};





fn main() -> std::io::Result<()> {
    let jubjub_params = JubjubBls12::new();
/*
    let params = phase2::MPCParameters::new(UtxoAccumulator::<Bls12> {
        params: &jubjub_params,
        note_hashes: [None, None],
        index: None,
        old_proof: None,
        new_proof: None
    }).unwrap();

    let params_file = File::create("mpc_params_accumulator")?;
    params.write(params_file)?;*/


    let params = phase2::MPCParameters::new(Transfer::<Bls12> {
        params: &jubjub_params,
        receiver: None,
        in_note: [None, None],
        out_note: [None, None],
        in_proof: [None, None],
        root_hash: None,
        packed_asset: None,
        sk: None
    }).unwrap();

    let params_file = File::create("mpc_params_transfer")?;
    params.write(params_file)?;

    println!("MPC params saved OK");
    Ok(())
}

use pairing::bls12_381::{Fr, Bls12};
use pairing::{Field, PrimeField};

use rand::{Rng, Rand};


use std::mem::transmute;
use wasm_bindgen::prelude::*;


use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use getrandom::getrandom;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn log(s: &str);
}

#[wasm_bindgen]
extern "C" {
    fn logs(s: String);
}




#[derive(Clone, Debug)]
pub struct GetrandomRng();


impl Rng for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut res = [0u8; 4];
        getrandom(res.as_mut()).unwrap();
        u32::from_be_bytes(res)
    }
}





#[wasm_bindgen]
pub fn run() -> String {
    let mut rng = GetrandomRng();
    let preimage = rng.gen();
    let params = JubjubBls12::new();
    logs(format!("preimage value {:?}", zwaves_primitives::pedersen_hasher::hash::<Bls12>(&preimage, &params)));
    return String::from("");
}


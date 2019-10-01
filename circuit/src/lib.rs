mod bit_iterator;
mod hasher;
mod utils;

extern crate pairing;
extern crate rand;
extern crate wasm_bindgen;

use crate::hasher::PedersenHasherBls12;
use pairing::bls12_381::FrRepr;
use rand::rngs::OsRng;
use rand::RngCore;
use std::mem::transmute;
use wasm_bindgen::prelude::*;
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn log(s: &str);
}

// #[wasm_bindgen]
// pub fn greet() {
//     //alert("Hello, circuit!");
// }

#[wasm_bindgen]
pub fn test() -> String {
    let mut preimage = [0u8; 32];
    let mut rng = OsRng.fill_bytes(&mut preimage);
    let hasher = PedersenHasherBls12::default();
    //let res = format!("{:?}", hasher.hash(unsafe { transmute(preimage) }));
    let res = format!("{:?}", hasher.hash(unsafe { transmute(preimage) }));
    return String::from(res);
}

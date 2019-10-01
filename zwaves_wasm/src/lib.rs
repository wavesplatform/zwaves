use zwaves_primitives::bit_iterator;
use zwaves_primitives::hasher;
use crate::hasher::PedersenHasherBls12;
use pairing::bls12_381::{Fr};

use rand::rngs::OsRng;
use rand::{RngCore};
use std::mem::transmute;
use wasm_bindgen::prelude::*;


use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
//use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};

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




#[derive(Clone)]
pub struct PedersenDemo<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub image: Option<E::Fr>,
    pub preimage: Option<E::Fr>
}

impl <'a, E: JubjubEngine> Circuit<E> for PedersenDemo<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let image = AllocatedNum::alloc(cs.namespace(|| "signal public input image"), || self.image.ok_or(SynthesisError::AssignmentMissing))?;
        image.inputize(cs.namespace(|| "image inputize"));
        let preimage = AllocatedNum::alloc(cs.namespace(|| "signal input preimage"), || self.preimage.ok_or(SynthesisError::AssignmentMissing))?;
        let preimage_bits = preimage.into_bits_le(cs.namespace(|| "preimage_bits <== bitify(preimage)"))?;
        let image_calculated = pedersen_hash::pedersen_hash(
            cs.namespace(|| "image_calculated <== pedersen_hash(preimage_bits)"),
            pedersen_hash::Personalization::NoteCommitment,
            &preimage_bits,
            self.params
        )?.get_x().clone();
        cs.enforce(|| "image_calculated === image", |lc| lc + image.get_variable(), |lc| lc + CS::one(), |lc| lc + image_calculated.get_variable());
        Ok(())
    }
}



fn randFr() -> Fr {
    let mut data = [0u8; 32];
    let mut rng = OsRng.fill_bytes(&mut data);
    data[31] &= 0x3f;
    let res : Fr = unsafe { transmute(data) };
    return res;
}

// pub fn test_proof(){
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    // let rng = &mut thread_rng();
    // let pedersen_params = &JubjubBls12::new();

    // let preimage = randFr();

    // let hasher = PedersenHasherBls12::default();
    // let mut hash = hasher.hash(preimage);

    // logs(format!("preimage: {:?}\n", preimage));
    // logs(format!("hash: {:?}\n", hash));
    
    // let params = {
    //     let c = PedersenDemo::<Bls12> {
    //         params: pedersen_params,
    //         hash: None,
    //         preimage: None
    //     };
    //     generate_random_parameters(c, rng).unwrap()
    // };

    // let hasher = PedersenHasherBls12::default();
    // let mut hash = preimage;
    // for _ in 0..5 {
    //     hash = hasher.hash(hash);
    // }
    // println!("Preimage: {}", preimage.clone());
    // println!("Hash: {}", hash.clone());

    // println!("Creating parameters...");
    // let params = {
    //     let c = PedersenDemo::<Bn256> {
    //         params: pedersen_params,
    //         hash: None,
    //         preimage: None
    //     };
    //     generate_random_parameters(c, rng).unwrap()
    // };

    // // Prepare the verification key (for proof verification)
    // let pvk = prepare_verifying_key(&params.vk);

    // println!("Checking constraints...");
    // let c = PedersenDemo::<Bn256> {
    //     params: pedersen_params,
    //     hash: Some(hash.clone()),
    //     preimage: Some(preimage.clone())
    // };
    // let mut cs = TestConstraintSystem::<Bn256>::new();
    // c.synthesize(&mut cs).unwrap();
    // println!("Unconstrained: {}", cs.find_unconstrained());
    // let err = cs.which_is_unsatisfied();
    // if err.is_some() {
    //     panic!("ERROR satisfying in: {}", err.unwrap());
    // }

    // println!("Creating proofs...");
    // let c = PedersenDemo::<Bn256> {
    //     params: pedersen_params,
    //     hash: Some(hash.clone()),
    //     preimage: Some(preimage.clone())
    // };
    // let stopwatch = std::time::Instant::now();
    // let proof = create_random_proof(c, &params, rng).unwrap();
    // println!("Proof time: {}ms", stopwatch.elapsed().as_millis());

    // let result = verify_proof(
    //     &pvk,
    //     &proof,
    //     &[hash]
    // ).unwrap();
    // assert!(result, "Proof is correct");
//}



#[wasm_bindgen]
pub fn run() -> String {
    let mut preimage = [0u8; 32];
    let mut rng = OsRng.fill_bytes(&mut preimage);
    let hasher = PedersenHasherBls12::default();
    //let res = format!("{:?}", hasher.hash(unsafe { transmute(preimage) }));
    logs(format!("preimage value {:?}", hasher.hash(unsafe { transmute(preimage) })));
    return String::from("");
}

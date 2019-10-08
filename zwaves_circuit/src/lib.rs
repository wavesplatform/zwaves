#![feature(test)]

extern crate test;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use pairing::bls12_381::{Bls12, Fr};
use rand::os::OsRng;
use rand::Rng;



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


#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    use zwaves_primitives::hasher::PedersenHasherBls12;
    //use sapling_crypto::circuit::test::TestConstraintSystem;


    #[test]
    pub fn test_pedersen_proof(){
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut OsRng::new().unwrap();
        let pedersen_params = &JubjubBls12::new();

        let preimage = rng.gen();
        let hasher = PedersenHasherBls12::default();
        let image = hasher.hash(preimage);

        println!("Preimage: {}", preimage);
        println!("Hash: {}", image);

        println!("Creating parameters...");
        let params = {
            let c = PedersenDemo::<Bls12> {
                params: pedersen_params,
                image: None,
                preimage: None
            };
            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        /*
        println!("Checking constraints...");
        let c = PedersenDemo::<Bls12> {
            params: pedersen_params,
            image: Some(image),
            preimage: Some(preimage)
        };
        
        let mut cs = TestConstraintSystem::<Bls12>::new();
        c.synthesize(&mut cs).unwrap();
        println!("Unconstrained: {}", cs.find_unconstrained());
        let err = cs.which_is_unsatisfied();
        if err.is_some() {
            panic!("ERROR satisfying in: {}", err.unwrap());
        }
        */

        println!("Creating proofs...");
        let c = PedersenDemo::<Bls12> {
            params: pedersen_params,
            image: Some(image),
            preimage: Some(preimage)
        };
        let stopwatch = std::time::Instant::now();
        let proof = create_random_proof(c, &params, rng).unwrap();
        println!("Proof time: {}ms", stopwatch.elapsed().as_millis());

        let result = verify_proof(
            &pvk,
            &proof,
            &[image]
        ).unwrap();
        assert!(result, "Proof is correct");
    }

    #[bench]
    fn bench_pedersen_proof_create(b: &mut Bencher) {
        let rng = &mut OsRng::new().unwrap();
        let pedersen_params = &JubjubBls12::new();

        let preimage = rng.gen();
        let hasher = PedersenHasherBls12::default();
        let image = hasher.hash(preimage);

        let params = {
            let c = PedersenDemo::<Bls12> {
                params: pedersen_params,
                image: None,
                preimage: None,
            };
            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        b.iter(|| {
            let c = PedersenDemo::<Bls12> {
                params: pedersen_params,
                image: Some(image),
                preimage: Some(preimage),
            };
            create_random_proof(c, &params, rng).unwrap()
        });
    }

    #[bench]
    fn bench_pedersen_proof_verify(b: &mut Bencher) {
        let rng = &mut OsRng::new().unwrap();
        let pedersen_params = &JubjubBls12::new();

        let preimage = rng.gen();
        let hasher = PedersenHasherBls12::default();
        let image = hasher.hash(preimage);

        let params = {
            let c = PedersenDemo::<Bls12> {
                params: pedersen_params,
                image: None,
                preimage: None,
            };
            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        let c = PedersenDemo::<Bls12> {
            params: pedersen_params,
            image: Some(image),
            preimage: Some(preimage),
        };
        let stopwatch = std::time::Instant::now();
        let proof = create_random_proof(c, &params, rng).unwrap();

        b.iter(||
            verify_proof(&pvk, &proof, &[image]).unwrap());
    }
}
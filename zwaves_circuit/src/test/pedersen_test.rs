use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use pairing::bls12_381::{Bls12, Fr};
use rand::os::OsRng;
use rand::Rng;



#[derive(Clone)]
pub struct PedersenDemo<E: JubjubEngine> {
    pub params: Box<E::Params>,
    pub image: Option<E::Fr>,
    pub preimage: Option<E::Fr>
}

impl <E: JubjubEngine> Circuit<E> for PedersenDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let image = AllocatedNum::alloc(cs.namespace(|| "signal public input image"), || self.image.ok_or(SynthesisError::AssignmentMissing))?;
        image.inputize(cs.namespace(|| "image inputize"));
        let preimage = AllocatedNum::alloc(cs.namespace(|| "signal input preimage"), || self.preimage.ok_or(SynthesisError::AssignmentMissing))?;
        let preimage_bits = preimage.into_bits_le_strict(cs.namespace(|| "preimage_bits <== bitify(preimage)"))?;
        let image_calculated = pedersen_hash::pedersen_hash(
            cs.namespace(|| "image_calculated <== pedersen_hash(preimage_bits)"),
            pedersen_hash::Personalization::NoteCommitment,
            &preimage_bits,
            &self.params
        )?.get_x().clone();
        cs.enforce(|| "image_calculated === image", |lc| lc + image.get_variable(), |lc| lc + CS::one(), |lc| lc + image_calculated.get_variable());
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
//    use test::Bencher;
    use zwaves_primitives::pedersen_hasher;
    //use sapling_crypto::circuit::test::TestConstraintSystem;


    #[test]
    pub fn test_pedersen_proof(){
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut OsRng::new().unwrap();
        let params = JubjubBls12::new();

        let preimage = rng.gen();
        
        let image = pedersen_hasher::hash::<Bls12>(&preimage, &params);

        println!("Preimage: {}", preimage);
        println!("Hash: {}", image);

        println!("Creating parameters...");
        let params = {
            let c = PedersenDemo::<Bls12> {
                params: Box::new(JubjubBls12::new()),
                image: None,
                preimage: None
            };
            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let tvk = prepare_verifying_key(&params.vk);


        println!("Creating proofs...");
        let c = PedersenDemo::<Bls12> {
            params: Box::new(JubjubBls12::new()),
            image: Some(image),
            preimage: Some(preimage)
        };
        let stopwatch = std::time::Instant::now();
        let proof = create_random_proof(c, &params, rng).unwrap();
        println!("Proof time: {}ms", stopwatch.elapsed().as_millis());

        let result = verify_proof(
            &tvk,
            &proof,
            &[image]
        ).unwrap();
        assert!(result, "Proof is correct");
    }


}
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, create_random_proof};
use pairing::bls12_381::{Bls12, Fr};
use rand::os::OsRng;
use rand::Rng;

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use zwaves_primitives::verifier::{truncate_verifying_key, TruncatedVerifyingKey, verify_proof};
use zwaves_primitives::serialization::write_fr_iter;

use base64::encode;


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
    use zwaves_primitives::hasher::PedersenHasherBls12;
    //use sapling_crypto::circuit::test::TestConstraintSystem;


    #[test]
    pub fn test_get_vectors(){
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut OsRng::new().unwrap();

        let preimage = rng.gen();
        let hasher = PedersenHasherBls12::default();
        let image = hasher.hash(preimage);

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
        let tvk = truncate_verifying_key(&params.vk);



        println!("Creating proofs...");
        let c = PedersenDemo::<Bls12> {
            params: Box::new(JubjubBls12::new()),
            image: Some(image),
            preimage: Some(preimage)
        };
        
        let proof = create_random_proof(c, &params, rng).unwrap();
        
        let mut tvk_c = Cursor::new(Vec::new());
        tvk.write(&mut tvk_c);
        tvk_c.seek(SeekFrom::Start(0)).unwrap();
        let mut tvk_b = Vec::new();
        tvk_c.read_to_end(&mut tvk_b).unwrap();
        println!("VK: {}", base64::encode(&tvk_b));

        let mut proof_c = Cursor::new(Vec::new());
        proof.write(&mut proof_c);
        proof_c.seek(SeekFrom::Start(0)).unwrap();
        let mut proof_b = Vec::new();
        proof_c.read_to_end(&mut proof_b).unwrap();
        println!("Proof: {}", base64::encode(&proof_b));

        let inputs = vec![image];


        let mut inputs_b = vec![0u8;32];
        write_fr_iter((&inputs).into_iter(), &mut inputs_b);

        println!("Inputs: {}", base64::encode(&inputs_b));

        let result = verify_proof(
            &tvk,
            &proof,
            &inputs
        ).unwrap();
        assert!(result, "Proof is correct");
    }
}

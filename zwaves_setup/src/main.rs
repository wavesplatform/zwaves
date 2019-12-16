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


fn main() {
    let rng = &mut OsRng::new().unwrap();
    let mut params = phase2::MPCParameters::new(PedersenDemo::<Bls12> {
        params: Box::new(JubjubBls12::new()),
        image: None,
        preimage: None
    }).unwrap();

    let hash = params.contribute(rng);

    let contributions = params.verify(PedersenDemo::<Bls12> {
        params: Box::new(JubjubBls12::new()),
        image: None,
        preimage: None
    }).expect("parameters should be valid!");

    assert!(phase2::contains_contribution(&contributions, &hash));

    println!("MPC contribution processed OK");
}

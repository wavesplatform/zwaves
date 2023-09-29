extern crate zwaves_jni;

use std::io::Cursor;

use ff::Field;
use pairing_ce::{bn256::*, CurveAffine, CurveProjective};
use rand::{Rand, SeedableRng, XorShiftRng};
use zwaves_jni::bn256::{
    serialization::write_fr_iter,
    verifier::{Proof, TruncatedVerifyingKey},
};

fn main() {
    const NINPUTS: usize = 1;
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    const SAMPLES: usize = 1000;

    let v = (0..SAMPLES)
        .map(|_| {
            let inputs = (0..NINPUTS).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let mut inputs_buff = vec![0u8; 32 * NINPUTS];
            write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();

            let ic = (0..NINPUTS + 1)
                .map(|_| G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();

            let mut x_sum = ic[0].into_projective();
            for i in 1..NINPUTS + 1 {
                let mut t = ic[i].into_projective();
                t.mul_assign(inputs[i - 1]);
                x_sum.add_assign(&t);
            }
            let g1_gen = x_sum.into_affine();
            let g2_gen = G2::rand(&mut rng).into_affine();

            let a_1 = Fr::one();
            let a_2 = Fr::rand(&mut rng);
            let a_3 = Fr::rand(&mut rng);
            let b_1 = Fr::one();
            let b_2 = Fr::rand(&mut rng);
            let b_3 = Fr::rand(&mut rng);
            let b_4 = Fr::rand(&mut rng);

            let mut a_4 = Fr::zero();
            let mut t = a_1;
            t.mul_assign(&b_1);
            a_4.add_assign(&t);
            t = a_2;
            t.mul_assign(&b_2);
            a_4.add_assign(&t);
            t = a_3;
            t.mul_assign(&b_3);
            a_4.add_assign(&t);
            a_4.mul_assign(&b_4.inverse().unwrap());

            let vk = TruncatedVerifyingKey::<Bn256> {
                alpha_g1: g1_gen.mul(a_3).into_affine(),
                beta_g2: g2_gen.mul(b_3).into_affine(),
                gamma_g2: g2_gen.clone(),
                delta_g2: g2_gen.mul(b_2).into_affine(),
                ic,
            };
            let mut vk_buff = Cursor::new(Vec::<u8>::new());
            vk.write(&mut vk_buff).unwrap();

            let proof = Proof::<Bn256> {
                a: g1_gen.mul(a_4).into_affine(),
                b: g2_gen.mul(b_4).into_affine(),
                c: g1_gen.mul(a_2).into_affine(),
            };
            let mut proof_buff = Cursor::new(Vec::<u8>::new());
            proof.write(&mut proof_buff).unwrap();

            //let res = crate::verifier::verify_proof(&vk, &proof, &inputs).unwrap_or(false);
            //assert!(res, "groth16_verify should be true");

            (
                base64::encode(vk_buff.get_ref()),
                base64::encode(proof_buff.get_ref()),
                base64::encode(&inputs_buff),
            )
        })
        .collect::<Vec<_>>();

    println!("{:?}", v);
}

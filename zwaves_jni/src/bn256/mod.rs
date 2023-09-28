use std::io;

use pairing_ce::bn256::{Bn256, Fr};
use serialization::read_fr_vec;
use verifier::{TruncatedVerifyingKey, verify_proof};
use verifier::Proof;

pub mod serialization;
pub mod verifier;

pub fn groth16_verify(vk: &[u8], proof: &[u8], inputs: &[u8]) -> io::Result<u8> {
    let buff_vk_len = vk.len();
    let buff_proof_len = proof.len();
    let buff_inputs_len = inputs.len();

    if (buff_vk_len % 32 != 0) || (buff_inputs_len % 32 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let inputs_len = buff_inputs_len / 32;

    if ((buff_vk_len / 32) != (inputs_len + 8)) || (buff_proof_len != 128) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let vk = TruncatedVerifyingKey::<Bn256>::read(vk)?;
    let proof = Proof::<Bn256>::read(proof)?;
    let inputs = read_fr_vec::<Fr>(inputs)?;

    if (inputs.len() != inputs_len) || (vk.ic.len() != (inputs_len + 1)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer parsing",
        ));
    }

    Ok(verify_proof(&vk, &proof, inputs.as_slice())
        .map(|r| r as u8)
        .unwrap_or(0))
}

#[cfg(test)]
mod local_tests {
    use base64::decode;

    use super::*;

    #[test]
    fn test_groth16_verify_binaries_ok() {
        let (vk, proof, inputs) = ("LDCJzjgi5HtcHEXHfU8TZz+ZUHD2ZwsQ7JIEvzdMPYKYs9SoGkKUmg1yya4TE0Ms7x+KOJ4Ze/CPfKp2s5jbniFNM71N/YlHVbNkytLtQi1DzReSh9SNBsvskdY5mavQJe+67PuPVEYnx+lJ97qIG8243njZbGWPqUJ2Vqj49NAunhqX+eIkK3zAB3IPWls3gruzX2t9wrmyE9cVVvf1kgWx63PsQV37qdH0KcFRpCH89k4TPS6fLmqdFxX3YGHCGFTpr6tLogvjbUFJPT98kJ/xck0C0B/s8PTVKdao4VQHT4DBIO8+GB3CQVh6VV4EcMLtDWWNxF4yloAlKcFT0Q4AzJSimpFqd/SwSz9Pb7uk5srte3nwphVamC+fHlJt", "GQPBoHuCPcIosF+WZKE5jZV13Ib4EdjLnABncpSHcMKBZl0LhllnPxcuzExIQwhxcfXvFFAjlnDGpKauQ9OQsjBKUBsdBZnGiV2Sg4TSdyHuLo2AbRRqJN0IV3iH3On8I4ngnL30ZAxVyGQH2EK58aUZGxMbbXGR9pQdh99QaiE=", "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQo=");

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();

        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(res, "groth16_verify should be true");
    }
}

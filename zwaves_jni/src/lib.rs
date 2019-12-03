#[cfg(test)]
pub mod test;

use jni::JNIEnv;
use jni::sys::{jboolean, jbyteArray, jlong};
use jni::objects::{JObject, JValue, JClass};

use pairing::bls12_381::{Fr, FrRepr, Bls12};
use pairing::{Engine, PrimeField, Field, PrimeFieldRepr};

use bellman::groth16::{Proof};

use std::{mem, io, iter};
use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt};

use zwaves_primitives::hasher::PedersenHasherBls12;
use zwaves_primitives::serialization::{read_fr_repr_be, read_fr_vec};
use zwaves_primitives::verifier::{TruncatedVerifyingKey, verify_proof};


fn parse_jni_bytes(env: &JNIEnv, jv: jbyteArray) -> Vec<u8> {
    let v_len = env.get_array_length(jv).unwrap() as usize;
    let mut v = vec![0i8; v_len];
    env.get_byte_array_region(jv, 0, &mut v[..]);
    
    unsafe {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);
        Vec::from_raw_parts(ptr as *mut u8, len, cap)
    }
}





fn groth16_verify(vk:&[u8], proof:&[u8], inputs:&[u8]) -> io::Result<u8> {
    
    let buff_vk_len = vk.len();
    let buff_proof_len = proof.len();
    let buff_inputs_len = inputs.len();

    if (buff_vk_len % 48 != 0) || (buff_inputs_len % 32 != 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
    }
        
    
    let inputs_len = buff_inputs_len / 32;

    if ((buff_vk_len / 48) != (inputs_len + 8)) || (buff_proof_len != 192) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
    }


    let vk = TruncatedVerifyingKey::<Bls12>::read(vk)?;
    let proof = Proof::<Bls12>::read(proof)?;
    let inputs = read_fr_vec::<Fr>(inputs)?;

    if (inputs.len() != inputs_len) || (vk.ic.len() != (inputs_len + 1)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer parsing"));
    } 
    
    Ok(verify_proof(
        &vk,
        &proof,
        inputs.as_slice()
    ).map(|r| r as u8).unwrap_or(0))
}







fn pedersen_merkle_tree_add_item(root: &[u8], sibling:&[u8], index: u64, leaf:&[u8]) -> io::Result<Vec<u8>> {
    let buff_root_len = root.len();
    let buff_sibling_len = sibling.len();
    let buff_leaf_len = leaf.len();
    
    let fr_repr_sz = mem::size_of::<FrRepr>();

    if (buff_leaf_len % 32 != 0) || (buff_sibling_len % 32 != 0) || (buff_root_len != 32) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
    }

    let root = Fr::from_repr(read_fr_repr_be::<Fr>(root)?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, "not in field"))?;
    let sibling = read_fr_vec::<Fr>(sibling)?;
    let leaf = read_fr_vec::<Fr>(leaf)?;

    if (leaf.len() * 32 != buff_leaf_len) || (sibling.len() * 32 != buff_sibling_len) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer read"));
    }

    let hasher = PedersenHasherBls12::default();
    let (root, proof) = hasher.update_merkle_root_and_proof(&root, &sibling, index, &leaf)?;

    let mut res = vec![0u8; fr_repr_sz*(proof.len()+1)];

    for (i, e) in iter::once(root).chain(proof.into_iter()).enumerate() {
        e.into_repr().write_be(&mut res[fr_repr_sz*i ..])?;
    }
    Ok(res)

}



#[no_mangle]
pub extern "system" fn Java_com_wavesplatform_zwaves_bls12_Groth16_verify(env: JNIEnv,
                                             class: JClass,
                                             jvk: jbyteArray,
                                             jproof: jbyteArray,
                                             jinputs: jbyteArray)
                                             -> jboolean {
    
    let vk = parse_jni_bytes(&env, jvk);
    let proof = parse_jni_bytes(&env, jproof);
    let inputs = parse_jni_bytes(&env, jinputs);

    groth16_verify(&vk, &proof, &inputs).unwrap_or(0u8)

}



#[no_mangle]
pub extern "system" fn Java_com_wavesplatform_zwaves_bls12_PedersenMerkleTree_addItem(env: JNIEnv,
                                             class: JClass,
                                             root: jbyteArray,
                                             sibling: jbyteArray,
                                             index: jlong,
                                             leaf: jbyteArray)
                                             -> jbyteArray {

    let root = parse_jni_bytes(&env, root);
    let sibling = parse_jni_bytes(&env, sibling);
    let index = index as u64;
    let leaf = parse_jni_bytes(&env, leaf);

    let result = pedersen_merkle_tree_add_item(&root, &sibling, index, &leaf).unwrap_or(vec![]);

    env.byte_array_from_slice(result.as_slice()).unwrap()

}

#[cfg(test)]
mod tests {
    use base64::decode;
    use super::*;

    #[test]
    fn test_groth16_verify_binaries_ok() {

        let vk = "hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r";
        let proof = "lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF";
        let inputs = "LcMT3OOlkHLzJBKCKjjzzVMg+r+FVgd52LlhZPB4RFg=";

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();


        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(res, "groth16_verify should be true");
    }

    #[test]
    fn test_groth16_verify_binaries_notok() {

        let vk = "hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r";
        let proof = "lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF";
        let inputs = "cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=";

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();


        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(!res, "groth16_verify should be false");
    
    }

    #[test]
    fn test_groth16_verify_binaries_bad_data() {

        let vk = "hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r";
        let proof = "lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF";
        let inputs = "cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=";

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();


        let res = groth16_verify(&vk, &proof, &inputs[0..1]).unwrap_or(0) != 0;
        assert!(!res, "groth16_verify should be false");
    
    }

    #[test]
    fn test_pedersen_merkle_tree_add_item() {
        let root0 = decode("YK6g9RXHtw3vE3zmjCGCdLqrij2BwvPCO0E8Bm977ks=").unwrap();
        let proof0 = decode("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").unwrap();
        let root_and_proof1 = decode("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").unwrap();

        let elements1 = decode("GrfbyxFPhfTsam3aY8yqeY072ZrT3DTO8SrSRg4nJZ9nF1OpFPuvXQlcbsqFrGUkgUlokbCealGEw0J8G/H2oWFOY3CHDDhqBQGzUzk+/R3uYljv0YS/Wnb41IKeDSzfDcrJ41FdxBXgptFlh+TM3OKlgJ2jSAF9mqE3v7dUD/1n6conMUMPB+yeP5fapHBGu2OtlDmiHjzuGG6xrrW7tW45mNToh8yTb+POgZP+IvCmf7b8Tzzs0Z9fv998Q5HdXwrH6ts1cC9GBn9GwlWiDxfbKHKE+XS86tNoGPje5MFE7fWtv5XKzkGirbKRuKsBrLDrwl4UwaruqMwk1jJ4jTnsYzLpaGW7nZ46g+Mx5THu8481Kl7zWTFyRXVLIlvCc3eI3oqsjglbnCZ/7xgG4mnlDWqKYBuWzkmm6pCXB0JV7p+/1G7KcT7SIYoWUdf/XPedxh3N3Qgp3xhyh2VpcAMiK9JrMi8j4EQEsxE9Qm58z8aZ+fGBDkEJPaX0TJ1mDQvC4jQH6Sw96KjRLwezomn2Y5rtXcsxqX5UEhuYk39cxPBUX1tC5ap9qn0IPJaQ1Aj7tZvKhm4H1z3zAdwILTzjXYFOE2NyGZub0DY0g16XZKzhOCrtyeSauxm2pRzjNOFKLyEnk8/8a4bAXfODxGA4tCoBlv8ixFGa1agonvVPMc9FP6/S/26YEL491LGZsnqQ5AvvPt1oe/TmcfK/P1AxgsO2chZPqwddisQNRinb8x5NE8ptEWh9He7uutE/LeAGQVN5BYNpEMijP1RDj1FQkDFgglvvh6rgqm7sZr4lh/8wInwzJMMVTN9Dw1uvRHI5Igir1gcvs0vbuqhAf1NRcY5tnD6PxSTl79M1SkTpg1MSmpYJcISdoFNmfq0LVRUyp47f6gjWt+qVkyJAe3xp0GaEmaMKvvj2xVxLdxRRlRRTYABMFjU63LBttYjn0e1qkAvv1JveIrreATBq5Q==").unwrap();


        let root_and_proof1_cmp = pedersen_merkle_tree_add_item(&root0, &proof0, 23, &elements1).unwrap_or(vec![]);

    

        assert!(root_and_proof1.iter().zip(root_and_proof1_cmp.iter()).all( |(&a,&b)| a==b), "new root and proof should be valid");
    }


}
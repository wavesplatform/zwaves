#[cfg(test)]
pub mod tests;

use jni::JNIEnv;
use jni::sys::{jboolean, jbyteArray, jlong};
use jni::objects::{JObject, JValue, JClass};

use pairing::bls12_381::{Fr, FrRepr, Bls12};
use pairing::{Engine, PrimeField, Field, PrimeFieldRepr};

use bellman::groth16::{Proof};

use std::{mem, io, iter};
use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt};

use zwaves_primitives::serialization::{read_fr_repr_be, read_fr_vec};
use zwaves_primitives::verifier::{TruncatedVerifyingKey, verify_proof};


fn parse_jni_bytes(env: &JNIEnv, jv: jbyteArray) -> Vec<u8> {
    let v_len = env.get_array_length(jv).unwrap() as usize;
    let mut v = vec![0i8; v_len];
    env.get_byte_array_region(jv, 0, &mut v[..]).unwrap();
    
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



#[cfg(test)]
mod local_tests {
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


}
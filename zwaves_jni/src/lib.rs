use std::mem;

use jni::{
    objects::JClass,
    sys::{jboolean, jbyteArray},
    JNIEnv,
};

pub mod bls12;
pub mod bn256;

#[no_mangle]
pub extern "system" fn Java_com_wavesplatform_zwaves_bls12_Groth16_verify(
    env: JNIEnv,
    _class: JClass,
    jvk: jbyteArray,
    jproof: jbyteArray,
    jinputs: jbyteArray,
) -> jboolean {
    let vk = parse_jni_bytes(&env, jvk);
    let proof = parse_jni_bytes(&env, jproof);
    let inputs = parse_jni_bytes(&env, jinputs);

    bls12::groth16_verify(&vk, &proof, &inputs).unwrap_or(0u8)
}

#[no_mangle]
pub extern "system" fn Java_com_wavesplatform_zwaves_bn256_Groth16_verify(
    env: JNIEnv,
    _class: JClass,
    jvk: jbyteArray,
    jproof: jbyteArray,
    jinputs: jbyteArray,
) -> jboolean {
    let vk = parse_jni_bytes(&env, jvk);
    let proof = parse_jni_bytes(&env, jproof);
    let inputs = parse_jni_bytes(&env, jinputs);

    bn256::groth16_verify(&vk, &proof, &inputs).unwrap_or(0u8)
}

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

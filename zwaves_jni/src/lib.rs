extern crate bincode;

use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::{jboolean, jbyteArray, jlong};
use std::mem;

use zwaves_primitives::serialization::{verifying_key, proof, frs};
use bellman::groth16::verify_proof;
use pairing::bls12_381::{Fr, FrRepr};
use zwaves_primitives::serialization::objects::Bls12Fr;
use zwaves_primitives::hasher::PedersenHasherBls12;
use jni::{objects::JObject, objects::JValue};

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

#[no_mangle]
pub extern "system" fn Java_Groth16_verify(env: JNIEnv,
                                             class: JClass,
                                             jvk: jbyteArray,
                                             jproof: jbyteArray,
                                             jinputs: jbyteArray)
                                             -> jboolean {
    
    let vk = parse_jni_bytes(&env, jvk);
    let proof = parse_jni_bytes(&env, jproof);
    let inputs = parse_jni_bytes(&env, jinputs);

    let vk = match verifying_key::deserialize(vk) { Ok(val) => val, Err(_) => return 0u8 };
    let proof = match proof::deserialize(proof) { Ok(val) => val, Err(_) => return 0u8 };
    let inputs: Vec<Fr> = match frs::deserialize(inputs) { Ok(val) => val, Err(_) => return 0u8 };

    // todo add check/assert for length of IC vector and inputs IC.len() == inputs.len()+1

    verify_proof(
        &vk,
        &proof,
        inputs.as_slice()
    ).unwrap().into()
}


#[no_mangle]
pub extern "system" fn Java_Bls12PedersenMerkleTree_addItem(env: JNIEnv,
                                             class: JClass,
                                             sibling: jbyteArray,
                                             index: jlong,
                                             leaf: jbyteArray)
                                             -> jbyteArray {

    let sibling = parse_jni_bytes(&env, sibling);
    let index = index as i64;
    let leaf = parse_jni_bytes(&env, leaf);

    let sibling: Vec<Fr> = match frs::deserialize(sibling) { Ok(val) => val, Err(_) => return env.new_byte_array(0).unwrap() };
    let leaf: Vec<Fr> = match frs::deserialize(leaf) { Ok(val) => val, Err(_) => return env.new_byte_array(0).unwrap() };

    let hasher = PedersenHasherBls12::default();

    let proof = hasher.update_merkle_proof(sibling.as_slice(), index as u64, leaf.as_slice());
    let serialized = frs::serialize(&proof);

    env.byte_array_from_slice(serialized.as_slice()).unwrap()
}

#[cfg(test)]
mod tests {
    // todo add tests
    #[test]
    fn it_works() {}
}
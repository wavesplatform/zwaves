extern crate bincode;

use jni::JNIEnv;
use jni::sys::{jboolean, jbyteArray, jlong};
use jni::objects::{JObject, JValue, JClass};

use pairing::bls12_381::{Fr, FrRepr, Bls12};
use pairing::{Engine, PrimeField, Field, PrimeFieldRepr};

use bellman::groth16::{verify_proof, Proof, TruncatedVerifyingKey};

use std::{mem, io};
use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};

use zwaves_primitives::hasher::PedersenHasherBls12;


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



fn read_fr_repr_be<R:Read, S:PrimeFieldRepr>(reader: &mut R, fr_repr: &mut S ) -> io::Result<()> {
    for digit in fr_repr.as_mut().iter_mut().rev() {
        *digit = reader.read_u64::<BigEndian>()?;
    }
    Ok(())
}

fn read_fr_vec<E:Engine, R:Read>(mut reader: R) -> io::Result<Vec<E::Fr>> {
    let mut fr_repr = E::Fr::zero().into_repr();
    let mut inputs = vec![];

    while read_fr_repr_be(&mut reader, &mut fr_repr).is_ok() {
        let fr = E::Fr::from_repr(fr_repr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, "not in field"))?;
        inputs.push(fr);
    }

    Ok(inputs)
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
    let inputs = read_fr_vec::<Bls12, _>(inputs)?;

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
pub extern "system" fn Java_com_wavesplatform_zwaves_Groth16_verify(env: JNIEnv,
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



// fn bls12_pedersen_merkle_tree_add_item(sibling:&[u8], leaf:&[u8], index: u64) -> io::Result<Vec<u8>> {
//     let buff_sibling_len = sibling.len();
//     let buf_leaf_len = leaf.len();

//     if (buf_leaf_len % 32 != 0) || (buff_sibling_len % 32 != 0) {
//         return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
//     }

//     let sibling = read_fr_vec::<Bls12, _>(sibling)?;
//     let leaf = read_fr_vec::<Bls12, _>(leaf)?;

//     if (leaf.len() * 32 != buf_leaf_len) || (sibling.len() * 32 != buff_sibling_len) {
//         return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer read"));
//     }

//     let hasher = PedersenHasherBls12::default();
//     let hash = hasher.update_merkle_proof(sibling.as_slice(), index, leaf.as_slice())?;


// }


// #[no_mangle]
// pub extern "system" fn Java_com_wavesplatform_zwaves_Bls12PedersenMerkleTreeAddItem(env: JNIEnv,
//                                              class: JClass,
//                                              sibling: jbyteArray,
//                                              index: jlong,
//                                              leaf: jbyteArray)
//                                              -> jbyteArray {

//     let sibling = parse_jni_bytes(&env, sibling);
//     let index = index as i64;
//     let leaf = parse_jni_bytes(&env, leaf);

//     let sibling: Vec<Fr> = match frs::deserialize(sibling) { Ok(val) => val, Err(_) => return env.new_byte_array(0).unwrap() };
//     let leaf: Vec<Fr> = match frs::deserialize(leaf) { Ok(val) => val, Err(_) => return env.new_byte_array(0).unwrap() };

//     let hasher = PedersenHasherBls12::default();

//     let proof = hasher.update_merkle_proof(sibling.as_slice(), index as u64, leaf.as_slice());
//     let serialized = frs::serialize(&proof);

//     env.byte_array_from_slice(serialized.as_slice()).unwrap()
// }

#[cfg(test)]
mod tests {
    // todo add tests
    #[test]
    fn it_works() {}
}
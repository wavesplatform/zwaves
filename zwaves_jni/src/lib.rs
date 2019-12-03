extern crate bincode;

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



fn read_fr_repr_be<Fr:PrimeField>(data: &[u8]) -> io::Result<Fr::Repr> {
    let mut fr_repr = Fr::zero().into_repr();

    match fr_repr.read_be(data) {
        Err(e) => return Err(e),
        _ => {}
    }
    Ok(fr_repr)
}

fn read_fr_vec<Fr:PrimeField>(data: &[u8]) -> io::Result<Vec<Fr>> {
    let mut inputs = vec![];
    
    let mut offset = 0;
    let fr_repr_sz = mem::size_of::<Fr::Repr>();

    loop {
        let fr_repr =  match read_fr_repr_be::<Fr>(&data[offset..]) {
            Ok(x) => x,
            _ => break
        };

        offset+=fr_repr_sz;
        let fr = Fr::from_repr(fr_repr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, "not in field"))?;
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
    // todo add tests
    #[test]
    fn it_works() {}
}
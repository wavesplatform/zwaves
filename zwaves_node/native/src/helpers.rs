use neon::prelude::*;
use neon::types::Value;
use pairing::bls12_381::{Fr, Bls12};
use pairing::{Field, PrimeField, PrimeFieldRepr};

use rand::os::OsRng;
use rand::Rng;


use std::mem::transmute;
use std::io::Cursor;


use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::pedersen_hash::{Personalization};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use bellman::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use zwaves_circuit::circuit::{Transfer, MERKLE_PROOF_LEN};
use zwaves_primitives::transactions::NoteData;
use zwaves_primitives::fieldtools::fr_to_repr_bool;
use zwaves_primitives::serialization::read_fr_repr_be;
use arrayvec::ArrayVec;

use zwaves_primitives::verifier;



lazy_static! {
    pub static ref JUBJUB_PARAMS : JubjubBls12 = JubjubBls12::new();
}


pub fn buf_copy_from_slice(cx: &FunctionContext, source: &[u8], buf: &mut Handle<JsBuffer>) {
    cx.borrow_mut(buf, |data| {
        data.as_mut_slice().copy_from_slice(source);
    });
}

pub fn read_obj_fr(cx: &mut FunctionContext, obj: Handle<JsObject>, key: &str) -> NeonResult<Fr> {
    let value = obj.get(cx, key)?;
    read_val_fr(cx, value)
}

pub fn read_val_fr(cx: &mut FunctionContext, val: Handle<JsValue>) -> NeonResult<Fr> {
    let buff_field = val.downcast::<JsBuffer>().or_else(|_| cx.throw_error("could not downcast value to Buffer"))?;
    let buff_field_slice = cx.borrow(&buff_field, |data| data.as_slice());
    let repr = read_fr_repr_be::<Fr>(buff_field_slice).or_else(|_| cx.throw_error("Buffer must be uint256 BE number"))?;
    Fr::from_repr(repr).or_else(|_| cx.throw_error("Wrong field element"))
}


pub fn read_buf_fr(cx: &mut FunctionContext, buff_field: Handle<JsBuffer>) -> NeonResult<Fr> {
    let buff_field_slice = cx.borrow(&buff_field, |data| data.as_slice());
    let repr = read_fr_repr_be::<Fr>(buff_field_slice).or_else(|_| cx.throw_error("Buffer must be uint256 BE number"))?;
    Fr::from_repr(repr).or_else(|_| cx.throw_error("Wrong field element"))
}

pub fn parse_note_data(cx: &mut FunctionContext, note_obj:Handle<JsObject>) -> NeonResult<NoteData<Bls12>> {
    Ok(NoteData::<Bls12> {
        asset_id: read_obj_fr(cx, note_obj, "asset_id")?,
        amount: read_obj_fr(cx, note_obj, "amount")?,
        native_amount: read_obj_fr(cx, note_obj, "native_amount")?,
        txid: read_obj_fr(cx, note_obj, "txid")?,
        owner: read_obj_fr(cx, note_obj, "owner")?
    })
}

pub fn fr_to_js<'a>(cx: &mut FunctionContext<'a>, fr: &Fr) -> JsResult<'a, JsBuffer> {
    let mut buff = Cursor::new(Vec::<u8>::new());
    fr.into_repr().write_be(&mut buff).unwrap();

    let mut hash_js_buf = JsBuffer::new(cx, buff.get_ref().len() as u32)?;
    buf_copy_from_slice(cx, buff.get_ref(), &mut hash_js_buf);
    Ok(hash_js_buf)
}

pub fn proof_to_js<'a>(cx: &mut FunctionContext<'a>, proof: &Proof<Bls12>) -> JsResult<'a, JsBuffer> {
    let mut proof_cur = Cursor::new(Vec::<u8>::new());
    proof.write(&mut proof_cur).unwrap();
    let mut proof_js_buf = JsBuffer::new(cx, proof_cur.get_ref().len() as u32)?;
    buf_copy_from_slice(cx, proof_cur.get_ref(), &mut proof_js_buf);
    Ok(proof_js_buf)
}

pub fn verifier_to_js<'a>(cx: &mut FunctionContext<'a>, verifier: &verifier::TruncatedVerifyingKey<Bls12>) -> JsResult<'a, JsBuffer> {
    let mut verifier_cur = Cursor::new(Vec::<u8>::new());
    verifier.write(&mut verifier_cur).unwrap();
    let mut verifier_js_buf = JsBuffer::new(cx, verifier_cur.get_ref().len() as u32)?;
    buf_copy_from_slice(cx, verifier_cur.get_ref(), &mut verifier_js_buf);
    Ok(verifier_js_buf)
}

pub fn parse_pair<'a, U:Value>(cx: &mut FunctionContext<'a>, value:Handle<'a, JsValue>) -> NeonResult<[Handle<'a, U>;2]> {
    let value = value.downcast::<JsArray>()
        .or_else(|_| cx.throw_error("Could not downcast value to Array"))?
        .to_vec(cx)?;
    if value.len()!= 2 {
        return cx.throw_error("in_note length should be 2");
    }

    let value = value.into_iter().map(|item| item.downcast::<U>().or_else(|_| cx.throw_error("downcast pair item error")))
        .collect::<NeonResult<ArrayVec<[Handle<'a, U>;2]>>>()?.into_inner().or_else(|_| cx.throw_error("Array was not completely filled"))?;
    Ok(value)
}
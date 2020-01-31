#[macro_use] extern crate neon;
#[macro_use] extern crate lazy_static;
extern crate pairing;
extern crate sapling_crypto;
extern crate bellman;
extern crate zwaves_circuit;
extern crate zwaves_primitives;
extern crate phase2;
extern crate rand;

use neon::prelude::*;

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
use zwaves_circuit::circuit::Deposit;
use zwaves_primitives::transactions::NoteData;
use zwaves_primitives::serialization::read_fr_repr_be;



lazy_static! {
    static ref jubjub_params : JubjubBls12 = JubjubBls12::new();
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
    let buff_field = val.downcast::<JsBuffer>().map_err(|_| neon::result::Throw)?;
    let buff_field_slice = cx.borrow(&buff_field, |data| data.as_slice());
    let repr = read_fr_repr_be::<Fr>(buff_field_slice).map_err(|_| cx.throw_error::<_,Fr>("Buffer must be uint256 BE number").unwrap_err())?;
    Fr::from_repr(repr).map_err(|_| cx.throw_error::<_,Fr>("Wrong field element").unwrap_err())
}


pub fn read_buf_fr(cx: &mut FunctionContext, buff_field: Handle<JsBuffer>) -> NeonResult<Fr> {
    let buff_field_slice = cx.borrow(&buff_field, |data| data.as_slice());
    let repr = read_fr_repr_be::<Fr>(buff_field_slice).map_err(|_| cx.throw_error::<_,Fr>("Buffer must be uint256 BE number").unwrap_err())?;
    Fr::from_repr(repr).map_err(|_| cx.throw_error::<_,Fr>("Wrong field element").unwrap_err())
}



pub fn verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let mpc_params_buff : Handle<JsBuffer> = cx.argument(0)?;
    let mpc_params_slice = cx.borrow(&mpc_params_buff, |data| data.as_slice());

    let params = phase2::MPCParameters::read(mpc_params_slice, false).unwrap();
    let groth16_params = params.get_params();

    let pvk = prepare_verifying_key(&groth16_params.vk);

    let proof_buff : Handle<JsBuffer> = cx.argument(1)?;
    let proof_buff_slice = cx.borrow(&proof_buff, |data| data.as_slice());

    let proof = Proof::<Bls12>::read(proof_buff_slice).map_err(|_| cx.throw_error::<_,Fr>("Wrong proof format").unwrap_err())?;

    let public_inputs : Handle<JsArray> = cx.argument(2)?;
    let public_inputs = public_inputs.to_vec(&mut cx)?;
    let public_inputs = public_inputs.iter().map(|&x| read_val_fr(&mut cx, x)).collect::<NeonResult<Vec<Fr>>>()?;

    let res = verify_proof(&pvk, &proof, &public_inputs).map_err(|_| cx.throw_error::<_,Fr>("Error during proof verification").unwrap_err())?;
    Ok(JsBoolean::new(&mut cx, res))

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


pub fn note_hash(mut cx: FunctionContext) ->JsResult<JsBuffer> {
    let note_obj : Handle<JsObject> = cx.argument(0)?;
    let note = parse_note_data(&mut cx, note_obj)?;
    
    let hash = zwaves_primitives::transactions::note_hash(&note, &jubjub_params);
    fr_to_js(&mut cx, &hash)
}


pub fn deposit(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let mut rng = OsRng::new().unwrap();
    let mpc_params_buff : Handle<JsBuffer> = cx.argument(0)?;
    let mpc_params_slice = cx.borrow(&mpc_params_buff, |data| data.as_slice());

    let note_obj : Handle<JsObject> = cx.argument(1)?;
    let params = phase2::MPCParameters::read(mpc_params_slice, false).unwrap();
    

    let note = parse_note_data(&mut cx, note_obj)?;

    let c = Deposit::<Bls12> {
        params: &jubjub_params,
        data: Some(note)
    };

    let proof = create_random_proof(c, params.get_params(), &mut rng).unwrap();
    

    let mut proof_cur = Cursor::new(Vec::<u8>::new());
    proof.write(&mut proof_cur).unwrap();

    let mut proof_js_buf = JsBuffer::new(&mut cx, proof_cur.get_ref().len() as u32)?;
    buf_copy_from_slice(&cx, proof_cur.get_ref(), &mut proof_js_buf);

    Ok(proof_js_buf)
}


pub fn merkle_hash(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let left_handle = cx.argument::<JsBuffer>(0)?;
    let left = read_buf_fr(&mut cx, left_handle)?;
    let right_handle = cx.argument::<JsBuffer>(1)?;
    let right = read_buf_fr(&mut cx, right_handle)?;
    let n = cx.argument::<JsNumber>(2)?.value();
    if n.fract() != 0.0 {
        return cx.throw_error("3rd parameter needs to be integer");
    }
    let hash = zwaves_primitives::pedersen_hasher::compress::<Bls12>(&left, &right, Personalization::MerkleTree(n.round() as usize), &jubjub_params);
    fr_to_js(&mut cx, &hash)
}



register_module!(mut cx, {
    cx.export_function("verify", verify)?;
    cx.export_function("deposit", deposit)?;
    cx.export_function("merkleHash", merkle_hash)?;
    cx.export_function("noteHash", note_hash)
    
});

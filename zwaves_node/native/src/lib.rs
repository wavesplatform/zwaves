#[macro_use] extern crate neon;
#[macro_use] extern crate lazy_static;
extern crate arrayvec;
extern crate pairing;
extern crate sapling_crypto;
extern crate bellman;
extern crate zwaves_circuit;
extern crate zwaves_primitives;
extern crate phase2;
extern crate rand;

pub mod helpers;

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
use zwaves_circuit::circuit::{Deposit, Transfer, FEE, MERKLE_PROOF_LEN};
use zwaves_primitives::transactions::NoteData;
use zwaves_primitives::fieldtools::fr_to_repr_bool;
use zwaves_primitives::serialization::read_fr_repr_be;
use arrayvec::ArrayVec;

use crate::helpers::*;





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



pub fn note_hash(mut cx: FunctionContext) ->JsResult<JsBuffer> {
    let note_obj : Handle<JsObject> = cx.argument(0)?;
    let note = parse_note_data(&mut cx, note_obj)?;
    
    let hash = zwaves_primitives::transactions::note_hash(&note, &JUBJUB_PARAMS);
    fr_to_js(&mut cx, &hash)
}

pub fn nullifier(mut cx: FunctionContext) ->JsResult<JsBuffer> {
    let note_hash : Handle<JsBuffer> = cx.argument(0)?;
    let note_hash = read_buf_fr(&mut cx, note_hash)?;
    let sk : Handle<JsBuffer> = cx.argument(1)?;
    let sk = read_buf_fr(&mut cx, sk)?;
    let nf = zwaves_primitives::transactions::nullifier::<Bls12>(&note_hash, &sk, &JUBJUB_PARAMS);
    fr_to_js(&mut cx, &nf)
}

pub fn pubkey(mut cx: FunctionContext) ->JsResult<JsBuffer> {
    let sk : Handle<JsBuffer> = cx.argument(0)?;
    let sk = read_buf_fr(&mut cx, sk)?;
    let nf = zwaves_primitives::transactions::pubkey::<Bls12>(&sk, &JUBJUB_PARAMS);
    fr_to_js(&mut cx, &nf)
}

pub fn edh(mut cx: FunctionContext) ->JsResult<JsBuffer> {
    let pk : Handle<JsBuffer> = cx.argument(0)?;
    let pk = read_buf_fr(&mut cx, pk)?;
    let sk : Handle<JsBuffer> = cx.argument(1)?;
    let sk = read_buf_fr(&mut cx, sk)?;
    let nf = zwaves_primitives::transactions::edh::<Bls12>(&pk, &sk, &JUBJUB_PARAMS).ok_or(()).or_else(|_| cx.throw_error("Not an elliptic curve point"))?;
    fr_to_js(&mut cx, &nf)
}








pub fn deposit(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let mut rng = OsRng::new().unwrap();
    let mpc_params_buff : Handle<JsBuffer> = cx.argument(0)?;
    let mpc_params_slice = cx.borrow(&mpc_params_buff, |data| data.as_slice());

    let note_obj : Handle<JsObject> = cx.argument(1)?;
    let params = phase2::MPCParameters::read(mpc_params_slice, false).unwrap();
    

    let note = parse_note_data(&mut cx, note_obj)?;

    let c = Deposit::<Bls12> {
        params: &JUBJUB_PARAMS,
        data: Some(note)
    };

    let proof = create_random_proof(c, params.get_params(), &mut rng).unwrap();

    proof_to_js(&mut cx, &proof)
}



pub fn parse_transfer(cx: &mut FunctionContext, transfer_obj:Handle<JsObject>) -> NeonResult<Transfer<'static, Bls12>> {

    let in_note = transfer_obj.get(cx, "in_note")?;
    let in_note = parse_pair::<JsObject>(cx, in_note)?;
    let in_note = in_note.iter().map(|&item| {
        parse_note_data(cx, item).map(|e| Some(e))
    }).collect::<NeonResult<ArrayVec<[Option<NoteData<Bls12>>;2]>>>()?.into_inner().map_err(|_| neon::result::Throw )?;
    
    let out_note = transfer_obj.get(cx, "out_note")?;
    let out_note = parse_pair::<JsObject>(cx, out_note)?;
    let out_note = out_note.iter().map(|&item| {
        parse_note_data(cx, item).map(|e| Some(e))
    }).collect::<NeonResult<ArrayVec<[Option<NoteData<Bls12>>;2]>>>()?.into_inner().map_err(|_| neon::result::Throw )?;
    

    let in_index = transfer_obj.get(cx, "in_proof_index")?;
    let in_index = parse_pair::<JsBuffer>(cx, in_index)?;
    let in_index = in_index.iter().map(|&item| {
        read_buf_fr(cx, item)
    }).collect::<NeonResult<ArrayVec<[Fr;2]>>>()?.into_inner().map_err(|_| neon::result::Throw )?;
    
    
    let in_proof = transfer_obj.get(cx, "in_proof_sibling")?;
    let in_proof = parse_pair::<JsArray>(cx, in_proof)?;

    let in_proof = in_proof.iter().zip(in_index.iter()).map(|(&item, &index)| {
        let item = item.to_vec(cx)?;
        if item.len() != MERKLE_PROOF_LEN {
            return cx.throw_error(format!("Merkle proof length should be {}.", MERKLE_PROOF_LEN));
        }

        if fr_to_repr_bool::<Fr>(&index).into_iter().skip(MERKLE_PROOF_LEN).any(|e| e) {
            return cx.throw_error("Index value should not be bigger than 2^MERKLE_PROOF_LEN");
        }

        let item = item.into_iter().zip(fr_to_repr_bool::<Fr>(&index)).map(|(e, b)| (read_val_fr(cx, e).unwrap(), b)).collect::<Vec<(Fr, bool)>>();
        Ok(Some(item))
    }).collect::<NeonResult<ArrayVec<[Option<Vec<(Fr, bool)>>;2]>>>()?.into_inner().unwrap_or_else(|_| panic!("Array was not completely filled"));

    let root_hash = Some(read_obj_fr(cx, transfer_obj, "root_hash")?);
    let sk = Some(read_obj_fr(cx, transfer_obj, "sk")?);


    Ok(Transfer {
        in_note,
        out_note,
        in_proof,
        root_hash,
        sk,
        params: &JUBJUB_PARAMS
    })
}


pub fn transfer(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let mut rng = OsRng::new().unwrap();
    let mpc_params_buff : Handle<JsBuffer> = cx.argument(0)?;
    let mpc_params_slice = cx.borrow(&mpc_params_buff, |data| data.as_slice());

    let transfer_obj : Handle<JsObject> = cx.argument(1)?;
    let params = phase2::MPCParameters::read(mpc_params_slice, false).unwrap();

    let c = parse_transfer(&mut cx, transfer_obj)?;
    let proof = create_random_proof(c, params.get_params(), &mut rng).unwrap();

    proof_to_js(&mut cx, &proof)
}


pub fn merkle_hash(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let left_handle = cx.argument::<JsBuffer>(0)?;
    let left = read_buf_fr(&mut cx, left_handle)?;
    let right_handle = cx.argument::<JsBuffer>(1)?;
    let right = read_buf_fr(&mut cx, right_handle)?;
    let n = cx.argument::<JsNumber>(2)?.value();
    if n.fract() != 0.0 {
        return cx.throw_error("3rd parameter should be integer");
    }
    let hash = zwaves_primitives::pedersen_hasher::compress::<Bls12>(&left, &right, Personalization::MerkleTree(n.round() as usize), &JUBJUB_PARAMS);
    fr_to_js(&mut cx, &hash)
}



register_module!(mut cx, {
    cx.export_function("verify", verify)?;
    cx.export_function("deposit", deposit)?;
    cx.export_function("transfer", deposit)?;    
    cx.export_function("merkleHash", merkle_hash)?;
    cx.export_function("nullifier", nullifier)?;
    cx.export_function("edh", edh)?;
    cx.export_function("noteHash", note_hash)
    
});

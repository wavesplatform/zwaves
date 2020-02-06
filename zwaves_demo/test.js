const { broadcast, waitForTx, setScript, invokeScript, nodeInteraction } = require("@waves/waves-transactions");
const { address, base58Encode, base58Decode, publicKey, privateKey } = require("@waves/waves-crypto");
const {extract_vk, MerkleTree, transfer, pubkey, fs_random, fr_random, verify, bufferizeBigints, debufferizeBigints, note_hash} = require("../zwaves_node/lib/index.js");

const fs = require("fs");
const env = process.env;
if (env.NODE_ENV !== 'production') {
  require('dotenv').load();
}


function utxo(asset_id, amount, native_amount, txid, owner) {
  return {asset_id, amount, native_amount, txid, owner};
}

const sleep = m => new Promise(r => setTimeout(r, m));

let seed = env.MNEMONIC;
const rpc = env.WAVES_RPC;
const chainId = env.WAVES_CHAINID;


const dAppPk = env.DAPP;
const dApp = address({publicKey:dAppPk}, chainId);
const userAddress = address(seed, chainId);

const buff2bigintBe = (b) => {
  let t = 0;
  let ti = 0;
  let res = 0n;
  for (let i = 0; i < b.length ; i++) {
    t = (t << 8) + b[i];
    ti += 1;
    if (ti == 3) {
      res = (res << 24n) + BigInt(t);
      t = 0;
      ti = 0;
    }
  }
  if (ti > 0) {
    res = (res << BigInt(ti * 8)) + BigInt(t);
  }
  return res;
}

const address2bigint = a => buff2bigintBe(base58Decode(a));

const fee = 900000;
let transferFee = 400000n;
let accumulatorFee = 400000n;

const transfer_mpc = fs.readFileSync("../zwaves_setup/mpc_params_transfer");
const accumulator_mpc = fs.readFileSync("../zwaves_setup/mpc_params_accumulator");



let mt = new MerkleTree(48);
let sk = fs_random();
let pk = pubkey(sk);

let deposit_amount = 10000000n;

let in_note = [utxo(0n, 0n, 0n, fr_random(), pk), utxo(0n, 0n, 0n, fr_random(), pk)];
let in_proof_index = [0n, 0n];
let in_proof_sibling = [Array(48).fill(0n), Array(48).fill(0n)];
let out_note = [utxo(0n, 0n, deposit_amount - accumulatorFee, fr_random(), pk), utxo(0n, 0n, 0n, fr_random(), pk)];
let packed_asset = (deposit_amount - accumulatorFee) << 128n;
let receiver = address2bigint(userAddress);


let data = {
  in_note,
  in_proof_index,
  out_note,
  in_proof_sibling,
  root_hash: mt.root(),
  sk,
  packed_asset,
  receiver

};

console.log(data);
let res = transfer(transfer_mpc, data);

console.log(res);
console.log(verify(extract_vk(transfer_mpc), res));


(async()=>{


console.log(`Waves balance before transfer:\t\t${await nodeInteraction.balance(address(seed, chainId), rpc)}`);

let tx = invokeScript({
  dApp,
  chainId,
  payment: [{ amount: Number(deposit_amount), assetId: null }],
  call: {
  function: "transferExternal",
  args: [{ type: "binary", value: res.proof.toString("base64") }, 
      { type: "binary", value: Buffer.concat(bufferizeBigints(res.publicInputs)).toString("base64") },
      { type: "binary", value: Buffer.from("test").toString("base64") }]
  }, fee
}, seed);
await broadcast(tx, rpc);
console.log(`Waiting for ${tx.id}`);
await waitForTx(tx.id, { apiBase: rpc });
console.log(`transaction complete`)

await sleep(10000);
console.log(`Waves balance after transfer:\t\t${await nodeInteraction.balance(address(seed, chainId), rpc)}`);

/*

let note_hashes = out_note.map(n=>note_hashes(n));
let proof_zero = mt.proof(0).slice(1);
mt.pushMany(note_hashes);
let proof_pair = mt.proof(0).slice(1);

let data = {
    note_hashes: pair,
    proof_index: 0n,
    proof_sibling: [proof_zero, proof_pair]
};

console.log(data);
let vk = extract_vk(mpc_params);
let res = utxoAccumulator(mpc_params, data);
console.log(res);
console.log(verify(vk, res));
*/


})();
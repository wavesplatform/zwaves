let {utxoAccumulator, MerkleTree, fr_random, fs_random, u64_random, 
    verify, u32_random, pubkey, note_hash, randrange, transfer, extract_vk, bufferizeBigints} = require("../lib/index.js");



function utxo_random(fixed) {
    return {
        asset_id:u32_random(),
        amount: u32_random(),
        native_amount: u32_random(),
        txid: fr_random(),
        owner: fr_random(),
        ...fixed
    }
}

function utxo(asset_id, amount, native_amount, txid, owner) {
    return {asset_id, amount, native_amount, txid, owner};
}



let fs = require("fs");
let mpc_params = fs.readFileSync("../zwaves_setup/mpc_params_transfer");


let sk = fs_random();
let pk = pubkey(sk);

let mt = new MerkleTree(48);
let leaves = Array(64).fill(0).map(()=>utxo_random({owner:pk, asset_id:0n, amount:0n}));
let hashes = leaves.map(l=>note_hash(l));

mt.pushMany(hashes);

const i1 = randrange(0, 64);
const i2 = randrange(0, 63);
const in_proof_index = [i1, i2<i1?i2:i2+1];
const in_note = in_proof_index.map(i=>leaves[i]);



const total_native_amount = in_note[0].native_amount + in_note[1].native_amount;
const part1 = total_native_amount/3n;
const out_note = [utxo_random({asset_id:0n, amount:0n, native_amount: part1}), utxo_random({asset_id:0n, amount:0n, native_amount: total_native_amount - part1})];
const in_proof_sibling = in_proof_index.map(i=>mt.proof(i));
const root_hash = mt.root();
const packed_asset = 0n;
const receiver = 0n;


let data = {
    in_note,
    in_proof_index:in_proof_index.map(n=>BigInt(n)),
    out_note,
    in_proof_sibling,
    root_hash,
    sk,
    packed_asset,
    receiver

};


let vk = extract_vk(mpc_params);
console.log(data);
let res = transfer(mpc_params, data);
console.log(res);
console.log(verify(vk, res));

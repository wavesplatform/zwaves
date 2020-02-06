let {utxoAccumulator, MerkleTree, fr_random, verify, extract_vk} = require("../lib/index.js");


let fs = require("fs");
let mpc_params = fs.readFileSync("../zwaves_setup/mpc_params_accumulator");

let mt = new MerkleTree(48);

let leaves = Array(64).fill(0).map(()=>fr_random());

mt.pushMany(leaves.slice(0, 10));
let proof_zero = mt.proof(10).slice(1);
let pair = leaves.slice(10,12);
mt.pushMany(pair);
let proof_pair = mt.proof(10).slice(1);

let data = {
    note_hashes: pair,
    proof_index: 10n,
    proof_sibling: [proof_zero, proof_pair]
};

console.log(data);
let vk = extract_vk(mpc_params);
let res = utxoAccumulator(mpc_params, data);
console.log(res);
console.log(verify(vk, res));

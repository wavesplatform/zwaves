const native = require('../native');
const _ = require("lodash");
const assert = require("assert");
const {toBufferBE, toBigIntBE} = require("bigint-buffer");
const crypto = require("crypto");
const fr_order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const fs_order = 0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n;



function objectMap(object, mapFn) {
    return Object.keys(object).reduce(function(result, key) {
        result[key] = mapFn(object[key])
        return result
    }, {})
}



function _bufferizeBigints(o) {
    if (o instanceof Buffer) { 
        return o;
    } else if ((typeof(o) == "bigint") || o.isZero !== undefined)  {
        return toBufferBE(o, 32);
    } else if (o instanceof Array) {
        return o.map(_bufferizeBigints);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = _bufferizeBigints(o[k]);
        }
        return res;
    } else {
        return o;
    }
}

const bufferizeBigints = (o)=> _bufferizeBigints(_.cloneDeep(o));


function _debufferizeBigints(o) {
    if (o instanceof Buffer && o.length == 32) { 
        return toBigIntBE(o);
    } else if (o instanceof Array) {
        return o.map(_debufferizeBigints);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = _debufferizeBigints(o[k]);
        }
        return res;
    } else {
        return o;
    }
}

const debufferizeBigints = (o)=> _debufferizeBigints(_.cloneDeep(o));

function randrange(from, to) {
    if (from == to)
        return from;
    if (from > to)
        [from, to] = [to, from];
    const interval = to - from;
    if (typeof from === "number")
        return from + Math.floor(Math.random() * interval);
    let t = 0;
    while (interval > (1n << BigInt(t*8)))
        t++;
    return from + toBigIntBE(crypto.randomBytes(t)) % interval;
}

function merkleHash(a, b, l) {
    assert(l<63, "Merkle level should be lesser 63");
    return debufferizeBigints(native.merkle_hash(bufferizeBigints(a), bufferizeBigints(b), l));
}

function utxoAccumulator(mpc_params, data) {
    const proof = native.utxo_accumulator(mpc_params, bufferizeBigints(data));
    const pair_hash = merkleHash(data.note_hashes[0], data.note_hashes[1], 0);
    const zero_hash = merkleHash(0n, 0n, 0);
    
    const roots = [zero_hash, pair_hash].map((leaf, i) => MerkleTree.getRoot(data.proof_sibling[i], data.proof_index, leaf, 1));
    const publicInputs = [...data.note_hashes, data.proof_index, ...roots];
    return {proof, publicInputs};
}

const nullifier = (hash, sk) => debufferizeBigints(native.nullifier(bufferizeBigints(hash), bufferizeBigints(sk)));


function transfer(mpc_params, data) {
    const proof = native.transfer(mpc_params, bufferizeBigints(data));
    const nf = data.in_note.map(n => nullifier(note_hash(n), data.sk));
    const out_hash = data.out_note.map(n=>note_hash(n));
    const publicInputs = [data.receiver, data.root_hash, data.packed_asset, ...out_hash, ...nf];
    return {proof, publicInputs};
}



function verify(mpc_params, {proof, publicInputs}) {
    return native.verify(mpc_params, proof, bufferizeBigints(publicInputs));
}


const fs_random = ()=>randrange(0n, fs_order);
const fr_random = ()=>randrange(0n, fr_order);
const u64_random = ()=>randrange(0n, 2n**64n);
const u32_random = ()=>randrange(0n, 2n**32n);

const extract_vk = (mpc_params) => native.extract_vk(mpc_params);
const note_hash = (note) => debufferizeBigints(native.note_hash(bufferizeBigints(note)));
const pubkey = (sk) => debufferizeBigints(native.pubkey(bufferizeBigints(sk)));

const maxheight = 64;
const merkleDefaults = Array(maxheight);
merkleDefaults[0] = 0n;
for (let i = 1; i < maxheight; i++) {
  merkleDefaults[i] = merkleHash(merkleDefaults[i-1], merkleDefaults[i-1], i-1);
}



class MerkleTree{
    constructor(proof_length) {
        assert(proof_length < maxheight, `height should be less or equal ${maxheight}`);
        this.proof_length = proof_length;
        this._merkleState = Array(proof_length+1).fill(0).map(() => []);
    }

    cell(row, index) {
        index = BigInt(index);
        assert(row <= this.proof_length, "too big row");
        if (index < this.size(row)) {
            return this._merkleState[row][index];
        } else {
            return merkleDefaults[row];
        }
    }

    size(n) {
        n = typeof n === "undefined" ? 0 : n;
        return BigInt(this._merkleState[n].length);
    }

    pushMany(elements) {
        let index = this.size();
        let s = BigInt(elements.length);
        this._merkleState[0].push(...elements);

        for (let i = 1; i<= this.proof_length; i++) {
            let rl = this.size(i);
            this._merkleState[i].push(...Array(parseInt(1n + (index+s>>BigInt(i)) - rl)).fill(0n));
            
            for (let j = (index >> BigInt(i)); j <= (index+s>>BigInt(i)); j++) {
                this._merkleState[i][j] = merkleHash(this.cell(i-1, j*2n), this.cell(i-1, j*2n+1n), i-1);
            }
        }
    }

    root() {
        return this.cell(this.proof_length, 0n)
    }

    proof(index, offset) {
        index = BigInt(index);
        offset = typeof offset === "undefined" ? 0 : offset;
        return Array(this.proof_length).fill(0).map((o, i) => this.cell(i, (index >> BigInt(i))^1n)).slice(offset);
    }

    static getRoot(proof, index, leaf, offset) {
        index = BigInt(index);
        offset = typeof offset === "undefined" ? 0 : offset;
        let root = leaf;
        for(let i = 0; i < proof.length; i++) {
            root = ((index >> BigInt(i + offset)) & 1n) == 0n ? merkleHash(root, proof[i], i+offset) : merkleHash(proof[i], root, i+offset);
        }
        return root;
    }
}




module.exports = {MerkleTree, merkleDefaults, merkleHash, utxoAccumulator, verify, fr_random, fs_random, u64_random, fr_order, fs_order, extract_vk, u32_random, note_hash, pubkey,
    randrange, nullifier, transfer, bufferizeBigints, debufferizeBigints}; 


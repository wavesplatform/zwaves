const native = require('../native');
const _ = require("lodash");
const assert = require("assert");
const {toBufferBE, toBigIntBE} = require("bigint-buffer");

const fr_order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const fs_order = 0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n;

// cx.export_function("verify", verify)?;
// cx.export_function("deposit", deposit)?;
// cx.export_function("transfer", deposit)?;    
// cx.export_function("merkleHash", merkleHash)?;
// cx.export_function("nullifier", nullifier)?;
// cx.export_function("edh", edh)?;
// cx.export_function("noteHash", note_hash)


function objectMap(object, mapFn) {
    return Object.keys(object).reduce(function(result, key) {
        result[key] = mapFn(object[key])
        return result
    }, {})
}



function bufferizeBigints(o) {
    if (o instanceof Buffer) { 
        return o;
    } else if ((typeof(o) == "bigint") || o.isZero !== undefined)  {
        return toBufferBE(o, 32);
    } else if (o instanceof Array) {
        return o.map(bufferizeBigints);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = bufferizeBigints(o[k]);
        }
        return res;
    } else {
        return o;
    }
}


function debufferizeBigints(o) {
    if (o instanceof Buffer && o.length == 32) { 
        return toBigIntBE(o);
    } else if (o instanceof Array) {
        return o.map(debufferizeBigints);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = debufferizeBigints(o[k]);
        }
        return res;
    } else {
        return o;
    }
}

function randrange(from, to) {
    if (from == to)
        return from;
    if (from > to)
        [from, to] = [to, from];
    const interval = to - from;
    if (typeof from === "number")
        return from + Math.floor(Math.random() * interval);
    let t = 0;
    while (interval > bigInt.one.shl(t*8))
        t++;
    return from + bigInt.leBuff2int(crypto.randomBytes(t)) % interval;
}

function merkleHash(a, b, l) {
    assert(l<63, "Merkle level should be lesser 63");
    return debufferizeBigints(native.merkleHash(bufferizeBigints(a), bufferizeBigints(b), l));
}


const fs_random = ()=>randrange(0n, fs_order);
const fr_random = ()=>randrange(0n, fr_order);
const u64_random = ()=>randrange(0n, 2n**64n);


const maxheight = 64;
const merkleDefaults = Array(maxheight);
merkleDefaults[0] = 0n;
for (let i = 1; i < maxheight; i++) {
  merkleDefaults[i] = merkleHash(merkleDefaults[i-1], merkleDefaults[i-1], i-1);
}


class MerkleTree {

    constructor(height) {
        assert(height <= maxheight, `height should be less or equal ${maxheight}`);
        this.height = height;
        this._merkleState = Array(this.height).fill(0).map(() => []);
    }

  _cell(row, index) {
    return index < this._merkleState[row].length ? this._merkleState[row][index] : merkleDefaults[row];
  }

  push(leaf) {
    let pos = this._merkleState[0].length;
    this._merkleState[0][pos] = leaf;
    for (let i = 1; i < this.height; i++) {
      pos = pos >>> 1;
      this._merkleState[i][pos] = merkleHash(this._cell(i - 1, pos * 2), this._cell(i - 1, pos * 2 + 1), i-1);
    }
  }

  proof(index) {
    return Array(this.height - 1).fill(0).map((e, i) => this._cell(i, (index >>> i) ^ 1));
  }

  static computeRoot(pi, index, leaf) {
    let root = leaf;
    for (let i = 0; i < pi.length; i++) {
      root = ((index >>> i) & 1) == 0 ? merkleHash(root, pi[i], i) : merkleHash(pi[i], root, i);
    }
    return root;
  }

  get root() {
    return this._cell(this.height - 1, 0);
  }

  pushMany(elements) {
    const index = this._merkleState[0].length;
    const s = elements.length;
    assert((index+s)<=(2**(this.height-1)), "too many elements");
    this._merkleState[0].push(...elements);

    for(let i = 1; i < this.height; i++) {
      for(let j = index>>>i; j<=(index+s)>>>i; j++) {
        this._merkleState[i][j] = merkleHash(this._cell(i-1, j*2), this._cell(i-1, j*2+1), i-1);
      }
    }
  }



  static updateProof(sibling, index, elements) {
    index = BigInt(index);
    let proofsz = BigInt(sibling.length);
    let elementssz = BigInt(elements.length);
    let index2 = index + elementssz;
    let maxproofsz = merkleDefaults.length;
    assert(proofsz <= maxproofsz, "too many long proof");
    assert(index2 < 1n << BigInt(proofsz), "too many elements");
    let sibling2 = [];
  
    if (elementssz == 0n) {
      for (let i = 0n; i < proofsz; i++) {
          sibling2.push(sibling[i]);
      }
    } else {
      let offset = index & 1n;
      let buffsz = offset + elementssz;
      let buffsz_was_odd = (buffsz & 1n) == 1n;
  
      let buff = [];
      
      if (offset > 0n) {
          buff.push(sibling[0]);
      }
      
      for (let i = 0n; i< elementssz; i++) {
          buff.push(elements[i]);
      }
  
      if (buffsz_was_odd) {
          buff.push(merkleDefaults[0]);
          buffsz ++;
      }
  
      let sibling2_i = offset + (index2 ^ 1n) - index;
      sibling2.push(sibling2_i >= buffsz ? merkleDefaults[0] : buff[sibling2_i]);
  
      for(let i = 1n; i < proofsz; i++) {
          offset = (index >> i) & 1n;
          for(let j = 0n; j < buffsz >> 1n; j++)
              buff[offset+j] = merkleHash(buff[j*2n], buff[j*2n+1n], i-1);
        
          if (offset > 0n) {
              buff[0] = sibling[i];
          }
  
          buffsz = offset + (buffsz>>1n);
          buffsz_was_odd = (buffsz & 1n) == 1n;
          if (buffsz_was_odd) {
              buff[buffsz] = merkleDefaults[i];
              buffsz ++;
          } 
  
          sibling2_i = offset + (((index2 >> i) ^ 1n) - (index >> i));
          sibling2.push(sibling2_i >= buffsz ? merkleDefaults[i] : buff[sibling2_i] );
      };
    }
  
    return sibling2;
  
  }


  static getRoot(proof, index, leaf) {
      let root = leaf;
      for(let i in proof) {
          root = (index >>> i) & 0x1 == 1 ? merkleHash(proof[i], root, i) : merkleHash(root, proof[i], i);
      }
      return root;
  }

  static genRandomRightProof(length, index) {
      let pi = Array(length).fill(0n);
      for (let i=0; i<length; i++) {
          pi[i] = (index >>> i) & 0x1 == 1 ? fr_random() : merkleDefaults[i];
      }
      return pi;
  }

}




module.exports = {MerkleTree, merkleDefaults, merkleHash}; 


let native = require("../lib/index.js");
let {toBufferBE} = require("bigint-buffer");

let fs = require("fs");
let mpc_params = fs.readFileSync("../zwaves_setup/mpc_params_deposit");


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

let note = {
    asset_id: 1n, 
    amount: 2n,
    native_amount: 3n,
    txid: 4n,
    owner: 5n
};



let proof = native.deposit(mpc_params, bufferizeBigints(note));
console.log("Proof: ", proof);
let hash = native.noteHash(bufferizeBigints(note));
console.log("UTXO hash: ", hash);
let verify_result = native.verify(mpc_params, proof, bufferizeBigints([hash, note.asset_id, note.amount, note.native_amount]));
console.log("Verifier result", verify_result);
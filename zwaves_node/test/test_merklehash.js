const {MerkleTree, bufferizeBigints} = require("../lib/index");
const bs58 = require('bs58')

let mt = new MerkleTree(48);
console.log(bs58.encode(bufferizeBigints(mt.root())));
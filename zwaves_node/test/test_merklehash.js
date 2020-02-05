const {MerkleTree} = require("../lib/index");

let mt = new MerkleTree(32+1);
console.log(mt.root);
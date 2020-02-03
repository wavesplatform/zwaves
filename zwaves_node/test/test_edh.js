let native = require("../lib/index.js");
let {toBufferBE} = require("bigint-buffer");


  

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


let edh = native.edh(bufferizeBigints(3n), bufferizeBigints(2n));
console.log(edh);


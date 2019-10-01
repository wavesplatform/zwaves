import * as wasm from "../zwaves_wasm/pkg";

//wasm.greet();

window.log = x => console.log(x);
window.logs = x => console.log(x);

console.log(wasm.run());

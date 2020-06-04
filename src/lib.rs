extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

#[wasm_bindgen]
pub fn isPoint(p: JsBuffer) -> bool {
    true
}

#[wasm_bindgen]
pub fn isPointCompressed(p: JsBuffer) -> bool {
    true
}

#[wasm_bindgen]
pub fn isPrivate(x: JsBuffer) -> bool {
    true
}
#[wasm_bindgen]
pub fn pointAdd(pA: JsBuffer, pB: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn pointAddScaler(p: JsBuffer, tweak: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn pointCompress(p: JsBuffer, compressed: Option<bool>) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen]
pub fn pointFromScalar(d: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn pointMultiply(p: JsBuffer, tweak: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn privateAdd(d: JsBuffer,  tweak: JsBuffer) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn privateSub(d: JsBuffer,  tweak: JsBuffer) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn sign(hash: JsBuffer,  x: JsBuffer) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen]
pub fn signWithEntropy(hash: JsBuffer,  x: JsBuffer, addData: JsValue) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen]
pub fn verify(hash: JsBuffer,  q: JsBuffer, signature: JsValue, compressed: Option<bool>) -> bool { // strict flag is not found in js impl (See #5)
    true
}

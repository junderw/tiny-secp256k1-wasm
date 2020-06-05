extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;
use js_sys::TypeError;
use secp256k1::{Message, Secp256k1, SecretKey};

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
pub fn sign(hash: JsBuffer,  x: JsBuffer) -> Result<JsBuffer, JsValue> {
    set_panic_hook();
    // How do I check Buffer.isBuffer()?
    if hash.len() != 32 {
        return Err(JsValue::from(TypeError::new("Expected Hash")));
    }
    if x.len() != 32 {
        return Err(JsValue::from(TypeError::new("Expected Private")));
    }
    let secp = Secp256k1::new();
    let msg_hash = Message::from_slice(&hash).unwrap_throw();
    let pk = SecretKey::from_slice(&x).unwrap_throw();
    Ok(Box::new(secp.sign(&msg_hash, &pk).serialize_compact()))
}
#[wasm_bindgen]
pub fn signWithEntropy(hash: JsBuffer,  x: JsBuffer, addData: JsValue) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen]
pub fn verify(hash: JsBuffer,  q: JsBuffer, signature: JsValue, compressed: Option<bool>) -> bool { // strict flag is not found in js impl (See #5)
    true
}

fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

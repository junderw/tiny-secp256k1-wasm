extern crate wasm_bindgen;
extern crate wee_alloc;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use js_sys::TypeError;
use secp256k1::{Message, Secp256k1, SecretKey};
use wasm_bindgen::prelude::*;

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

#[wasm_bindgen(js_name = isPoint)]
#[allow(unused_variables)]
pub fn is_point(p: JsBuffer) -> bool {
    true
}

#[wasm_bindgen(js_name = isPointCompressed)]
#[allow(unused_variables)]
pub fn is_point_compressed(p: JsBuffer) -> bool {
    true
}

#[wasm_bindgen(js_name = isPrivate)]
#[allow(unused_variables)]
pub fn is_private(x: JsBuffer) -> bool {
    true
}
#[wasm_bindgen(js_name = pointAdd)]
#[allow(unused_variables)]
pub fn point_add(p_a: JsBuffer, p_b: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen(js_name = pointAddScalar)]
#[allow(unused_variables)]
pub fn point_add_scalar(
    p: JsBuffer,
    tweak: JsBuffer,
    compressed: Option<bool>,
) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen(js_name = pointCompress)]
#[allow(unused_variables)]
pub fn point_compress(p: JsBuffer, compressed: Option<bool>) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen(js_name = pointFromScalar)]
#[allow(unused_variables)]
pub fn point_from_scalar(d: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen(js_name = pointMultiply)]
#[allow(unused_variables)]
pub fn point_multiply(p: JsBuffer, tweak: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen(js_name = privateAdd)]
#[allow(unused_variables)]
pub fn private_add(d: JsBuffer, tweak: JsBuffer) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen(js_name = privateSub)]
#[allow(unused_variables)]
pub fn private_sub(d: JsBuffer, tweak: JsBuffer) -> Option<JsBuffer> {
    Some(Box::new([0u8]))
}
#[wasm_bindgen]
pub fn sign(hash: JsBuffer, x: JsBuffer) -> Result<JsBuffer, JsValue> {
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
#[wasm_bindgen(js_name = signWithEntropy)]
#[allow(unused_variables)]
pub fn sign_with_entropy(hash: JsBuffer, x: JsBuffer, add_data: JsValue) -> JsBuffer {
    Box::new([0u8])
}
#[wasm_bindgen]
#[allow(unused_variables)]
pub fn verify(hash: JsBuffer, q: JsBuffer, signature: JsValue, compressed: Option<bool>) -> bool {
    // strict flag is not found in js impl (See #5)
    true
}

// fn set_panic_hook() {
//     #[cfg(feature = "console_error_panic_hook")]
//     console_error_panic_hook::set_once();
// }

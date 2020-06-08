extern crate wasm_bindgen;
extern crate wee_alloc;

// use web_sys::console;
//
// pub struct Timer<'a> {
//     name: &'a str,
// }
//
// impl<'a> Timer<'a> {
//     pub fn new(name: &'a str) -> Timer<'a> {
//         console::time_with_label(name);
//         Timer { name }
//     }
// }
//
// impl<'a> Timer<'a> {
//     fn end(&mut self) {
//         console::time_end_with_label(self.name);
//     }
// }

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use js_sys::TypeError;
use secp256k1::{Message, Secp256k1, SecretKey};
use wasm_bindgen::prelude::*;

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

#[wasm_bindgen]
pub struct TinySecp {
    secp: Secp256k1<secp256k1::All>,
}

#[wasm_bindgen]
impl TinySecp {
    pub fn new() -> TinySecp {
        TinySecp {
            secp: Secp256k1::new(),
        }
    }

    #[wasm_bindgen(js_name = isPoint)]
    #[allow(unused_variables)]
    pub fn is_point(&self, p: JsBuffer) -> bool {
        true
    }

    #[wasm_bindgen(js_name = isPointCompressed)]
    #[allow(unused_variables)]
    pub fn is_point_compressed(&self, p: JsBuffer) -> bool {
        true
    }

    #[wasm_bindgen(js_name = isPrivate)]
    #[allow(unused_variables)]
    pub fn is_private(&self, x: JsBuffer) -> bool {
        true
    }
    #[wasm_bindgen(js_name = pointAdd)]
    #[allow(unused_variables)]
    pub fn point_add(
        &self,
        p_a: JsBuffer,
        p_b: JsBuffer,
        compressed: Option<bool>,
    ) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen(js_name = pointAddScalar)]
    #[allow(unused_variables)]
    pub fn point_add_scalar(
        &self,
        p: JsBuffer,
        tweak: JsBuffer,
        compressed: Option<bool>,
    ) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen(js_name = pointCompress)]
    #[allow(unused_variables)]
    pub fn point_compress(&self, p: JsBuffer, compressed: Option<bool>) -> JsBuffer {
        Box::new([0u8])
    }
    #[wasm_bindgen(js_name = pointFromScalar)]
    #[allow(unused_variables)]
    pub fn point_from_scalar(&self, d: JsBuffer, compressed: Option<bool>) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen(js_name = pointMultiply)]
    #[allow(unused_variables)]
    pub fn point_multiply(
        &self,
        p: JsBuffer,
        tweak: JsBuffer,
        compressed: Option<bool>,
    ) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen(js_name = privateAdd)]
    #[allow(unused_variables)]
    pub fn private_add(&self, d: JsBuffer, tweak: JsBuffer) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen(js_name = privateSub)]
    #[allow(unused_variables)]
    pub fn private_sub(&self, d: JsBuffer, tweak: JsBuffer) -> Option<JsBuffer> {
        Some(Box::new([0u8]))
    }
    #[wasm_bindgen]
    pub fn sign(&self, hash: JsBuffer, x: JsBuffer) -> Result<JsBuffer, JsValue> {
        set_panic_hook();
        // How do I check Buffer.isBuffer()?
        if hash.len() != 32 {
            return Err(JsValue::from(TypeError::new("Expected Hash")));
        }
        if x.len() != 32 {
            return Err(JsValue::from(TypeError::new("Expected Private")));
        }
        let msg_hash = Message::from_slice(&hash).unwrap_throw();
        let pk = SecretKey::from_slice(&x).unwrap_throw();
        Ok(Box::new(self.secp.sign(&msg_hash, &pk).serialize_compact()))
    }
    #[wasm_bindgen(js_name = signWithEntropy)]
    #[allow(unused_variables)]
    pub fn sign_with_entropy(&self, hash: JsBuffer, x: JsBuffer, add_data: JsValue) -> JsBuffer {
        Box::new([0u8])
    }
    #[wasm_bindgen]
    #[allow(unused_variables)]
    pub fn verify(
        &self,
        hash: JsBuffer,
        q: JsBuffer,
        signature: JsValue,
        compressed: Option<bool>,
    ) -> bool {
        // strict flag is not found in js impl (See #5)
        true
    }
}

fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

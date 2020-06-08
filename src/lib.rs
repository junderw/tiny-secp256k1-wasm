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
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
pub use secp256k1_sys as ffi;
use secp256k1_sys::CPtr;
use wasm_bindgen::prelude::*;

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

pub fn is_point(ctx_ptr: *const ffi::Context, p: &JsBuffer, pubkey: &mut ffi::PublicKey) -> bool {
    if p.len() != 33 && p.len() != 65 {
        return false;
    }
    unsafe { ffi::secp256k1_ec_pubkey_parse(ctx_ptr, pubkey, p.as_c_ptr(), p.len()) != 0 }
}

pub fn is_order_scalar(tweak: JsBuffer) -> bool {
    if tweak.len() != 32 || &*tweak >= &secp256k1::constants::CURVE_ORDER || &*tweak == [0u8; 32] {
        return false;
    }
    return true;
}

#[wasm_bindgen]
pub struct TinySecp {
    secp: Secp256k1<secp256k1::All>,
}

#[wasm_bindgen]
impl TinySecp {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TinySecp {
        TinySecp {
            secp: Secp256k1::new(),
        }
    }

    #[wasm_bindgen(js_name = isPoint)]
    #[allow(unused_variables)]
    pub fn is_point(&self, p: JsBuffer) -> bool {
        if p.len() != 33 && p.len() != 65 {
            return false;
        }
        is_point(*self.secp.ctx(), &p, &mut ffi::PublicKey::new())
    }

    #[wasm_bindgen(js_name = isPointCompressed)]
    #[allow(unused_variables)]
    pub fn is_point_compressed(&self, p: JsBuffer) -> Result<bool, JsValue> {
        let has_proper_len = p.len() == 33;
        if !self.is_point(p) {
            return Err(JsValue::from(TypeError::new("Expected Point")));
        }
        Ok(has_proper_len)
    }

    #[wasm_bindgen(js_name = isPrivate)]
    #[allow(unused_variables)]
    pub fn is_private(&self, x: JsBuffer) -> bool {
        unsafe { ffi::secp256k1_ec_seckey_verify(*self.secp.ctx(), x.as_c_ptr()) == 1 }
    }
    #[wasm_bindgen(js_name = pointAdd)]
    #[allow(unused_variables)]
    pub fn point_add(
        &self,
        p_a: JsBuffer,
        p_b: JsBuffer,
        compressed: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let puba = PublicKey::from_slice(&p_a)
            .map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;
        let pubb = PublicKey::from_slice(&p_b)
            .map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;

        let key_option = match puba.combine(&pubb) {
            Ok(a) => Some(a),
            Err(_) => None,
        };

        if key_option == None {
            return Ok(JsValue::NULL);
        }

        let result = key_option.unwrap();

        let is_compressed = compressed.unwrap_or(p_a.len() == 33);

        if is_compressed {
            unsafe {
                let array = js_sys::Uint8Array::view(&mut result.serialize());
                return Ok(JsValue::from(array));
            }
        } else {
            unsafe {
                let array = js_sys::Uint8Array::view(&mut result.serialize_uncompressed());
                return Ok(JsValue::from(array));
            }
        }
    }
    #[wasm_bindgen(js_name = pointAddScalar)]
    #[allow(unused_variables)]
    pub fn point_add_scalar(
        &self,
        p: JsBuffer,
        tweak: JsBuffer,
        compressed: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let tweak_clone = tweak.clone();
        if !is_order_scalar(tweak) {
            return Err(JsValue::from(TypeError::new("Expected Tweak")));
        }
        let mut pubkey = ffi::PublicKey::new();
        if !is_point(*self.secp.ctx(), &p, &mut pubkey) {
            return Err(JsValue::from(TypeError::new("Expected Point")));
        }

        let mut puba = PublicKey::from_slice(&p)
            .map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;

        let key_option = match puba.add_exp_assign(&self.secp, &tweak_clone) {
            Ok(a) => Some(a),
            Err(_) => None,
        };

        if key_option == None {
            return Ok(JsValue::NULL);
        }

        let result = key_option.unwrap();

        let is_compressed = compressed.unwrap_or(p.len() == 33);

        if is_compressed {
            unsafe {
                let array = js_sys::Uint8Array::view(&mut puba.serialize());
                return Ok(JsValue::from(array));
            }
        } else {
            unsafe {
                let array = js_sys::Uint8Array::view(&mut puba.serialize_uncompressed());
                return Ok(JsValue::from(array));
            }
        }
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

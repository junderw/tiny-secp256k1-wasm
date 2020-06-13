#[macro_use]
extern crate lazy_static;

use js_sys::TypeError;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use secp256k1_sys as ffi;
use secp256k1_sys::CPtr;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const ZERO: [u8; 32] = [0u8; 32];

lazy_static! {
    static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

fn is_point_internal(
    ctx_ptr: *const ffi::Context,
    p: &JsBuffer,
    pubkey: &mut ffi::PublicKey,
) -> bool {
    let plen = p.len();
    if plen != 33 && plen != 65 {
        return false;
    }
    unsafe { ffi::secp256k1_ec_pubkey_parse(ctx_ptr, pubkey, p.as_c_ptr(), plen) != 0 }
}

fn lt_order(p: &JsBuffer) -> bool {
    for i in 0..32 {
        if p[i] < secp256k1::constants::CURVE_ORDER[i] {
            return true;
        } else if p[i] > secp256k1::constants::CURVE_ORDER[i] {
            return false;
        }
    }
    return false;
}

fn eq_bytes(p: &JsBuffer, q: &[u8; 32]) -> bool {
    for i in 0..32 {
        if p[i] != q[i] {
            return false;
        }
    }
    return true;
}

fn is_private_internal(x: &JsBuffer) -> bool {
    is_tweak(x) && !eq_bytes(x, &ZERO)
}

fn is_tweak(tweak: &JsBuffer) -> bool {
    tweak.len() == 32 && lt_order(tweak)
}

#[wasm_bindgen(js_name = isPoint)]
pub fn is_point(p: JsBuffer) -> bool {
    is_point_internal(*SECP.ctx(), &p, &mut ffi::PublicKey::new())
}

#[wasm_bindgen(js_name = isPointCompressed)]
pub fn is_point_compressed(p: JsBuffer) -> Result<bool, JsValue> {
    let has_proper_len = p.len() == 33;
    if !has_proper_len {
        return Ok(false);
    }
    if !is_point(p) {
        return Err(JsValue::from(TypeError::new("Expected Point")));
    }
    Ok(has_proper_len)
}

#[wasm_bindgen(js_name = isPrivate)]
pub fn is_private(x: JsBuffer) -> bool {
    is_private_internal(&x)
}

#[wasm_bindgen(js_name = pointAdd)]
pub fn point_add(
    p_a: JsBuffer,
    p_b: JsBuffer,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let puba =
        PublicKey::from_slice(&p_a).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;
    let pubb =
        PublicKey::from_slice(&p_b).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;

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
pub fn point_add_scalar(
    p: JsBuffer,
    tweak: JsBuffer,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let is_compressed = compressed.unwrap_or(p.len() == 33);
    if !is_tweak(&tweak) {
        return Err(JsValue::from(TypeError::new("Expected Tweak")));
    }
    let mut puba =
        PublicKey::from_slice(&p).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;
    if !is_point(p) {
        return Err(JsValue::from(TypeError::new("Expected Point")));
    }

    let key_option = match puba.add_exp_assign(&SECP, &tweak) {
        Ok(a) => Some(a),
        Err(_) => None,
    };

    if key_option == None {
        return Ok(JsValue::NULL);
    }

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
pub fn point_compress(p: JsBuffer, compressed: Option<bool>) -> Result<JsBuffer, JsValue> {
    let is_compressed = compressed.unwrap_or(p.len() == 33);
    let puba =
        PublicKey::from_slice(&p).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;

    if is_compressed {
        Ok(Box::new(puba.serialize()))
    } else {
        Ok(Box::new(puba.serialize_uncompressed()))
    }
}
#[wasm_bindgen(js_name = pointFromScalar)]
pub fn point_from_scalar(d: JsBuffer, compressed: Option<bool>) -> Result<JsBuffer, JsValue> {
    let is_compressed = compressed.unwrap_or(true);
    let sk =
        SecretKey::from_slice(&d).map_err(|_| JsValue::from(TypeError::new("Expected Private")))?;
    let pk = PublicKey::from_secret_key(&SECP, &sk);
    if is_compressed {
        Ok(Box::new(pk.serialize()))
    } else {
        Ok(Box::new(pk.serialize_uncompressed()))
    }
}
#[wasm_bindgen(js_name = pointMultiply)]
pub fn point_multiply(
    p: JsBuffer,
    tweak: JsBuffer,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let is_compressed = compressed.unwrap_or(p.len() == 33);
    let mut pubkey =
        PublicKey::from_slice(&p).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;
    if !is_tweak(&tweak) {
        return Err(JsValue::from(TypeError::new("Expected Tweak")));
    }

    let newpubkey = match pubkey.mul_assign(&SECP, &tweak) {
        Ok(a) => Some(a),
        Err(_) => None,
    };
    if newpubkey == None {
        return Ok(JsValue::NULL);
    }

    if is_compressed {
        unsafe {
            let array = js_sys::Uint8Array::view(&mut pubkey.serialize());
            return Ok(JsValue::from(array));
        }
    } else {
        unsafe {
            let array = js_sys::Uint8Array::view(&mut pubkey.serialize_uncompressed());
            return Ok(JsValue::from(array));
        }
    }
}
#[wasm_bindgen(js_name = privateAdd)]
pub fn private_add(d: JsBuffer, tweak: JsBuffer) -> Result<JsValue, JsValue> {
    let mut sk1 =
        SecretKey::from_slice(&d).map_err(|_| JsValue::from(TypeError::new("Expected Private")))?;
    if !is_tweak(&tweak) {
        return Err(JsValue::from(TypeError::new("Expected Tweak")));
    }

    let result = match sk1.add_assign(&tweak) {
        Ok(a) => Some(a),
        Err(_) => None,
    };
    if result == None {
        return Ok(JsValue::NULL);
    }
    unsafe {
        let array = js_sys::Uint8Array::view(&sk1[..]);
        return Ok(JsValue::from(array));
    }
}
#[wasm_bindgen(js_name = privateSub)]
pub fn private_sub(d: JsBuffer, tweak: JsBuffer) -> Result<JsValue, JsValue> {
    let mut sk1 =
        SecretKey::from_slice(&d).map_err(|_| JsValue::from(TypeError::new("Expected Private")))?;
    if !is_tweak(&tweak) {
        return Err(JsValue::from(TypeError::new("Expected Tweak")));
    }
    let mut tweak_clone = tweak.clone();

    unsafe {
        assert_eq!(
            ffi::secp256k1_ec_privkey_negate(*SECP.ctx(), tweak_clone.as_mut_c_ptr()),
            1
        );
    }

    let result = match sk1.add_assign(&tweak_clone) {
        Ok(a) => Some(a),
        Err(_) => None,
    };
    if result == None {
        return Ok(JsValue::NULL);
    }
    unsafe {
        let array = js_sys::Uint8Array::view(&sk1[..]);
        return Ok(JsValue::from(array));
    }
}
#[wasm_bindgen]
pub fn sign(hash: JsBuffer, x: JsBuffer) -> Result<JsBuffer, JsValue> {
    let msg_hash =
        Message::from_slice(&hash).map_err(|_| JsValue::from(TypeError::new("Expected Hash")))?;
    let pk =
        SecretKey::from_slice(&x).map_err(|_| JsValue::from(TypeError::new("Expected Private")))?;
    Ok(Box::new(SECP.sign(&msg_hash, &pk).serialize_compact()))
}
#[wasm_bindgen(js_name = signWithEntropy)]
pub fn sign_with_entropy(
    hash: JsBuffer,
    x: JsBuffer,
    add_data: Option<JsBuffer>,
) -> Result<JsBuffer, JsValue> {
    let msg =
        Message::from_slice(&hash).map_err(|_| JsValue::from(TypeError::new("Expected Hash")))?;
    let sk =
        SecretKey::from_slice(&x).map_err(|_| JsValue::from(TypeError::new("Expected Private")))?;

    if add_data == None {
        return Ok(Box::new(SECP.sign(&msg, &sk).serialize_compact()));
    }
    let extra_bytes = add_data.unwrap();
    if extra_bytes.len() != 32 {
        return Err(JsValue::from(TypeError::new(
            "Expected Extra Data (32 bytes)",
        )));
    }
    let mut ret = ffi::Signature::new();
    unsafe {
        // We can assume the return value because it's not possible to construct
        // an invalid signature from a valid `Message` and `SecretKey`
        assert_eq!(
            ffi::secp256k1_ecdsa_sign(
                *SECP.ctx(),
                &mut ret,
                msg.as_c_ptr(),
                sk.as_c_ptr(),
                ffi::secp256k1_nonce_function_rfc6979,
                extra_bytes.as_c_ptr() as *const ffi::types::c_void
            ),
            1
        );
    }

    Ok(Box::new(
        secp256k1::Signature::from(ret).serialize_compact(),
    ))
}
#[wasm_bindgen]
pub fn verify(
    hash: JsBuffer,
    q: JsBuffer,
    signature: JsBuffer,
    strict: Option<bool>,
) -> Result<bool, JsValue> {
    let is_strict = strict.unwrap_or(false);
    let pubkey =
        PublicKey::from_slice(&q).map_err(|_| JsValue::from(TypeError::new("Expected Point")))?;
    let msg =
        Message::from_slice(&hash).map_err(|_| JsValue::from(TypeError::new("Expected Hash")))?;
    let mut sig = Signature::from_compact(&signature)
        .map_err(|_| JsValue::from(TypeError::new("Expected Signature")))?;
    if !is_strict {
        sig.normalize_s();
    }
    match SECP.verify(&msg, &sig, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

use js_sys::{TypeError, Uint8Array};
use secp256k1::{Message, PublicKey, SecretKey, Signature, SECP256K1};
use secp256k1_sys as ffi;
use secp256k1_sys::CPtr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const ZERO: [u8; 32] = [0u8; 32];

enum Error {
    BadPrivate,
    BadPoint,
    BadTweak,
    BadHash,
    BadSignature,
    BadExtraData,
}

impl Error {
    fn as_str(&self) -> &str {
        match *self {
            Error::BadPrivate => "Expected Private",
            Error::BadPoint => "Expected Point",
            Error::BadTweak => "Expected Tweak",
            Error::BadHash => "Expected Hash",
            Error::BadSignature => "Expected Signature",
            Error::BadExtraData => "Expected Extra Data (32 bytes)",
        }
    }
}

impl From<Error> for JsValue {
    fn from(error: Error) -> Self {
        JsValue::from(TypeError::new(error.as_str()))
    }
}

// Dummy Node.js Buffer type
// TODO: Replace appropriate type. It might be good to subdivide into `Point`, `Scaler`, etc.
type JsBuffer = Box<[u8]>;

#[wasm_bindgen]
extern "C" {
    pub type Buffer;

    #[wasm_bindgen(static_method_of = Buffer)]
    pub fn from(buffer: JsBuffer) -> Buffer;

    #[wasm_bindgen(js_name = isBuffer, static_method_of = Buffer)]
    pub fn is_buffer(val: &JsValue) -> bool;
}

macro_rules! unwrap_or_jsnullres {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Ok(JsValue::NULL),
        }
    };
}

macro_rules! get_buffer_return {
    ( $val:expr, $err:expr ) => {
        match maybe_buffer($val) {
            Some(v) => v,
            None => return $err,
        }
    };
}

fn maybe_buffer(buf: &JsValue) -> Option<&Uint8Array> {
    if Buffer::is_buffer(buf) {
        Some(buf.unchecked_ref::<Uint8Array>())
    } else {
        None
    }
}

fn pubkey_from_slice(p: &Uint8Array) -> Result<PublicKey, Error> {
    let plen = p.length();
    if plen != 33 && plen != 65 {
        return Err(Error::BadPoint);
    }
    if plen == 33 && p.get_index(0) != 2u8 && p.get_index(0) != 3u8 {
        return Err(Error::BadPoint);
    }
    if plen == 65 && p.get_index(0) != 4u8 {
        return Err(Error::BadPoint);
    }
    PublicKey::from_slice(&p.to_vec()).map_err(|_| Error::BadPoint)
}

fn seckey_from_slice(p: &Uint8Array) -> Result<SecretKey, Error> {
    SecretKey::from_slice(&p.to_vec()).map_err(|_| Error::BadPrivate)
}

fn message_from_slice(p: &Uint8Array) -> Result<Message, Error> {
    Message::from_slice(&p.to_vec()).map_err(|_| Error::BadHash)
}

fn signature_from_slice(p: &Uint8Array) -> Result<Signature, Error> {
    Signature::from_compact(&p.to_vec()).map_err(|_| Error::BadSignature)
}

fn is_point_internal(p: &Uint8Array) -> bool {
    match pubkey_from_slice(p) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn compare_32_bytes(p: &Uint8Array, q: &[u8; 32]) -> i8 {
    for i in 0..32u32 {
        if p.get_index(i) < q[i as usize] {
            return -1;
        } else if p.get_index(i) > q[i as usize] {
            return 1;
        }
    }
    return 0;
}

fn is_private_internal(x: &Uint8Array) -> bool {
    is_tweak(x) && compare_32_bytes(x, &ZERO) != 0
}

fn is_tweak(tweak: &Uint8Array) -> bool {
    tweak.length() == 32 && compare_32_bytes(tweak, &secp256k1::constants::CURVE_ORDER) == -1
}

fn check_tweak(tweak: &Uint8Array) -> Result<(), Error> {
    if !is_tweak(tweak) {
        Err(Error::BadTweak)
    } else {
        Ok(())
    }
}

#[wasm_bindgen(js_name = isPoint)]
pub fn is_point(p: &JsValue) -> bool {
    let buf = get_buffer_return!(p, false);
    is_point_internal(buf)
}

#[wasm_bindgen(js_name = isPointCompressed)]
pub fn is_point_compressed(p: &JsValue) -> Result<bool, JsValue> {
    let buf = get_buffer_return!(p, Ok(false));
    if !is_point_internal(buf) {
        Err(Error::BadPoint)?
    }
    Ok(buf.length() == 33)
}

#[wasm_bindgen(js_name = isPrivate)]
pub fn is_private(x: &JsValue) -> bool {
    let x_buf = get_buffer_return!(x, false);
    is_private_internal(x_buf)
}

#[wasm_bindgen(js_name = pointAdd)]
pub fn point_add(
    p_a: &JsValue,
    p_b: &JsValue,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let buf_a = get_buffer_return!(p_a, Err(JsValue::from(Error::BadPoint)));
    let buf_b = get_buffer_return!(p_b, Err(JsValue::from(Error::BadPoint)));

    let is_compressed = compressed.unwrap_or(buf_a.length() == 33);

    let puba = pubkey_from_slice(&buf_a)?;
    let pubb = pubkey_from_slice(&buf_b)?;

    let result = unwrap_or_jsnullres!(puba.combine(&pubb));

    if is_compressed {
        Ok(JsValue::from(Buffer::from(Box::new(result.serialize()))))
    } else {
        Ok(JsValue::from(Buffer::from(Box::new(
            result.serialize_uncompressed(),
        ))))
    }
}
#[wasm_bindgen(js_name = pointAddScalar)]
pub fn point_add_scalar(
    p: &JsValue,
    tweak: &JsValue,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let buf = get_buffer_return!(p, Err(JsValue::from(Error::BadPoint)));
    let buf_tweak = get_buffer_return!(tweak, Err(JsValue::from(Error::BadTweak)));

    let is_compressed = compressed.unwrap_or(buf.length() == 33);
    let mut puba = pubkey_from_slice(&buf)?;
    check_tweak(&buf_tweak)?;

    unwrap_or_jsnullres!(puba.add_exp_assign(&SECP256K1, &buf_tweak.to_vec()));

    if is_compressed {
        Ok(JsValue::from(Buffer::from(Box::new(puba.serialize()))))
    } else {
        Ok(JsValue::from(Buffer::from(Box::new(
            puba.serialize_uncompressed(),
        ))))
    }
}
#[wasm_bindgen(js_name = pointCompress)]
pub fn point_compress(p: &JsValue, compressed: Option<bool>) -> Result<Buffer, JsValue> {
    let buf = get_buffer_return!(p, Err(JsValue::from(Error::BadPoint)));

    let is_compressed = compressed.unwrap_or(buf.length() == 33);
    let puba = pubkey_from_slice(&buf)?;

    if is_compressed {
        Ok(Buffer::from(Box::new(puba.serialize())))
    } else {
        Ok(Buffer::from(Box::new(puba.serialize_uncompressed())))
    }
}
#[wasm_bindgen(js_name = pointFromScalar)]
pub fn point_from_scalar(d: &JsValue, compressed: Option<bool>) -> Result<Buffer, JsValue> {
    let buf = get_buffer_return!(d, Err(JsValue::from(Error::BadPrivate)));

    let is_compressed = compressed.unwrap_or(true);
    let sk = seckey_from_slice(&buf)?;
    let pk = PublicKey::from_secret_key(&SECP256K1, &sk);
    if is_compressed {
        Ok(Buffer::from(Box::new(pk.serialize())))
    } else {
        Ok(Buffer::from(Box::new(pk.serialize_uncompressed())))
    }
}
#[wasm_bindgen(js_name = pointMultiply)]
pub fn point_multiply(
    p: &JsValue,
    tweak: &JsValue,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let buf = get_buffer_return!(p, Err(JsValue::from(Error::BadPoint)));
    let buf_tweak = get_buffer_return!(tweak, Err(JsValue::from(Error::BadTweak)));

    let is_compressed = compressed.unwrap_or(buf.length() == 33);
    let mut pubkey = pubkey_from_slice(&buf)?;
    check_tweak(&buf_tweak)?;

    unwrap_or_jsnullres!(pubkey.mul_assign(&SECP256K1, &buf_tweak.to_vec()));

    if is_compressed {
        Ok(JsValue::from(Buffer::from(Box::new(pubkey.serialize()))))
    } else {
        Ok(JsValue::from(Buffer::from(Box::new(
            pubkey.serialize_uncompressed(),
        ))))
    }
}
#[wasm_bindgen(js_name = privateAdd)]
pub fn private_add(d: &JsValue, tweak: &JsValue) -> Result<JsValue, JsValue> {
    let buf = get_buffer_return!(d, Err(JsValue::from(Error::BadPrivate)));
    let buf_tweak = get_buffer_return!(tweak, Err(JsValue::from(Error::BadTweak)));

    let mut sk1 = seckey_from_slice(&buf)?;
    check_tweak(&buf_tweak)?;

    unwrap_or_jsnullres!(sk1.add_assign(&buf_tweak.to_vec()));

    let mut key = [0u8; 32];
    key[..32].clone_from_slice(&sk1[..]);

    Ok(JsValue::from(Buffer::from(Box::new(key))))
}
#[wasm_bindgen(js_name = privateSub)]
pub fn private_sub(d: &JsValue, tweak: &JsValue) -> Result<JsValue, JsValue> {
    let buf = get_buffer_return!(d, Err(JsValue::from(Error::BadPrivate)));
    let buf_tweak = get_buffer_return!(tweak, Err(JsValue::from(Error::BadTweak)));

    let mut sk1 = seckey_from_slice(&buf)?;
    check_tweak(&buf_tweak)?;

    let mut tweak_clone = buf_tweak.to_vec();
    if tweak_clone != ZERO {
        unsafe {
            assert_eq!(
                ffi::secp256k1_ec_seckey_negate(*SECP256K1.ctx(), tweak_clone.as_mut_c_ptr()),
                1
            );
        }
    }

    unwrap_or_jsnullres!(sk1.add_assign(&tweak_clone));

    let mut key = [0u8; 32];
    key[..32].clone_from_slice(&sk1[..]);

    Ok(JsValue::from(Buffer::from(Box::new(key))))
}
#[wasm_bindgen]
pub fn sign(hash: &JsValue, x: &JsValue) -> Result<Buffer, JsValue> {
    let buf_hash = get_buffer_return!(hash, Err(JsValue::from(Error::BadHash)));
    let buf_x = get_buffer_return!(x, Err(JsValue::from(Error::BadPrivate)));

    let msg_hash = message_from_slice(&buf_hash)?;
    let pk = seckey_from_slice(&buf_x)?;
    Ok(Buffer::from(Box::new(
        SECP256K1.sign(&msg_hash, &pk).serialize_compact(),
    )))
}
#[wasm_bindgen(js_name = signWithEntropy)]
pub fn sign_with_entropy(
    hash: &JsValue,
    x: &JsValue,
    add_data: JsValue,
) -> Result<Buffer, JsValue> {
    let buf_hash = get_buffer_return!(hash, Err(JsValue::from(Error::BadHash)));
    let buf_x = get_buffer_return!(x, Err(JsValue::from(Error::BadPrivate)));

    let msg = message_from_slice(&buf_hash)?;
    let sk = seckey_from_slice(&buf_x)?;

    if add_data == JsValue::NULL || add_data == JsValue::UNDEFINED {
        return Ok(Buffer::from(Box::new(
            SECP256K1.sign(&msg, &sk).serialize_compact(),
        )));
    }

    let extra_bytes = get_buffer_return!(&add_data, Err(JsValue::from(Error::BadExtraData)));
    if extra_bytes.length() != 32 {
        Err(Error::BadExtraData)?
    }

    unsafe {
        let mut ret = ffi::Signature::new();
        // We can assume the return value because it's not possible to construct
        // an invalid signature from a valid `Message` and `SecretKey`
        assert_eq!(
            ffi::secp256k1_ecdsa_sign(
                *SECP256K1.ctx(),
                &mut ret,
                msg.as_c_ptr(),
                sk.as_c_ptr(),
                ffi::secp256k1_nonce_function_rfc6979,
                extra_bytes.to_vec().as_c_ptr() as *const ffi::types::c_void
            ),
            1
        );
        Ok(Buffer::from(Box::new(
            secp256k1::Signature::from(ret).serialize_compact(),
        )))
    }
}
#[wasm_bindgen]
pub fn verify(
    hash: &JsValue,
    q: &JsValue,
    signature: &JsValue,
    strict: Option<bool>,
) -> Result<bool, JsValue> {
    let buf_hash = get_buffer_return!(hash, Err(JsValue::from(Error::BadHash)));
    let buf_q = get_buffer_return!(q, Err(JsValue::from(Error::BadPoint)));
    let buf_sig = get_buffer_return!(signature, Err(JsValue::from(Error::BadPoint)));

    let is_strict = strict.unwrap_or(false);
    let pubkey = pubkey_from_slice(&buf_q)?;
    let msg = message_from_slice(&buf_hash)?;
    let mut sig = signature_from_slice(&buf_sig)?;
    if !is_strict {
        sig.normalize_s();
    }
    match SECP256K1.verify(&msg, &sig, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

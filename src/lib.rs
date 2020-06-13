use js_sys::TypeError;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use secp256k1_sys as ffi;
use secp256k1_sys::CPtr;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}

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

macro_rules! unwrap_or_jsnullres {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Ok(JsValue::NULL),
        }
    };
}

fn pubkey_from_slice(p: &JsBuffer) -> Result<PublicKey, Error> {
    let plen = p.len();
    if plen != 33 && plen != 65 {
        return Err(Error::BadPoint);
    }
    if plen == 33 && p[0] != 2u8 && p[0] != 3u8 {
        return Err(Error::BadPoint);
    }
    if plen == 65 && p[0] != 4u8 {
        return Err(Error::BadPoint);
    }
    PublicKey::from_slice(&p).map_err(|_| Error::BadPoint)
}

fn seckey_from_slice(p: &JsBuffer) -> Result<SecretKey, Error> {
    SecretKey::from_slice(&p).map_err(|_| Error::BadPrivate)
}

fn message_from_slice(p: &JsBuffer) -> Result<Message, Error> {
    Message::from_slice(&p).map_err(|_| Error::BadHash)
}

fn signature_from_slice(p: &JsBuffer) -> Result<Signature, Error> {
    Signature::from_compact(&p).map_err(|_| Error::BadSignature)
}

fn is_point_internal(p: &JsBuffer) -> bool {
    match pubkey_from_slice(&p) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn compare_32_bytes(p: &JsBuffer, q: &[u8; 32]) -> i8 {
    for i in 0..32 {
        if p[i] < q[i] {
            return -1;
        } else if p[i] > q[i] {
            return 1;
        }
    }
    return 0;
}

fn is_private_internal(x: &JsBuffer) -> bool {
    is_tweak(x) && compare_32_bytes(x, &ZERO) != 0
}

fn is_tweak(tweak: &JsBuffer) -> bool {
    tweak.len() == 32 && compare_32_bytes(tweak, &secp256k1::constants::CURVE_ORDER) == -1
}

fn check_tweak(tweak: &JsBuffer) -> Result<(), Error> {
    if !is_tweak(tweak) {
        Err(Error::BadTweak)
    } else {
        Ok(())
    }
}

unsafe fn uint8array_from_u8slice(data: &[u8]) -> JsValue {
    let array = js_sys::Uint8Array::view(data);
    return JsValue::from(array);
}

#[wasm_bindgen(js_name = isPoint)]
pub fn is_point(p: JsBuffer) -> bool {
    is_point_internal(&p)
}

#[wasm_bindgen(js_name = isPointCompressed)]
pub fn is_point_compressed(p: JsBuffer) -> Result<bool, JsValue> {
    let has_proper_len = p.len() == 33;
    if !has_proper_len {
        return Ok(false);
    }
    if !is_point_internal(&p) {
        Err(Error::BadPoint)?
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
    let is_compressed = compressed.unwrap_or(p_a.len() == 33);

    let puba = pubkey_from_slice(&p_a)?;
    let pubb = pubkey_from_slice(&p_b)?;

    let result = unwrap_or_jsnullres!(puba.combine(&pubb));

    if is_compressed {
        unsafe { Ok(uint8array_from_u8slice(&result.serialize())) }
    } else {
        unsafe { Ok(uint8array_from_u8slice(&result.serialize_uncompressed())) }
    }
}
#[wasm_bindgen(js_name = pointAddScalar)]
pub fn point_add_scalar(
    p: JsBuffer,
    tweak: JsBuffer,
    compressed: Option<bool>,
) -> Result<JsValue, JsValue> {
    let is_compressed = compressed.unwrap_or(p.len() == 33);
    let mut puba = pubkey_from_slice(&p)?;
    check_tweak(&tweak)?;

    unwrap_or_jsnullres!(puba.add_exp_assign(&SECP, &tweak));

    if is_compressed {
        unsafe { Ok(uint8array_from_u8slice(&puba.serialize())) }
    } else {
        unsafe { Ok(uint8array_from_u8slice(&puba.serialize_uncompressed())) }
    }
}
#[wasm_bindgen(js_name = pointCompress)]
pub fn point_compress(p: JsBuffer, compressed: Option<bool>) -> Result<JsBuffer, JsValue> {
    let is_compressed = compressed.unwrap_or(p.len() == 33);
    let puba = pubkey_from_slice(&p)?;

    if is_compressed {
        Ok(Box::new(puba.serialize()))
    } else {
        Ok(Box::new(puba.serialize_uncompressed()))
    }
}
#[wasm_bindgen(js_name = pointFromScalar)]
pub fn point_from_scalar(d: JsBuffer, compressed: Option<bool>) -> Result<JsBuffer, JsValue> {
    let is_compressed = compressed.unwrap_or(true);
    let sk = seckey_from_slice(&d)?;
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
    let mut pubkey = pubkey_from_slice(&p)?;
    check_tweak(&tweak)?;

    unwrap_or_jsnullres!(pubkey.mul_assign(&SECP, &tweak));

    if is_compressed {
        unsafe { Ok(uint8array_from_u8slice(&pubkey.serialize())) }
    } else {
        unsafe { Ok(uint8array_from_u8slice(&pubkey.serialize_uncompressed())) }
    }
}
#[wasm_bindgen(js_name = privateAdd)]
pub fn private_add(d: JsBuffer, tweak: JsBuffer) -> Result<JsValue, JsValue> {
    let mut sk1 = seckey_from_slice(&d)?;
    check_tweak(&tweak)?;

    unwrap_or_jsnullres!(sk1.add_assign(&tweak));

    unsafe { Ok(uint8array_from_u8slice(&sk1[..])) }
}
#[wasm_bindgen(js_name = privateSub)]
pub fn private_sub(d: JsBuffer, tweak: JsBuffer) -> Result<JsValue, JsValue> {
    let mut sk1 = seckey_from_slice(&d)?;
    check_tweak(&tweak)?;

    let mut tweak_clone = tweak.clone();
    unsafe {
        assert_eq!(
            ffi::secp256k1_ec_privkey_negate(*SECP.ctx(), tweak_clone.as_mut_c_ptr()),
            1
        );
    }

    unwrap_or_jsnullres!(sk1.add_assign(&tweak_clone));

    unsafe { Ok(uint8array_from_u8slice(&sk1[..])) }
}
#[wasm_bindgen]
pub fn sign(hash: JsBuffer, x: JsBuffer) -> Result<JsBuffer, JsValue> {
    let msg_hash = message_from_slice(&hash)?;
    let pk = seckey_from_slice(&x)?;
    Ok(Box::new(SECP.sign(&msg_hash, &pk).serialize_compact()))
}
#[wasm_bindgen(js_name = signWithEntropy)]
pub fn sign_with_entropy(
    hash: JsBuffer,
    x: JsBuffer,
    add_data: Option<JsBuffer>,
) -> Result<JsBuffer, JsValue> {
    let msg = message_from_slice(&hash)?;
    let sk = seckey_from_slice(&x)?;

    if add_data == None {
        return Ok(Box::new(SECP.sign(&msg, &sk).serialize_compact()));
    }
    let extra_bytes = add_data.unwrap();
    if extra_bytes.len() != 32 {
        Err(Error::BadExtraData)?
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
    let pubkey = pubkey_from_slice(&q)?;
    let msg = message_from_slice(&hash)?;
    let mut sig = signature_from_slice(&signature)?;
    if !is_strict {
        sig.normalize_s();
    }
    match SECP.verify(&msg, &sig, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

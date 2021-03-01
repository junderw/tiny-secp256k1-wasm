use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(debug)]
#[wasn_bindgen(js_name = setPanicHook)]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

type InvalidInputResult<T> = Result<T, JsValue>;

#[wasm_bindgen(js_name = isPoint)]
pub fn is_point(pubkey: &[u8]) -> bool {
    secp256k1::is_point(pubkey)
}

#[wasm_bindgen(js_name = isPointCompressed)]
pub fn is_point_compressed(pubkey: &[u8]) -> bool {
    secp256k1::is_point_compressed(pubkey)
}

#[wasm_bindgen(js_name = isPrivate)]
pub fn is_private(seckey: &[u8]) -> bool {
    secp256k1::is_private(seckey)
}

#[wasm_bindgen(js_name = pointAdd)]
pub fn point_add(
    pubkey1: &[u8],
    pubkey2: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Vec<u8>>> {
    secp256k1::point_add(pubkey1, pubkey2, compressed).map_err(Into::into)
}

#[wasm_bindgen(js_name = pointAddScalar)]
pub fn point_add_scalar(
    pubkey: &[u8],
    tweak: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Vec<u8>>> {
    secp256k1::point_add_scalar(pubkey, tweak, compressed).map_err(Into::into)
}

#[wasm_bindgen(js_name = pointCompress)]
pub fn point_compress(pubkey: &[u8], compressed: bool) -> InvalidInputResult<Vec<u8>> {
    secp256k1::point_compress(pubkey, compressed).map_err(Into::into)
}

#[wasm_bindgen(js_name = pointFromScalar)]
pub fn point_from_scalar(seckey: &[u8], compressed: Option<bool>) -> InvalidInputResult<Vec<u8>> {
    secp256k1::point_from_scalar(seckey, compressed).map_err(Into::into)
}

#[wasm_bindgen(js_name = pointMultiply)]
pub fn point_multiply(
    pubkey: &[u8],
    tweak: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Vec<u8>> {
    secp256k1::point_multiply(pubkey, tweak, compressed).map_err(Into::into)
}

#[wasm_bindgen(js_name = privateAdd)]
pub fn private_add(seckey: &[u8], tweak: &[u8]) -> InvalidInputResult<Option<Vec<u8>>> {
    secp256k1::private_add(seckey, tweak).map_err(Into::into)
}

#[wasm_bindgen(js_name = privateSub)]
pub fn pirvate_sub(seckey: &[u8], tweak: &[u8]) -> InvalidInputResult<Option<Vec<u8>>> {
    secp256k1::pirvate_sub(seckey, tweak).map_err(Into::into)
}

#[wasm_bindgen]
pub fn sign(message: &[u8], seckey: &[u8]) -> InvalidInputResult<Vec<u8>> {
    secp256k1::sign(message, seckey).map_err(Into::into)
}

#[wasm_bindgen(js_name = signWithEntropy)]
pub fn sign_with_entropy(
    message: &[u8],
    seckey: &[u8],
    noncedata: &[u8],
) -> InvalidInputResult<Vec<u8>> {
    secp256k1::sign_with_entropy(message, seckey, noncedata).map_err(Into::into)
}

#[wasm_bindgen]
pub fn verify(
    message: &[u8],
    pubkey: &[u8],
    signature: &[u8],
    strict: Option<bool>,
) -> InvalidInputResult<bool> {
    secp256k1::verify(message, pubkey, signature, strict).map_err(Into::into)
}

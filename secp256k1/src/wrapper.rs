use std::sync::Once;

pub use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_ec_pubkey_combine, secp256k1_ec_pubkey_create,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_verify, secp256k1_nonce_function_rfc6979, types::c_void, PublicKey, Signature,
};
use secp256k1_sys::{
    secp256k1_context_preallocated_create, secp256k1_context_preallocated_size,
    secp256k1_context_randomize, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    types::AlignedType, Context, SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED,
    SECP256K1_START_SIGN, SECP256K1_START_VERIFY,
};

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const TWEAK_SIZE: usize = 32;
pub const MESSAGE_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const NONCEDATA_SIZE: usize = 32;

const ZERO: [u8; 32] = [0u8; 32];
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Possible errors related with invalid input data.
pub enum InvalidInput {
    BadPrivate,
    BadPoint,
    BadTweak,
    BadHash,
    BadSignature,
    BadExtraData,
}

impl InvalidInput {
    pub fn as_str(&self) -> &str {
        use InvalidInput::*;
        match *self {
            BadExtraData => "Expected Extra Data (32 bytes)",
            BadHash => "Expected Hash",
            BadPoint => "Expected Point",
            BadPrivate => "Expected Private",
            BadSignature => "Expected Signature",
            BadTweak => "Expected Tweak",
        }
    }
}

#[cfg(feature = "wasm")]
impl From<InvalidInput> for wasm_bindgen::JsValue {
    fn from(error: InvalidInput) -> Self {
        wasm_bindgen::JsValue::from(js_sys::TypeError::new(error.as_str()))
    }
}

pub type InvalidInputResult<T> = Result<T, InvalidInput>;

pub fn get_context() -> *const secp256k1_sys::Context {
    static mut CONTEXT: *const Context = std::ptr::null();
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let size =
            secp256k1_context_preallocated_size(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
        const ALIGN_TO: usize = std::mem::align_of::<AlignedType>();
        let layout = std::alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
        let ptr = std::alloc::alloc(layout);
        let ctx = secp256k1_context_preallocated_create(
            ptr as *mut c_void,
            SECP256K1_START_SIGN | SECP256K1_START_VERIFY,
        );
        let mut seed: [u8; 32] = [0; 32];
        getrandom::getrandom(&mut seed).expect("random seed");
        assert_eq!(secp256k1_context_randomize(ctx, seed.as_ptr()), 1);
        CONTEXT = ctx
    });
    unsafe { CONTEXT }
}

pub fn seckey_check(seckey: &[u8]) -> InvalidInputResult<()> {
    if seckey.len() == SECRET_KEY_SIZE
        && compare_32_bytes(seckey, &CURVE_ORDER) < 0
        && compare_32_bytes(seckey, &ZERO) > 0
    {
        Ok(())
    } else {
        Err(InvalidInput::BadPrivate)
    }
}

pub fn pubkey_parse(pubkey: &[u8]) -> InvalidInputResult<PublicKey> {
    match pubkey.len() {
        PUBLIC_KEY_COMPRESSED_SIZE | PUBLIC_KEY_UNCOMPRESSED_SIZE => unsafe {
            let mut pk = PublicKey::new();
            if secp256k1_ec_pubkey_parse(
                secp256k1_context_no_precomp,
                &mut pk,
                pubkey.as_ptr(),
                pubkey.len() as usize,
            ) == 1
            {
                Ok(pk)
            } else {
                Err(InvalidInput::BadPoint)
            }
        },
        _ => Err(InvalidInput::BadPoint),
    }
}

pub fn pubkey_serialize(pubkey: &PublicKey, compressed: bool) -> Vec<u8> {
    if compressed {
        let mut ret = [0; PUBLIC_KEY_COMPRESSED_SIZE];

        unsafe {
            let mut outputlen = PUBLIC_KEY_COMPRESSED_SIZE;
            let retcode = secp256k1_ec_pubkey_serialize(
                secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &mut outputlen,
                pubkey.as_ptr() as *const PublicKey,
                SECP256K1_SER_COMPRESSED,
            );
            debug_assert_eq!(retcode, 1);
            debug_assert_eq!(outputlen, ret.len());
        }

        ret.into()
    } else {
        let mut ret = [0; PUBLIC_KEY_UNCOMPRESSED_SIZE];

        unsafe {
            let mut outputlen = PUBLIC_KEY_UNCOMPRESSED_SIZE;
            let retcode = secp256k1_ec_pubkey_serialize(
                secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &mut outputlen,
                pubkey.as_ptr() as *const PublicKey,
                SECP256K1_SER_UNCOMPRESSED,
            );
            debug_assert_eq!(retcode, 1);
            debug_assert_eq!(outputlen, ret.len());
        }

        ret.into()
    }
}

pub fn tweak_check(tweak: &[u8]) -> InvalidInputResult<()> {
    if tweak.len() == TWEAK_SIZE && compare_32_bytes(tweak, &CURVE_ORDER) == -1 {
        Ok(())
    } else {
        Err(InvalidInput::BadTweak)
    }
}

pub fn message_check(message: &[u8]) -> InvalidInputResult<()> {
    if message.len() == MESSAGE_SIZE {
        Ok(())
    } else {
        Err(InvalidInput::BadHash)
    }
}

pub fn signature_parse(signature: &[u8]) -> InvalidInputResult<Signature> {
    unsafe {
        let mut sig = Signature::new();
        if signature.len() == SIGNATURE_SIZE
            && secp256k1_ecdsa_signature_parse_compact(
                secp256k1_context_no_precomp,
                &mut sig,
                signature.as_ptr(),
            ) == 1
        {
            Ok(sig)
        } else {
            Err(InvalidInput::BadSignature)
        }
    }
}

pub fn signature_serialize(sig: &Signature) -> [u8; 64] {
    unsafe {
        let mut signature: [u8; 64] = std::mem::MaybeUninit::uninit().assume_init();
        let retcode = secp256k1_ecdsa_signature_serialize_compact(
            secp256k1_context_no_precomp,
            signature.as_mut_ptr(),
            sig,
        );
        debug_assert_eq!(retcode, 1);
        signature
    }
}

pub fn noncedata_check(noncedata: &[u8]) -> InvalidInputResult<()> {
    if noncedata.len() == NONCEDATA_SIZE {
        Ok(())
    } else {
        Err(InvalidInput::BadExtraData)
    }
}

fn compare_32_bytes(data1: &[u8], data2: &[u8]) -> i8 {
    debug_assert_eq!(data1.len(), 32);
    debug_assert_eq!(data2.len(), 32);
    for (a, b) in data1.iter().zip(data2.iter()) {
        if a < b {
            return -1;
        }
        if a > b {
            return 1;
        }
    }
    0
}

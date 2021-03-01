mod wrapper;

pub use wrapper::InvalidInput;
use wrapper::{
    c_void, get_context, message_check, noncedata_check, pubkey_parse, pubkey_serialize,
    seckey_check, secp256k1_context_no_precomp, secp256k1_ec_pubkey_combine,
    secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul,
    secp256k1_ec_seckey_negate, secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign,
    secp256k1_ecdsa_signature_normalize, secp256k1_ecdsa_verify, secp256k1_nonce_function_rfc6979,
    signature_parse, signature_serialize, tweak_check, InvalidInputResult, PublicKey, Signature,
    PUBLIC_KEY_COMPRESSED_SIZE,
};

/// Validate input data as point.
pub fn is_point(pubkey: &[u8]) -> bool {
    pubkey_parse(pubkey).is_ok()
}

/// Same as [is_point] but also checks that `pubkey` is in compressed format.
pub fn is_point_compressed(pubkey: &[u8]) -> bool {
    is_point(pubkey) && pubkey.len() == PUBLIC_KEY_COMPRESSED_SIZE
}

/// Validate input data as Secret Key.
pub fn is_private(seckey: &[u8]) -> bool {
    seckey_check(seckey).is_ok()
}

/// Combine two valid Public Keys.
pub fn point_add(
    pubkey1: &[u8],
    pubkey2: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Vec<u8>>> {
    let pk1 = pubkey_parse(pubkey1)?;
    let pk2 = pubkey_parse(pubkey2)?;

    unsafe {
        let mut pk = PublicKey::new();
        let ptrs = [pk1.as_ptr(), pk2.as_ptr()];
        Ok(
            if secp256k1_ec_pubkey_combine(
                secp256k1_context_no_precomp,
                &mut pk,
                ptrs.as_ptr() as *const *const PublicKey,
                ptrs.len() as i32,
            ) == 1
            {
                Some(pubkey_serialize(
                    &pk,
                    compressed.unwrap_or_else(|| pubkey1.len() == PUBLIC_KEY_COMPRESSED_SIZE),
                ))
            } else {
                None
            },
        )
    }
}

/// Add `tweak` to the Public Key.
pub fn point_add_scalar(
    pubkey: &[u8],
    tweak: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Vec<u8>>> {
    let mut pk = pubkey_parse(pubkey)?;
    tweak_check(tweak)?;

    unsafe {
        Ok(
            if secp256k1_ec_pubkey_tweak_add(
                get_context(),
                pk.as_mut_ptr() as *mut PublicKey,
                tweak.as_ptr(),
            ) == 1
            {
                Some(pubkey_serialize(
                    &pk,
                    compressed.unwrap_or_else(|| pubkey.len() == PUBLIC_KEY_COMPRESSED_SIZE),
                ))
            } else {
                None
            },
        )
    }
}

/// Encode Public Key in specifed format.
pub fn point_compress(pubkey: &[u8], compressed: bool) -> InvalidInputResult<Vec<u8>> {
    let pk = pubkey_parse(pubkey)?;
    Ok(pubkey_serialize(&pk, compressed))
}

/// Create Public Key from Secret Key.
pub fn point_from_scalar(seckey: &[u8], compressed: Option<bool>) -> InvalidInputResult<Vec<u8>> {
    seckey_check(seckey)?;

    unsafe {
        let mut pk = PublicKey::new();
        let retcode = secp256k1_ec_pubkey_create(get_context(), &mut pk, seckey.as_ptr());
        debug_assert_eq!(retcode, 1);
        Ok(pubkey_serialize(&pk, compressed.unwrap_or(true)))
    }
}

/// Multiply Public Key on the `tweak`.
pub fn point_multiply(
    pubkey: &[u8],
    tweak: &[u8],
    compressed: Option<bool>,
) -> InvalidInputResult<Vec<u8>> {
    let mut pk = pubkey_parse(pubkey)?;
    tweak_check(tweak)?;

    unsafe {
        let retcode = secp256k1_ec_pubkey_tweak_mul(get_context(), &mut pk, tweak.as_ptr());
        debug_assert_eq!(retcode, 1);
        Ok(pubkey_serialize(
            &pk,
            compressed.unwrap_or_else(|| pubkey.len() == PUBLIC_KEY_COMPRESSED_SIZE),
        ))
    }
}

/// Add `tweak` to Secret Key.
pub fn private_add(seckey: &[u8], tweak: &[u8]) -> InvalidInputResult<Option<Vec<u8>>> {
    seckey_check(seckey)?;
    tweak_check(tweak)?;

    let mut sk: Vec<u8> = seckey.into();
    unsafe {
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            sk.as_mut_ptr(),
            tweak.as_ptr(),
        ) == 1
        {
            Ok(Some(sk))
        } else {
            Ok(None)
        }
    }
}

/// Substract `tweak` from Secret Key.
pub fn pirvate_sub(seckey: &[u8], tweak: &[u8]) -> InvalidInputResult<Option<Vec<u8>>> {
    seckey_check(seckey)?;
    tweak_check(tweak)?;

    unsafe {
        let mut tweak_negated: [u8; 32] = std::mem::MaybeUninit::uninit().assume_init();
        if secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, tweak_negated.as_mut_ptr()) == 0
        {
            return Err(InvalidInput::BadTweak);
        }

        let mut sk: Vec<u8> = seckey.into();
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            sk.as_mut_ptr(),
            tweak_negated.as_ptr(),
        ) == 1
        {
            Ok(Some(sk))
        } else {
            Ok(None)
        }
    }
}

/// Sign `message` with Secret Key.
pub fn sign(message: &[u8], seckey: &[u8]) -> InvalidInputResult<Vec<u8>> {
    message_check(message)?;
    seckey_check(seckey)?;

    unsafe {
        let mut sig = Signature::new();
        let retcode = secp256k1_ecdsa_sign(
            get_context(),
            &mut sig,
            message.as_ptr(),
            seckey.as_ptr(),
            secp256k1_nonce_function_rfc6979,
            std::ptr::null(),
        );
        debug_assert_eq!(retcode, 1);

        Ok(signature_serialize(&sig).into())
    }
}

/// Sign `message` with Secret Key with arbitary `data` used by nonce generation function.
pub fn sign_with_entropy(
    message: &[u8],
    seckey: &[u8],
    noncedata: &[u8],
) -> InvalidInputResult<Vec<u8>> {
    message_check(message)?;
    seckey_check(seckey)?;
    noncedata_check(noncedata)?;

    unsafe {
        let mut sig = Signature::new();
        let retcode = secp256k1_ecdsa_sign(
            get_context(),
            &mut sig,
            message.as_ptr(),
            seckey.as_ptr(),
            secp256k1_nonce_function_rfc6979,
            noncedata.as_ptr() as *const c_void,
        );
        debug_assert_eq!(retcode, 1);

        Ok(signature_serialize(&sig).into())
    }
}

/// Verify signature.
pub fn verify(
    message: &[u8],
    pubkey: &[u8],
    signature: &[u8],
    strict: Option<bool>,
) -> InvalidInputResult<bool> {
    message_check(message)?;
    let pk = pubkey_parse(pubkey)?;
    let mut sig = signature_parse(signature)?;

    unsafe {
        if !strict.unwrap_or(false) {
            secp256k1_ecdsa_signature_normalize(secp256k1_context_no_precomp, &mut sig, &sig);
        }

        Ok(secp256k1_ecdsa_verify(get_context(), &sig, message.as_ptr(), &pk) == 1)
    }
}

#[allow(dead_code)]
mod keys;

#[cfg(feature = "debug_less_secure")]
macro_rules! assert_privkeys_eq {
    ($a:expr, $b:expr) => {
        assert_eq!($a, $b)
    }
}

#[cfg(not(feature = "debug_less_secure"))]
macro_rules! assert_privkeys_eq {
    ($a:expr, $b:expr) => {
        assert!($a == $b, "privkeys are not equal \
            (enable feature 'debug_less_secure' to Debug the private keys)")
    }
}

fn check_decode_privkey(expected_privkey: makiko::Privkey, pem_data: &str, password: Option<&str>) {
    let decoded_nopass = makiko::keys::decode_openssh_pem_keypair_nopass(pem_data.as_bytes())
        .expect("could not decode keypair (without password)");

    let decoded = makiko::keys::decode_openssh_pem_keypair(
            pem_data.as_bytes(), password.unwrap_or("").as_bytes())
        .expect("could not decode keypair (with password)");
    assert_privkeys_eq!(&decoded.privkey, &expected_privkey);

    assert_eq!(decoded_nopass.privkey.is_some(), password.is_none());
    assert_eq!(decoded_nopass.comment.is_some(), password.is_none());

    assert_eq!(decoded_nopass.pubkey, decoded.pubkey);
    if password.is_none() {
        assert_privkeys_eq!(decoded_nopass.privkey.unwrap(), decoded.privkey);
        assert_eq!(decoded_nopass.comment.unwrap(), decoded.comment);
    }
}

#[test] fn test_decode_alice_ed25519() {
    check_decode_privkey(keys::alice_ed25519(), keys::ALICE_ED25519_KEYPAIR_PEM, None);
}

#[test] fn test_decode_ruth_rsa_1024() {
    check_decode_privkey(keys::ruth_rsa_1024(), keys::RUTH_RSA_1024_KEYPAIR_PEM, None);
}
#[test] fn test_decode_ruth_rsa_2048() {
    check_decode_privkey(keys::ruth_rsa_2048(), keys::RUTH_RSA_2048_KEYPAIR_PEM, None);
}
#[test] fn test_decode_ruth_rsa_4096() {
    check_decode_privkey(keys::ruth_rsa_4096(), keys::RUTH_RSA_4096_KEYPAIR_PEM, None);
}

#[test] fn test_decode_eda_ecdsa_p256() {
    check_decode_privkey(keys::eda_ecdsa_p256(), keys::EDA_ECDSA_P256_KEYPAIR_PEM, None);
}
#[test] fn test_decode_eda_ecdsa_p384() {
    check_decode_privkey(keys::eda_ecdsa_p384(), keys::EDA_ECDSA_P384_KEYPAIR_PEM, None);
}

#[test] fn test_decode_encrypted_rsa() {
    check_decode_privkey(keys::encrypted_rsa(),
        keys::ENCRYPTED_RSA_KEYPAIR_PEM, Some("password"));
}
#[test] fn test_decode_encrypted_ed25519() {
    check_decode_privkey(keys::encrypted_ed25519(),
        keys::ENCRYPTED_ED25519_KEYPAIR_PEM, Some("password"));
}
#[test] fn test_decode_encrypted_ecdsa_p256() {
    check_decode_privkey(keys::encrypted_ecdsa_p256(),
        keys::ENCRYPTED_ECDSA_P256_KEYPAIR_PEM, Some("password"));
}
#[test] fn test_decode_encrypted_ecdsa_p384() {
    check_decode_privkey(keys::encrypted_ecdsa_p384(),
        keys::ENCRYPTED_ECDSA_P384_KEYPAIR_PEM, Some("password"));
}

#[test] 
#[should_panic] // this is not implemented
fn test_decode_encrypted_rsa_aes128_gcm() {
    // the `cryptography` library in Python does not support keys encrypted using aes128-gcm, so
    // the keys.rs file does not contain `encrypted_rsa_aes128_gcm()`
    let pem_data = keys::ENCRYPTED_RSA_AES128_GCM_KEYPAIR_PEM;
    let decoded = makiko::keys::decode_openssh_pem_keypair(pem_data.as_bytes(), b"password".as_slice())
        .expect("could not decode keypair");
    // at least check that the keypair is valid
    assert_eq!(decoded.pubkey, decoded.privkey.pubkey());
}


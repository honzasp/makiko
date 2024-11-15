#[allow(dead_code)]
mod keys;

#[cfg(feature = "debug-less-secure")]
macro_rules! assert_privkeys_eq {
    ($a:expr, $b:expr) => {
        assert_eq!($a, $b)
    }
}

#[cfg(not(feature = "debug-less-secure"))]
macro_rules! assert_privkeys_eq {
    ($a:expr, $b:expr) => {
        assert!($a == $b, "privkeys are not equal \
            (enable feature 'debug_less_secure' to Debug the private keys)")
    }
}

mod openssh {
    use super::keys;

    fn check_openssh_privkey(expected_privkey: makiko::Privkey, pem_data: &str, password: Option<&str>) {
        let decoded_nopass = makiko::keys::decode_openssh_pem_keypair_nopass(pem_data.as_bytes())
            .expect("could not decode keypair (without password)");

        let decoded = makiko::keys::decode_openssh_pem_keypair(
                pem_data.as_bytes(), password.unwrap_or("").as_bytes())
            .expect("could not decode keypair (with password)");
        assert_privkeys_eq!(decoded.privkey, expected_privkey);

        assert_eq!(decoded_nopass.privkey.is_some(), password.is_none());
        assert_eq!(decoded_nopass.comment.is_some(), password.is_none());

        assert_eq!(decoded_nopass.pubkey, decoded.pubkey);
        if password.is_none() {
            assert_privkeys_eq!(decoded_nopass.privkey.unwrap(), decoded.privkey);
            assert_eq!(decoded_nopass.comment.unwrap(), decoded.comment);
        }

        let decoded_auto = makiko::keys::decode_pem_privkey(
                pem_data.as_bytes(), password.unwrap_or("").as_bytes())
            .expect("could not decode privkey (auto-detected format)");
        assert_privkeys_eq!(decoded_auto, expected_privkey);

        let decoded_auto_nopass = makiko::keys::decode_pem_privkey_nopass(pem_data.as_bytes())
            .expect("could not decode privkey (auto-detected format nopass)");
        match decoded_auto_nopass {
            makiko::keys::DecodedPrivkeyNopass::Privkey(privkey) =>
                assert_privkeys_eq!(privkey, expected_privkey),
            makiko::keys::DecodedPrivkeyNopass::Pubkey(pubkey) => {
                assert!(password.is_some());
                assert_eq!(pubkey, expected_privkey.pubkey());
            },
            makiko::keys::DecodedPrivkeyNopass::Encrypted =>
                panic!("it must be possible to decode at least pubkey from encrypted privkey"),
        }
    }

    #[test] fn test_decode_alice_ed25519() {
        check_openssh_privkey(keys::alice_ed25519(), keys::ALICE_ED25519_PRIVKEY_FILE, None);
    }

    #[test] fn test_decode_ruth_rsa_1024() {
        check_openssh_privkey(keys::ruth_rsa_1024(), keys::RUTH_RSA_1024_PRIVKEY_FILE, None);
    }
    #[test] fn test_decode_ruth_rsa_2048() {
        check_openssh_privkey(keys::ruth_rsa_2048(), keys::RUTH_RSA_2048_PRIVKEY_FILE, None);
    }
    #[test] fn test_decode_ruth_rsa_4096() {
        check_openssh_privkey(keys::ruth_rsa_4096(), keys::RUTH_RSA_4096_PRIVKEY_FILE, None);
    }

    #[test] fn test_decode_eda_ecdsa_p256() {
        check_openssh_privkey(keys::eda_ecdsa_p256(), keys::EDA_ECDSA_P256_PRIVKEY_FILE, None);
    }
    #[test] fn test_decode_eda_ecdsa_p384() {
        check_openssh_privkey(keys::eda_ecdsa_p384(), keys::EDA_ECDSA_P384_PRIVKEY_FILE, None);
    }

    #[test] fn test_decode_rsa_encrypted() {
        check_openssh_privkey(keys::rsa_encrypted(),
            keys::RSA_ENCRYPTED_PRIVKEY_FILE, Some("password"));
    }
    #[test] fn test_decode_ed25519_encrypted() {
        check_openssh_privkey(keys::ed25519_encrypted(),
            keys::ED25519_ENCRYPTED_PRIVKEY_FILE, Some("password"));
    }
    #[test] fn test_decode_ecdsa_p256_encrypted() {
        check_openssh_privkey(keys::ecdsa_p256_encrypted(),
            keys::ECDSA_P256_ENCRYPTED_PRIVKEY_FILE, Some("password"));
    }
    #[test] fn test_decode_ecdsa_p384_encrypted() {
        check_openssh_privkey(keys::ecdsa_p384_encrypted(),
            keys::ECDSA_P384_ENCRYPTED_PRIVKEY_FILE, Some("password"));
    }

    #[test] 
    #[should_panic] // this functionality is not implemented
    fn test_decode_rsa_encrypted_aes128_gcm() {
        // the `cryptography` library in Python does not support keys encrypted using aes128-gcm, so
        // the keys.rs file does not contain `encrypted_rsa_aes128_gcm()`
        let pem_data = keys::RSA_ENCRYPTED_AES128_GCM_PRIVKEY_FILE;
        let decoded = makiko::keys::decode_openssh_pem_keypair(pem_data.as_bytes(), b"password".as_slice())
            .expect("could not decode keypair");
        // at least check that the keypair is valid
        assert_eq!(decoded.pubkey, decoded.privkey.pubkey());
    }
}

mod pkcs1 {
    use super::keys;

    #[test]
    fn test_decode_pkcs1_privkey() {
        let pem_data = keys::PKCS1_PRIVKEY_FILE;
        let privkey = makiko::keys::decode_pkcs1_pem_privkey_nopass(pem_data.as_bytes())
            .expect("could not decode privkey");
        assert_privkeys_eq!(makiko::Privkey::Rsa(privkey), keys::pkcs1());

        let privkey_auto = makiko::keys::decode_pem_privkey(pem_data.as_bytes(), b"")
            .expect("could not decode privkey (auto-format)");
        assert_privkeys_eq!(privkey_auto, keys::pkcs1());
    }

    #[test]
    fn test_decode_pkcs1_pubkey() {
        let pem_data = keys::PKCS1_PUBKEY_FILE;
        let pubkey = makiko::keys::decode_pkcs1_pem_pubkey(pem_data.as_bytes())
            .expect("could not decode pubkey");
        assert_eq!(makiko::Pubkey::Rsa(pubkey), keys::pkcs1().pubkey());

        let pubkey_auto = makiko::keys::decode_pem_pubkey(pem_data.as_bytes())
            .expect("could not decode pubkey (auto-format)");
        assert_privkeys_eq!(pubkey_auto, keys::pkcs1().pubkey());
    }
}

mod pkcs8 {
    use super::keys;

    fn check_pkcs8_privkey(expected_privkey: makiko::Privkey, pem_data: &str, password: &str) {
        let decoded_privkey = makiko::keys::decode_pkcs8_pem_privkey(pem_data.as_bytes(), password.as_bytes())
            .expect("could not decode privkey");
        assert_privkeys_eq!(decoded_privkey, expected_privkey);

        let decoded_auto = makiko::keys::decode_pem_privkey(pem_data.as_bytes(), password.as_bytes())
            .expect("could not decode privkey (auto-detected format)");
        assert_privkeys_eq!(decoded_auto, expected_privkey);

        let decoded_nopass = makiko::keys::decode_pem_privkey_nopass(pem_data.as_bytes())
            .expect("could not decode privkey (nopass)");
        match decoded_nopass {
            makiko::keys::DecodedPrivkeyNopass::Privkey(privkey) =>
                assert_privkeys_eq!(privkey, expected_privkey),
            makiko::keys::DecodedPrivkeyNopass::Pubkey(_) =>
                panic!("it is not possible to decode pubkey from encrypted pkcs#8"),
            makiko::keys::DecodedPrivkeyNopass::Encrypted =>
                assert!(!password.is_empty()),
        }
    }

    fn check_pkcs8_pubkey(expected_privkey: makiko::Privkey, pem_data: &str) {
        let decoded_pubkey = makiko::keys::decode_pkcs8_pem_pubkey(pem_data.as_bytes())
            .expect("could not decode pubkey");
        assert_eq!(decoded_pubkey, expected_privkey.pubkey());

        let decoded_auto = makiko::keys::decode_pem_pubkey(pem_data.as_bytes())
            .expect("could not decode pubkey (auto-detected format)");
        assert_eq!(decoded_auto, expected_privkey.pubkey());
    }

    #[test] fn test_decode_pkcs8_rsa() {
        check_pkcs8_privkey(keys::pkcs8_rsa(), keys::PKCS8_RSA_PRIVKEY_FILE, "");
        check_pkcs8_pubkey(keys::pkcs8_rsa(), keys::PKCS8_RSA_PUBKEY_FILE);
    }

    #[test] fn test_decode_pkcs8_ecdsa_p256() {
        check_pkcs8_privkey(keys::pkcs8_ecdsa_p256(), keys::PKCS8_ECDSA_P256_PRIVKEY_FILE, "");
        check_pkcs8_pubkey(keys::pkcs8_ecdsa_p256(), keys::PKCS8_ECDSA_P256_PUBKEY_FILE);
    }

    #[test] fn test_decode_pkcs8_ecdsa_p384() {
        check_pkcs8_privkey(keys::pkcs8_ecdsa_p384(), keys::PKCS8_ECDSA_P384_PRIVKEY_FILE, "");
        check_pkcs8_pubkey(keys::pkcs8_ecdsa_p384(), keys::PKCS8_ECDSA_P384_PUBKEY_FILE);
    }

    #[test] fn test_decode_pkcs8_ed25519() {
        check_pkcs8_privkey(keys::pkcs8_ed25519(), keys::PKCS8_ED25519_PRIVKEY_FILE, "");
        check_pkcs8_pubkey(keys::pkcs8_ed25519(), keys::PKCS8_ED25519_PUBKEY_FILE);
    }

    #[test] fn test_decode_pkcs8v2_ed25519() {
        let pem_data = keys::PKCS8V2_ED25519_PRIVKEY_FILE;
        let decoded_privkey = makiko::keys::decode_pkcs8_pem_privkey(pem_data.as_bytes(), &[])
            .expect("could not decode privkey");
        assert!(matches!(decoded_privkey, makiko::Privkey::Ed25519(_)));
    }

    #[test] fn test_decode_pkcs8_rsa_encrypted() {
        check_pkcs8_privkey(keys::pkcs8_rsa_encrypted(), keys::PKCS8_RSA_ENCRYPTED_PRIVKEY_FILE, "password");
    }
}

mod fingerprint {
    use super::keys;

    fn check_fingerprint(privkey: makiko::Privkey, expected: &str) {
        let fingerprint = privkey.pubkey().fingerprint();
        assert_eq!(fingerprint, expected);
    }

    #[test] fn test_fingerprint_alice_ed25519() {
        check_fingerprint(keys::alice_ed25519(), "SHA256:sBkOpFO1h8D6+8mvKFvAgaHSFLjrG3LMeXDhST/qXwY");
    }
    #[test] fn test_fingerprint_ruth_rsa_1024() {
        check_fingerprint(keys::ruth_rsa_1024(), "SHA256:JKKfprhKd9n4BaqMcwQmdrtaMxxvaYAi3LEwfsl/j10");
    }
    #[test] fn test_fingerprint_ruth_rsa_2048() {
        check_fingerprint(keys::ruth_rsa_2048(), "SHA256:f7yXzeoej4cteCs7EipdN2+GPWRLgtleYTpDDQzNybk");
    }
    #[test] fn test_fingerprint_ruth_rsa_4096() {
        check_fingerprint(keys::ruth_rsa_4096(), "SHA256:eaBPG/rqx+IPa0Lc9KHypkG3UxjmUwerwq9CZ/xpPWM");
    }
    #[test] fn test_fingerprint_eda_ecdsa_p256() {
        check_fingerprint(keys::eda_ecdsa_p256(), "SHA256:c8EWc8omrSNzIK2ipOLWju6F9Do4ypK+mf3RRbgOCXw");
    }
    #[test] fn test_fingerprint_eda_ecdsa_p384() {
        check_fingerprint(keys::eda_ecdsa_p384(), "SHA256:8vBuizZHVX0885H8gCJQTzpf73/S9y3vT3VAHtuBikY");
    }
}

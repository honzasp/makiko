// auto generated by print_keys.py
use num_bigint_dig::BigUint;
use hex_literal::hex;

pub fn edward_ed25519() -> makiko::Privkey {
    let private_bytes = hex!("3972dfb17dcf6a949e08d8979ef0722b021379e72c66b549af2a98d3eeae905c");
    let public_bytes = hex!("f2549b117e1f8d9a440a8360e1eab3d5a1d890de70be755a0632832d61c6cc25");
    makiko::Privkey::Ed25519(ed25519_dalek::Keypair {
        secret: ed25519_dalek::SecretKey::from_bytes(&private_bytes).unwrap(),
        public: ed25519_dalek::PublicKey::from_bytes(&public_bytes).unwrap(),
    }.into())
}

pub fn ruth_rsa_1024() -> makiko::Privkey {
    let n = BigUint::from_bytes_be(&hex!(
        "e72e0e6569dd40cafc4c608c4ee3b7f13956b7e5b301cc8dc47c9e26019b053d"
        "0f9de0ed4856f89c5cf2355f08c41486d7c6840a670e2eaa425a7db58a8e99b3"
        "e46bf2902a1b699de966df734f7b127129909b2e009a102e553f0b683870b127"
        "16569b6e8ab707d5bf52d1575c8093b506f3bf54c2a23d644023ce6d0fbd8a11"
    ));
    let e = BigUint::from_bytes_be(&hex!("010001"));
    let d = BigUint::from_bytes_be(&hex!(
        "ccd54e04256cd90001d45aa7772ee5c86299a78f6ab06962237a9755ed8e4171"
        "fce852676bf5438aa80023b1f4be67c1a2664e903907a3e94fa98640d867c95e"
        "9fc837873c58c1adcfe9ba2624089b45d841bb838be73470f319ccf5541d27dd"
        "e7734a59a242f796d8c6e21129c95ea5b5b7a9ea6346afc55b7f725b4afd18c1"
    ));
    let p = BigUint::from_bytes_be(&hex!(
        "fd9484530f9492f263198e923707318d1b2517546ce6c3eb357e8985551fd95a"
        "6096a1ad74e9ab1715e10cc41c6b075f98f3c8482c4b52c2ea8222faa211cdbd"
    ));
    let q = BigUint::from_bytes_be(&hex!(
        "e962d1151bf00073d3ee5cda8b22a3b03685cf203daf4f9cb110d50dedd52799"
        "92ab6c68dfed18a1e17aadaaf3a524dbc90a6c8569e0d28f16053551acda80e5"
    ));
    let privkey = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]);
    makiko::Privkey::Rsa(privkey.into())
}

pub fn ruth_rsa_2048() -> makiko::Privkey {
    let n = BigUint::from_bytes_be(&hex!(
        "e248796bbb1912c2131adb59e32415bde6f1ed68ca3ba582eb70b9c45e728ab4"
        "9f58d01585a9269a556a0437b494f6fd57713a02437f80b395a92748e272f4ea"
        "95ee818f683d25461d1eae9d024e7f6e19b404c02b13618ee6fd7fd467e7ba62"
        "250f48306c1e726df5e5c83beb80a0e260a0530dfabb8e470b7bbd03fd6804b3"
        "a043c588242ef45659f0223047c929d0fa183aab20052aaba0aa78f468c1b668"
        "4e5742ffc9f65443e2ed068774cf55ef7799f50d32fa920e64834d2b61ab0d8c"
        "9a6561b69b17a28cea51de0f8f9bc7f5d012fe74e2ceb3ebf692a08fd2e23c76"
        "9b9e9d121cda1f26f2a2781741aba1da0353f3dcc2f694f712d654951d609e01"
    ));
    let e = BigUint::from_bytes_be(&hex!("010001"));
    let d = BigUint::from_bytes_be(&hex!(
        "41e470d71a2876f9e4ae51699f67069dc1fe78efa6d42fa22c052b532f5d935e"
        "7d78533fb1284c816c95ee9c7a0d56cef70395accb12f9db519d6c3f2111f097"
        "cf0920d92db580812641a4ff3b88b83acb694c68d9224faa594140540dddc0bc"
        "8ba6239356289791c5a51fe5b2f245e725d409db6c43e96e6ebd9d90e7ddbe60"
        "3402a07c12800e1674f77bbe85bb61be16b3c7606e9aeea35887c2b95b95911f"
        "5a54682f71a7cd4081ade177b69851a9bcd9e3f2ce93ca63dfefe49b9418efa7"
        "d2c33862792e50bfc26923fb975ced69c827e047fa4099e9935c9e5fc3aac2f1"
        "d1663e037ff3a8ac7755031e909b1f0b2ff1ba30f8d34572871444c66b0e1531"
    ));
    let p = BigUint::from_bytes_be(&hex!(
        "f0f31c437f765fc87fcf479a530da6637259e80bda84df779da810a2eb3e26a4"
        "57b2f234e473a3ca74f6696d9c66fafff4eb8cef0e1ac05225c00b1857dc347d"
        "3b20248383d993807a2ec3c5cd32ccdc4bac121c54d12bc92529bf86d1483898"
        "43da68ae7581cee6fe7360e1b7471c98a87c13b0f8662042b62d178d54eb3a87"
    ));
    let q = BigUint::from_bytes_be(&hex!(
        "f06ad6e4fc578f4310f0b6a977af571646f42ac0757ac017a3599c679eb04d6e"
        "b5813e561cf2e6e100bcff381b7aa622c5f9089917dab5765a13d82959b27764"
        "a7b88f7ccb93223aeaadc6771bd9a6b6b67138383805f42c4c5cff58b6c4e7f5"
        "76f0cd4a3193f8e4ca2678fa931dc03f621323799b9c565d2953b5d4c1cc5d37"
    ));
    let privkey = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]);
    makiko::Privkey::Rsa(privkey.into())
}

pub fn ruth_rsa_4096() -> makiko::Privkey {
    let n = BigUint::from_bytes_be(&hex!(
        "ed89a6dda8e80c2d90d6ef0b69fa1ff02045ba736c015f88a8a6e9bd7b13dc41"
        "40c421a754d30a7fa1efe15686547d69e8efe42d076e7262b7df4e9e814b80ec"
        "e236744b00bf95c748324e001a55e140ee7c58d4d0e02ad58c08b9df060a775f"
        "c85b8ef60fd0db8275a1402cc39107f06fb883e7115a838dedfba78a46773a74"
        "46f6c8b3a2c515dbeec31351b0617545201211fd033a03b126ebe345d8628b06"
        "5390cbea2775bdee8cff35e5ed6ecb7f9f2b7e1527c733b32cb91043c2fd361a"
        "d745af5ed7bd431f7e98edb436b35cabc755176cb5e72886c6040c09ee744d43"
        "99a63bd8facafb5c2a2cc9c523e582070859a8c8ae79c0da9195cd059737cdc5"
        "d760b1c4bb77ffb5cc08f34d7a5238980945b1796f12aee31197fe85b4fa22b4"
        "402ee76d1cf0971022c3630acbe5d28f38a03f5fce2e54e1e2a5f20e119b785e"
        "4a1060302a685abe0d2760c9a4b3ddaf90b8e03cc7a28881e8e6f5ce27b1a175"
        "b3d215ba10e76c3bf61052ac9ae79cbf2fee89e266679f9e981a850361983395"
        "6ce39238fbd64e98ce717b88861f954ff1ef9641a3cbf071fa9607277ba21656"
        "bdc662eef52f8119542f35919968c3a8a61fdea485589758945bb165249aa500"
        "ca5f1d10ad96a82d4f308286e36efd5768cc6ab00469ff0f89dd9fd8fedfc027"
        "6934d8a1383f0769cf7dacf8c5aa9e3bca0e923f53c849ec9c974c41d2033f09"
    ));
    let e = BigUint::from_bytes_be(&hex!("010001"));
    let d = BigUint::from_bytes_be(&hex!(
        "2feb560b5f78b88434b4f7726105c18daaa506712477be730e3ae5ea80bac7f3"
        "2e02a31b63a45378de0d4b732e143b5cb34e39c4cfbbfb3d69049692a958b700"
        "92be1385d1f7d45a6879257d25d2ef672ef54ce259e4ef1f3769c73d73b586d1"
        "7ed4e1a948158542f341fd754a5aa6b45d8566aea5b491d77f0c068781a1a9dc"
        "2d38b9d26b62c0ff26529a421f87f9a5614be3ef1bc887582496efb97666a2cf"
        "3aea7a0899bf49faa6dd115d7a21a0d1f5254c012e8e2422e041d1432a41f4b9"
        "43765e638eb832a356e1b90a63029a0e595f1423ad2a9de55a6b1496a8513409"
        "102515ebb6e45e0300cb1a4537f1a3e2914fad1a17009ee438fc7468cd51c7a3"
        "df476887f187ca1e9469fb0793a1afbbb2c60f64a1fe19776f3d96486d2e15d6"
        "208b037e519e91423deaa87954d59aba3bfa316a93c3ffba16b57d8e03daa509"
        "7b0aee81ec099f028ef0c814908a871666e25d004bb276ea3c4f608f20194175"
        "1ff56a9e12fc40ad1b9cbc792fb535e38b5d384163b4fab42c20766290cbc4f4"
        "32db6d094de3cb9494e3d42a5465640360252e5b83b406952463ae0ba4ff1734"
        "d2d56ee2a2117a743a66f5598f54555aa464f08774e7d0ec72ceef95c50f4554"
        "5108b1409a2dab28062dbcdb35f067fb9431ec33a946b8c7e20c7d477d778ffd"
        "680fb2a4b0dbf04cca3da016f5726a955645387d25faffdba9a2c7a2f1460381"
    ));
    let p = BigUint::from_bytes_be(&hex!(
        "f9cbda75eea8ca71a5bd0a586d9793077779fbb11ebc1c6e31183dfa79d93f88"
        "ac3406d115cd395b3679dc32ad136c94a8d6a54383928b92391c33b3cfc76c45"
        "f23431e7b9e5735e97458b9c083c7fb83353aae008d5a8cb92ded469081ebcb5"
        "43885f7dceb0f3375cf4f6b64b6251304bc6d8fcc25e29b20affb7a9feeb04cf"
        "6b481ed05bfe68e5ac7c2054ce4fe83de5c48bd44d383ae35ad1f8a5376ac194"
        "c83017113d5163e8439920c2afc972dded06d0e63a2e2e0d484fc48d10e81a04"
        "0ca44a9e9805df1ef4dfa740cbde7d20ef7c08ea392455410328a653aff1e2bb"
        "9d8800ff39578a5a5229cf97b24db66379e356744e96aa3ddf0a256df5cdd5d1"
    ));
    let q = BigUint::from_bytes_be(&hex!(
        "f36fdc739bb0b7c933e5e086023aab31235f59cb4ec16da80054e430ee849b71"
        "efb34f7ee74eaf091c4a5519bc706401c048acb41d3fb9786ebd88eb7dfa0f26"
        "ec0eba2f37d823af8235bb97bf7423fe918683e7e0121fbb8a56ce2e908ce156"
        "208057ed6b6e39ca542d588e44dcffa3db4a9245a9ccceae83d63a354a005a2a"
        "b7b49612ecb1967f49d6aa2477e6211e482edd69e8e4cbe6206aff487c6eb4aa"
        "38270f8289c308c4eca9fdcb78df73d1fd34c3893fe41b69152ef20a0081fdf4"
        "45bc7b533ff23bc9e0d60e0b80cf7d995ba3d4504a0df457d55f446106d6d553"
        "f07198cab9dccc0753c42a1f94418b81c83a97db8c1d01516b804f02ef07cbb9"
    ));
    let privkey = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]);
    makiko::Privkey::Rsa(privkey.into())
}


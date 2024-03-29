module Bridge::RLP {
    use StarcoinFramework::Vector;
    use Bridge::Bytes;
    const INVALID_RLP_DATA: u64 = 100;
    const DATA_TOO_SHORT: u64 = 101;

    // Decode data into array of bytes.
    // Nested arrays are not supported.
    public fun decode_list(data: &vector<u8>): vector<vector<u8>> {
        let (decoded, consumed) = decode(data, 0);
        assert!(consumed == Vector::length(data), INVALID_RLP_DATA);
        decoded
    }

    fun decode(data: &vector<u8>, offset: u64): (vector<vector<u8>>, u64) {
        let data_len = Vector::length(data);
        assert!(offset < data_len, DATA_TOO_SHORT);
        let first_byte = *Vector::borrow(data, offset);
        if (first_byte >= 248u8) { // 0xf8
            let length_of_length = ((first_byte - 247u8) as u64);
            assert!(offset + length_of_length < data_len, DATA_TOO_SHORT);
            let length = unarrayify_integer(data, offset + 1, (length_of_length as u8));
            assert!(offset + length_of_length + length < data_len, DATA_TOO_SHORT);
            decode_children(data, offset, offset + 1 + length_of_length, length_of_length + length)
        } else if (first_byte >= 192u8) { // 0xc0
            let length = ((first_byte - 192u8) as u64);
            assert!(offset + length < data_len, DATA_TOO_SHORT);
            decode_children(data, offset, offset + 1, length)
        } else if (first_byte >= 184u8) { // 0xb8
            let length_of_length = ((first_byte - 183u8) as u64);
            assert!(offset + length_of_length < data_len, DATA_TOO_SHORT);
            let length = unarrayify_integer(data, offset + 1, (length_of_length as u8));
            assert!(offset + length_of_length + length < data_len, DATA_TOO_SHORT);

            let bytes = Bytes::slice(data, offset + 1 + length_of_length, offset + 1 + length_of_length + length);
            (Vector::singleton(bytes), 1+length_of_length+length)
        } else if (first_byte >= 128u8) { // 0x80
            let length = ((first_byte - 128u8) as u64);
            assert!(offset + length < data_len, DATA_TOO_SHORT);
            let bytes = Bytes::slice(data, offset + 1, offset + 1 + length);
            (Vector::singleton(bytes), 1+length)
        } else {
            let bytes = Bytes::slice(data, offset, offset + 1);
            (Vector::singleton(bytes), 1)
        }
    }

    fun decode_children(data: &vector<u8>, offset: u64, child_offset: u64, length: u64): (vector<vector<u8>>, u64) {
        let result = Vector::empty();

        while (child_offset < offset + 1 + length) {
            let (decoded, consumed) = decode(data, child_offset);
            Vector::append(&mut result, decoded);
            child_offset = child_offset + consumed;
            assert!(child_offset <= offset + 1 + length, DATA_TOO_SHORT);
        };
        (result, 1 + length)
    }


    fun unarrayify_integer(data: &vector<u8>, offset: u64, length: u8): u64 {
        let result = 0;
        let i = 0u8;
        while(i < length) {
            result = result * 256 + (*Vector::borrow(data, offset + (i as u64)) as u64);
            i = i + 1;
        };
        result
    }

}
module Bridge::EthStateVerifier {
    use Bridge::RLP;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Hash;
    use Bridge::Bytes;

    const INVALID_PROOF: u64 = 400;

    public fun to_nibble(b: u8): (u8, u8) {
        let n1 = b >> 4;
        let n2 = (b << 4) >> 4;
        (n1, n2)
    }
    public fun to_nibbles(bytes: &vector<u8>): vector<u8> {
        let result = Vector::empty<u8>();
        let i = 0;
        let data_len = Vector::length(bytes);
        while (i < data_len) {
            let (a, b) = to_nibble(*Vector::borrow(bytes, i));
            Vector::push_back(&mut result, a);
            Vector::push_back(&mut result, b);
            i = i + 1;
        };

        result
    }

    fun verify_inner(
        expected_root: vector<u8>,
        key: vector<u8>,
        proof: vector<vector<u8>>,
        expected_value: vector<u8>,
        key_index: u64,
        proof_index: u64,
    ): bool {
        if (proof_index >= Vector::length(&proof)) {
            return false
        };

        let node = Vector::borrow(&proof, proof_index);
        let dec = RLP::decode_list(node);
        // trie root is always a hash
        if (key_index == 0 || Vector::length(node) >= 32u64) {
            if (Hash::keccak_256(*node) != expected_root) {
                return false
            }
        } else {
            // and if rlp < 32 bytes, then it is not hashed
            let root = Vector::borrow(&dec, 0);
            if (root != &expected_root) {
                return false
            }
        };
        let rlp_len = Vector::length(&dec);
        // branch node.
        if (rlp_len == 17) {
            if (key_index >= Vector::length(&key)) {
                // value stored in the branch
                let item = Vector::borrow(&dec, 16);
                if (item == &expected_value) {
                    return true
                }
            } else {
                // down the rabbit hole.
                let index = Vector::borrow(&key, key_index);
                let new_expected_root = Vector::borrow(&dec, (*index as u64));
                if (Vector::length(new_expected_root) != 0) {
                    return verify_inner(*new_expected_root, key, proof, expected_value, key_index + 1, proof_index + 1)
                }
            };
        } else if (rlp_len == 2) {
            let node_key = Vector::borrow(&dec, 0);
            let node_value = Vector::borrow(&dec, 1);
            let (prefix, nibble) = to_nibble(*Vector::borrow(node_key, 0));

            if (prefix == 0) {
                // even extension node
                let shared_nibbles = to_nibbles(&Bytes::slice(node_key, 1, Vector::length(node_key)));
                let extension_length = Vector::length(&shared_nibbles);
                if (shared_nibbles ==
                    Bytes::slice(&key, key_index, key_index + extension_length)) {
                        return verify_inner(*node_value, key, proof, expected_value, key_index + extension_length, proof_index + 1)
                }
            } else if (prefix == 1) {
                // odd extension node
                let shared_nibbles = to_nibbles(&Bytes::slice(node_key, 1, Vector::length(node_key)));
                let extension_length = Vector::length(&shared_nibbles);
                if (nibble == *Vector::borrow(&key, key_index) &&
                    shared_nibbles ==
                        Bytes::slice(
                            &key,
                            key_index + 1,
                            key_index + 1 + extension_length,
                        )) {
                    return verify_inner(*node_value, key, proof, expected_value, key_index + 1 + extension_length, proof_index + 1)
                };
            } else if (prefix == 2) {
                // even leaf node
                let shared_nibbles = to_nibbles(&Bytes::slice(node_key, 1, Vector::length(node_key)));
                return shared_nibbles == Bytes::slice(&key, key_index, Vector::length(&key)) && &expected_value == node_value
            } else if (prefix == 3) {
                // odd leaf node
                let shared_nibbles = to_nibbles(&Bytes::slice(node_key, 1, Vector::length(node_key)));
                return &expected_value == node_value &&
                    nibble == *Vector::borrow(&key, key_index) &&
                     shared_nibbles ==
                        Bytes::slice(&key, key_index + 1, Vector::length(&key))
            } else {
                // invalid proof
                abort INVALID_PROOF
            };
        };
        return Vector::length(&expected_value) == 0
    }

    public fun verify(
        expected_root: vector<u8>,
        key: vector<u8>,
        proof: vector<vector<u8>>,
        expected_value: vector<u8>,
    ): bool {
        let hashed_key = Hash::keccak_256(key);
        let key = to_nibbles(&hashed_key);
        return verify_inner(expected_root, key, proof, expected_value, 0, 0)
    }
}

#[test_only]
module Bridge::ProofVerifyTest {
    use StarcoinFramework::Vector;
    #[test_only]use StarcoinFramework::Debug;
    use Bridge::Bytes;
    #[test_only]use Bridge::EthStateVerifier;
    
    struct EthAccount has key, store, drop  {
        state_root: vector<u8>,
        height: u64,
        address: vector<u8>,
        balance: u128,
        nonce: u64,
        code_hash: vector<u8>,
        storage_hash: vector<u8>,
        account_proof: vector<vector<u8>>,
        storage_proof: StorageProof,
    }

    struct BasicAccount has key, store, drop  {
        nonce: u64,
        balance: u128,
        storage_root: vector<u8>, // self.storage_hash
        code_hash: vector<u8>,
    }

    struct StorageProof has key, store, drop  {
        key: vector<u8>,
        value: vector<u8>,
        proof: vector<vector<u8>>,
    }


    public fun init_eth_account(): EthAccount {
        let balance_hex:vector<u8> = x"00";
        let nonce_hex:vector<u8> = x"01";

        EthAccount {
            state_root: x"fd725b0325c2bda54cf7e33e3b9f6bc9b7927beb7ba6a2ef5feef7d20b394168",
            height: 11146077,
            address: x"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            balance: Bytes::bytes_to_u128(&balance_hex),
            nonce: (Bytes::bytes_to_u128(&nonce_hex) as u64),
            code_hash: x"d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505",
            storage_hash: x"a9302463fd528ce8aca2d5ad58de0622f07e2107c12a780f67c624592bbcc13d",
            account_proof: init_account_proof(),
            storage_proof: init_storage_proof(),
        }
    }

    public fun init_account_proof(): vector<vector<u8>> {
        let account_proof_slice_0:vector<u8> = x"f90211a039fed75b49c0a6d1f40ac24dc3d78113a86d903af75b5f755e4f8b31fa853c0aa0f7a04d1ae40830305133a7a65b1db592d0a1058df2200605ed1d6133949a6ecda0c932a6f90d2ac6e99476ec8ff02f033f6b10d5c2d0c8260775a95ec9acb0e70da0d3dfb0abd32670791c8d7ea4e4ec91597f5aaa5751c1625d31dbf83afd7cde41a0e413022d7c9dc2d92a7dfca5871db93b8e8bce48d0fb3fde196872aa45a5b5eba0873cd98810f64aaca097822877b84bed32c3a61ba4eb610a5d515c9fca883ed7a0cc2699c6ed9508b8dfc6a31652c718d3dc65870c7aa595c5d973824e50f26515a0a4f2e659e0584b974c2b066d44d262f1d9ba1c521ef7eb4395ff08e3c577748ea0624031f4a00a06f3edaf603f7145bab2996cc4290d277c0d4be0008ddee1fc7ba0198188a0f6687aca76854927f8415942bb433120d0a323ad60e416f20e177285a00733760b383f584efb11a10c2d0a1a668660c726a74cc4820f1e1a52c1b5ad78a0151ea4eac7711b7a4848f76e200991fe81c80de315c94b0b4bd6dde829e36313a04e937d24c9c3e4bbf082f5a5ede7b6f008da8c9faeaccdf0f0ae1ed735bc173da09add0ef904731043b77e6ba495279f5667cf7a26ae8b4a8be7fc4b8169615fb7a02528aedcda9e3c27e31ff5d3cafc8c79d6569b355fc8dbd3e0df4093ea71a158a0fe070bd479438a29ec302c38366c6df2528fe7348e01a23f06da15aaaa0cff8b80";
        let account_proof_slice_1:vector<u8> = x"f90211a01b716021a6c4e9766f357c63859e3eae2ceed9969c6d9f66c9bbd327958f6502a007537e21da9a254ca8710f06ac3e7e24a9f54be025a606605c603ad061e397cfa02c4e6df9e22f1e6f0fbb5647659a13cf8233fabdf6459a38857aea26e8849f84a0e33ce848125b69660c12e6c7b11c226e9a661acc295ca9ed9cf6bd1c237b8e74a083a188a9d01e80f45ef23e47b373e68a68b3518057fc87d8e43df50fed0ed185a0c3f401141a99070e964adbe73508641d30d02ea44f4735e3a66f62503c6d13b3a0db98ee916188e5419a30ffbbbb9d558fe05073f1cb88ebe26f3f6b134f5d9a9ea02334d97db5777550d26befa2d014c178d2d715a9685a4135d59ef037a6ef8c17a0e7f79dbdd63b3d783c667c6142e5dc34840b4501885187cd1835550d111812d2a000a5292386ad8eb311292d0ae459847ad39ead7341552a1d2e7d073310fd2124a0555ab491b4003c7e9dd278b40c8bf70f525447e42179a9392f30c999f3d2acd0a061647d9cedd5b565ce902b06de043880d5caf5e264ab11175f44206562f2ccaaa09c2a74e4a93f4bd0d1be61b559555405abf97560fc88abd0daddef096a31816ca00422ccdfa4fd76206961febfca80a9eb1d4b1c5a8ce358dcc18c6dcb5c691822a0f820d15c72d71bcd2ef63b4f62415dd9025dff2be127bf056d63f65e1867309ea06b73ba01a38c4ffd188fd783efb77ae4a2f2baf2314c18bf292152a4d065c35880";
        let account_proof_slice_2:vector<u8> = x"f90211a0a3c3c63eac1a4674ab6d41facf56090fe9d819471493b98ab5590fa33630fff3a0bc0a0ead4f23d4f3908c86069cefe7aa2c4eac8e9e969b2a4f01c157aa5bbef9a03990876b005cb2196529e6c47d668ae060e17223a100df442746ee606174cfada08d351b3bb64faf7078604eeb2abdb12c284bd307d9f939062c2606b7ab2a1cc0a09a4d05262ea88bcfa00e6e55bacf0d2a9acd20b8125799b70f6f03c8b284df0ca0f894ac4fd64e14ad6e075a1a2461aa3008ee5235c1c5a0ef1d1ccb16cddf8a61a01eac3fba8ccf6d537a71be4a6b7c4b50fce36b16057053f02ddf79999806558ba0a76f25036a9c04a8b6ac3a53b004d3ab43dc6b0af165f325de89e401d408e5e5a0b8878da8c04733a2cecd223047a9ee5aeae4a72ec1d7a636d577e9f57daea282a068c49f2547c5398dc54ffe0e58035bd27512faad5ccbbe8999409e6845e6bc70a02a647296f3a4108c69b9fa8db8d562c6ff95df6c1676950f30af5935718e31e6a06712578a5c46722ddd8da072a6ddf95c77171bb521947fe535dbe5bcd46ef45aa07d86de806c95efb4efa6660579c217590d775287c343ddd4d0849c3645a97583a0175216a6fc4774b6b0de39d4d92f0f06f553d0a6984b7e015dcaafcda686a6a4a0f8373e7e228bfad00b1db8f7903aa9ed4aa0b12d2681402469a2fec2911e1901a07d8c641e07171b76f894c6753c3b667d7e1e93e1b5461df789072b18bda2e9cf80";
        let account_proof_slice_3:vector<u8> = x"f90211a0c629e5ab77599a1b17144521b5bd20226422c82d65f5cb90a4d07ce09048f772a0ef1924a17b51e40168f09936b30db2fd94762813d3e8376b028581537cabc2a6a0eb27517b697198a4559506e71e2f25d284fe13ae7837985851aac75c5dd2be1da04954b8caa68e94de7d660fdb07556c9f126af389c9c00fed9dac96987b8c8f9ca0c3af915fc5ed6616c395f4a18ff796ba69d70d0ee53ba18b6a0c0d7cbc71312ea0258d57b13c032f0d76019a0f576f89d83ec5a5d0113fc54be0bd8d8f74032386a09ec645321981f494c834294543e14d234cf49185612f70ccfd1b87b9ad6e36eda068de0df16e830dc40b79a2f8b0157dc6684769a7ad62a2c4b9e8161cae4b9959a01b492db9e6f0e288b9060338646e348ecef480dc696fde7dafddf45921340f59a01bca054feb512cec6de6cf9ff8b32d00d55ad309318bed3749d979217e311e11a012fbc06097af3f9ce3d85c827ff117929597a126874c2efd0aca6281e6988732a014099e99ff18a19a99dfcbb4162aeeea67e2968be101fcdcbdbf8cbf01b5cee9a0ec3a8d07685c685fd35063d835ad391e74a00c986151be9f1ec7eac5d8812c64a0d663e37d382867e3f05bdb52bb8c0938b4de0048c481ab7fac20559621ec071ca0127ae42fa6278588c6d7e1127cf7893b4221425bf34e685bde63f3506abd95b7a087e13735b0a9eb956c90c9c0cce55853850c9c653581ee119cdfb1b46986b15180";
        let account_proof_slice_4:vector<u8> = x"f90211a02162bfcea6553b9b1a7f465f1ffd0499697404f15ce25e8cb69dd7b17dda3fd3a0f2712a67e448d0273c251f3d535611295d47d58ff7910e6fb1416d0306b2c913a01935dcfa3f91b79b8df6c97a153631ea562b973ac114c8e8e11b8cd008c9b5c5a0f9ab3dba107370dd076ef4ea8bb0c6fa0f08944a13298e90683e89b516d37e94a01a03e9add8a4979ca1260541f5caaad0bac79f24a22e6565d760424a8c5a0310a0564f77138f12d96c08d4952d05d0d049e86b417fb6ed3cc3a945ecf9eb76b8dda02161d776c12c458ee9590b94fde205a14ba693ff112aeb26d329e70e420734f2a02630216a87e7e08006ad1884e2aacbcc8b8974ed5fcf81d0e4ff2e0e2dbadcb8a095033c5eb82321dda067c2f4798c3a67339255874b4f1f41413bebf198db0c7aa0e6ec36fd496a6503e77c0c7ddafdd91f8f9e493d78b3d98a276feeecf8190a0ba0ef07fcf8c42fc5355e672dfa4397c830a1bf124b645396200f46f00f871d4f4ca0e28d7eeadf2475164922f0d367ee104d823f1db00829736871a928d6cf54255ca00f04873e8c09d0e9c9daa07690901806f5535203add732c11c0a53445bb7829ea0d952821bc327e4e0e6e13ceeeee20514ef358f8f97671fcc6d7ffb8f7bbcc596a084bdee7f4fab3ef4e51120ab36f77d3f0bec3f12b886d00859690aa14a632341a0d355083114e01ebe7e19671ac36196cbf299ca8c8420b69dc17716f3618a1bde80";
        let account_proof_slice_5:vector<u8> = x"f90211a09de6b0101efd7a910d3f5c818dda4ae5f683face6cc2adef0241ce09607ac7e2a02854271440ed7710c813922ec25972029fceeb9a71c619ae05a385be54a46a2ba0dbf4471186119f65130ec4de24f5a4549c288085f3bbeec2fce96e85ce79a542a028bed7905f83437274bcf048a7cc08e8873dc8b761e98f387d39e83c2b4a20b1a0718a55da0e5f5f51102838b8f5aa8d8bc7ccbd448eac86e9903edaed23807089a0788a858cb1f272f8c8c2cbc5514d1782a637780e15ecb0f9e5bba5cab44cb44da00575ce84f14cba25cab3aabe9cac7901e6402b84f985f64bc82e4cff625216a5a0b6429f01756315b7fb9de64ac831c3dcc706663d26e71ca8034951c394ec0a5ca0cfea6a7f844bae7ada294525a8e10aa81fac634924ec47ef303eb36d752cac76a043890cca104e25bf95636b875fea6214ffb680cfc37fba9962c642b161cae2afa00926c77779136644c659b65c48532a57be7923a70ac7ff0872f93f9b27f2597aa010c67946f8fdbf8fbbcb9320e6bafccb1d8ab34eacc242dd7f8a8d0d6306e32ba0b1a825bf9182504c086d64ac2a4fdd072136a86984e895df7fd6499a048b452aa0db152acded3fb8df9f4d1005cf7f4d38fc1c0d6d1c55b81385d2d92c7397825da04ca471ce492cdf4692406b2b2787b1c78258350225c40814af8687d89c78e460a0568b92c18e85758988981c993b44794164d5291f164d3d38910c2e4ebf0c9cf680";
        let account_proof_slice_6:vector<u8> = x"f8f1a075aecc05e77688cfcf7b2be6918d317d40f84ac70ae82fa00e363eb6d54e9d6f80a0c66b311f312e309f3cb80cce2ea55e7fabd55bfd222297868b8cda2186c5e0dd80808080a0d3bee690d48173444d679a7ab969cd9199b83ac3de64db3d987dc6aa2ddb06e780a07b3eb22f76a4e16a632f1732fe234e87fd2bea81ffe1dbba8ff04495319b0257a0903e3cd41d04b4693e0eae1549f7fe024eb06b98fa1c137cacc66d57a7a0e223a05d07ec85b94b44ef509a9cff840b0ce44facf7e79411967c7e9fabcaa354629b8080a015234d9ef39b97af083fb5715dd5cc2f4454a23ca3a4d72419cfde3ea918036c8080";
        let account_proof_slice_7:vector<u8> = x"f87180a0568a3548f0c468bec66c6d91b1d72f84e44373c03c6e118d7edc6ba8fe9b4d0c80808080808080a0ec26e129a6fc11a5dcc748bd22ca4e41a0ace63cbf1cb2de018e2b9585a06fc680a0de28cbec81a40883ee13ca2ca4a047f79f9b7b411898941314270334f0c86ec38080808080";
        let account_proof_slice_8:vector<u8> = x"f8669d2092cd7f3f78137497df02f6ccb9badda93d9782e0f230c807ba728be0b846f8440180a0a9302463fd528ce8aca2d5ad58de0622f07e2107c12a780f67c624592bbcc13da0d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505";

        let account_proof = Vector::empty();
        Vector::push_back(&mut account_proof, account_proof_slice_0);
        Vector::push_back(&mut account_proof, account_proof_slice_1);
        Vector::push_back(&mut account_proof, account_proof_slice_2);
        Vector::push_back(&mut account_proof, account_proof_slice_3);
        Vector::push_back(&mut account_proof, account_proof_slice_4);
        Vector::push_back(&mut account_proof, account_proof_slice_5);
        Vector::push_back(&mut account_proof, account_proof_slice_6);
        Vector::push_back(&mut account_proof, account_proof_slice_7);
        Vector::push_back(&mut account_proof, account_proof_slice_8);

        account_proof
    }

    public fun init_storage_proof(): StorageProof {
        let key_hex:vector<u8> = x"49c4c8b2db715e9f7e1d3306b9f6860a389635dfb3943db13f1005544a50fbb2";
        let value_hex:vector<u8> = x"014e95f5a48100";

        StorageProof {
            key: key_hex,
            value: value_hex,
            proof: init_storage_proof_proof(),
        }
    }

    public fun init_storage_proof_proof(): vector<vector<u8>> {
        let storage_proof_proof_slice_0:vector<u8> = x"f90211a0e62e1acc64b071fde44901c09efa7a2442bc053cdfe6c2e5c51d11437b84e7d6a08b2dd500665d24ba0cb1cc63b4fb635d41f628a865def35d4e9a27629ae6c68ca0ca19f1a8d953c9080295929903228cf57574f744902b48d900b24e4c4e319e43a03ea8dadbc9e76d1d720e290c0f1211482a6dc2f77db7d9acba92f173bf4d73b8a0c2950cd953d803e73c7c2752c5837ec44699bedd625ea3b003b22eeb97d94bfea098b6ddd236efe34f443f5e0a3cdedeef6c2eec5d6ca1391ee07929dff62755f1a0c61b4da5ef023198aacb6b6132bc250252e8541609bd370f3f5528fdb2e9481fa00dfe1436977f60f66464eef277d21981df06ba7e1425fd94581ca36eae0978aaa0c8dc83fad9c717ccd9d3afdd21ffe2164efcdf058d784f05996c1d4d48f9f9d1a08da439979f9c70448e6880ac8d34cb78387ab6cb830cc6b0d0b97cb19b0b58cca0a1581e43412fb1e9662eeab392beb663e67079aebf491518c2730e2bc59f4835a0a8c4b00430a704f07c784c49518d686f2ef826099ccba44b5be7c4744567b89ba0622320bab4969a7c89927492f9872f1762e1ac13d58c2174b06151ede9171000a024617e7256d67da2781d7edde08a3431a97a4ff154fd97abce8de67e0d3907aba0b60cc3dca2f93d40f3f21a6e2c8aefcbcf9f8c10523838194d56f511c8413b34a045851e88c0fee11b669fc8ca86957758f1c488078c69b7b810fc5c6342e284c580";
        let storage_proof_proof_slice_1:vector<u8> = x"f90211a0860feeaa8da3f512ab46dabdb891faaf1807ba240252274b5c5dfd731ead55f4a05bdc1e2b60be129264d8ecb1643dc35e0235eb721501b5d1ba6a471e2e7c1240a00cac1a0a8ad2a1013ac0fde58b345f9abc19a173c9e2249d1d7061551a41bc01a06555e5c377d477784085a54d62ecf6eb398d86afb2bfab9be3bbf6f1ee4f5590a00780251a4e9fc5f8cd636bcca2b7c684d0aed9e452062c05acbae34b9c732321a0fba7dd1482a2148c7bfa7a5fc0f383ebe005a8e295486f38a589b4a30ef379a2a031f0d9fd5f641b7aef0e8e08fe2da526bcb98a6e933bed1d1339515c112a8c24a0fc2bd1942e5852aa6b4a08c6156d598d157e2062857280fad1d45207ad294e6ea09578d621e51ada5bba3087279e76c906f4b3efc11c5b42580d09168873993a7da0f1f328145fd7be1c82f3fc524e8954ad817552f872aa8bec1ee1cd3e5a2022b4a00e396b47ec153b6372627c1505dce3ce741035660bebb63c2f578adc392efb92a09de1cbc4e13a886c9c72d65e89fcc1608c02f4ab3421b02c223af8ce60916d37a0f09d7d3bbf38403dcb674f5723f6ce2d5a6a84870f6efb513217be126dd15366a055f428565f2065c798319f615381954caa42d25d838beba4fffa9f80e1ef828ba06b528398dfa6087a2e0c2d267eb6d100b891772af45015df1ae4c9e3480af69fa06d668aae28e38f21aa22f8129a5bed8554ffdb39d05b0f5ccecb4be126c6571180";
        let storage_proof_proof_slice_2:vector<u8> = x"f90211a0731b9f54cd38335a6d2ef9463c73a847e9834a60a4d9e3b76c6137f2d16a5004a06aba38c58f4de79b5251f81ff5ca0de4ecd49f2ada694c467d78681c28c55ccda0ea63ebace8764b5c6d46a6c1995fa9d94b284b7d307576f1226719bc8a94737da04c2306e7fe2e74dcac5c9e5e8bf617ec097b6b4aabc7a27b469b72656580ca2ba0967df259734d12946e1fa18f32614b99e3fcb789db19ff023ec886bc16badd7aa01f0e86c3ecb93adc678748ed4518d23d12ef61ec532e90c7222589aecd626edda097d7e9c04db1a801dc0ce2a193a5a2702e816905a4620dd50d82b61619257563a025f5e3041a52b1cca05cbfad0f79d35d9dd852af284d13c67f56067df254d288a095d846cfcf2ea1f9ee9faf9363835c02b2a6b2d8eb71e10d20afd6932753473ea0c4a7c2d6bb8e22469d831be708ae9f182ff94eecd019c82b99a176e251b1af17a0e42b47e7c3ee9fe201c42c9d0f9664135688ed574a824410bc42bcf93f608cdda0f610da1d7b11d1fa870246171a4cf26afc6f69a1965ba2a41921939542dced67a011e9851ba26fc6f162a3f12189bcf665ead7d138f816268a23d2bb6264c2d813a05ac5a8730b4271119e4873be5fedca2e5f1ded84aa6746d6ea89a38afae785eda082b3d2eac9a325ac22e264169f58f1b9fa803db85592e66625557c2ce97190b2a0b2c1e2ed4ff26320497c7c6fc4a76fd6f8c4d2e2c2ca330454a93be0d0876ea680";
        let storage_proof_proof_slice_3:vector<u8> = x"f90211a0d22bf91874b3d45ca94cee5c4210d9f5b24fb3f03a9a35f2fe36dfea4537f6dfa0420cbe25b9124aa27869c1b68c8fce40a2296218fa62940e39d3eb7c7fdc8317a0716f79b13a07e6b69d0deb3727f8107482b0218eb35e8a0106dd7088b0ad4ca7a03064266303865f34d7f22c206a8d350f700932bc1f7ea4219f32a8a4c4b140efa03dab7936da1b5b4d613c51f9d71bf4e127b95e7f75e4c35581ab1bf7f2687109a0722f339e6e8eed2a4352581ce876a3de7bf7911f6d602b0b6d462cafa36f6854a09443c709e573c5a4b3ad8059440b7dda92b6ff3300aacb268532b1afd1a4dc81a054f916991e0cff532fb643bc7ffe3821060accedfe15962ede787529a5d8b030a0e4b48d88444920d1fc3b7b018f5c7a7f17c5a8240babf522a3950bbb5ba363e5a0fd76d2060eaedcfe20190525f7affbb87cac5565e4d3c921b22c41d2bdc20007a0539b1e1765734b07fa5deb989d3fed1a60ffbe7bb7cfe5da062aadeedc3cb61ea06e531ac45644b01649c0d5e71995c4af5ee94ca94ef1cc67eb9de338015dcf93a093ef683145c52c81021f4e663b1f9b1964bb945d1a404fc3a869931d65a0744da0d8e07d38b5a23a570314029e7f915c0be9b534a3f6c91a3cfa2881a71d4024b0a01edcd31a8a97ed0f7472c926d7f85b772f1d743b2daeaf933d04230acbb867caa0fb9214798aebb7edb921f53be4de50fdf13cb81d765d07d2daff177d4c3a73ec80";
        let storage_proof_proof_slice_4:vector<u8> = x"f8f1a0ceccff816a886b06d94bca3b53df877952ce900d7ac7c8358f1e98f26ac495b3a0a716f78e3e95bd4afcedb841bde324ed0409fd1558d38cf0fac414482af2947e808080a0f06845ee91d07ae23d31d519747ffac44c63484774e65c127456af81625da496a0358c4482854960c58c8fd44ea0d5286dc9b4a8f231db373678fa8b7809abb32fa0e820cf4ba798c2032313f81cbcb76f180f0e4a18ca0628277742520793a568b9a099cd28647efb126988ff2fbf7f4cf06ac13102a76c068e50ee2ddc1fdbf706b78080a0539eeefa1bf495aec1010701dab11ee27b90a7f25bbbaad6fbd8e9c60849a7a48080808080";
        let storage_proof_proof_slice_5:vector<u8> = x"e89e3d637bfb05fd0393af2b1e03c3b0e0489e8bcd9cc6a506d57e7df4b1ef698887014e95f5a48100";

        let storage_proof_proof = Vector::empty();
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_0);
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_1);
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_2);
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_3);
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_4);
        Vector::push_back(&mut storage_proof_proof, storage_proof_proof_slice_5);

        storage_proof_proof
    }

    public fun init_basic_account(eth_account: &EthAccount): BasicAccount {
        BasicAccount {
            nonce: eth_account.nonce,
            balance: eth_account.balance,
            storage_root: *&eth_account.storage_hash,
            code_hash: *&eth_account.code_hash,
        }
    }


    #[test]
    public fun test_account_prove() {
        let eth_account = init_eth_account();
        // let basic_account = init_basic_account(eth_account);

        let expected_root = *&eth_account.state_root;
        let key = *&eth_account.address;
        let proof = *&eth_account.account_proof;
        // expected_value encoded by rust tool, move need to realize the RLP encode function
        let expected_value:vector<u8> = x"f8440180a0a9302463fd528ce8aca2d5ad58de0622f07e2107c12a780f67c624592bbcc13da0d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505";

        let result = EthStateVerifier::verify(expected_root, key, proof, expected_value);

        Debug::print<bool>(&result);
        assert!(result == true, 1101);
    }


    #[test]
    public fun test_storage_prove() {
        let eth_account = init_eth_account();

        let storage_proof = &eth_account.storage_proof;
        let expected_root = *&eth_account.storage_hash;
        let key = *&storage_proof.key;
        let proof = *&storage_proof.proof;
        // expected_value encoded by rust tool, move need to realize the RLP encode function
        let expected_value:vector<u8> = x"87014e95f5a48100";

        let result = EthStateVerifier::verify(expected_root, key, proof, expected_value);

        Debug::print<bool>(&result);
        assert!(result == true, 1102);
    }

}
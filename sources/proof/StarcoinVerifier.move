module Bridge::StarcoinVerifierScripts {
    use Bridge::StarcoinVerifier;
    public entry fun create_merkle(signer: signer, merkle_root: vector<u8>) {

        StarcoinVerifier::create(&signer, merkle_root);
    }
}

module Bridge::StarcoinVerifier {
    use StarcoinFramework::Vector;
    use Bridge::Bit;
    use Bridge::MerkleProofStructuredHash;
    use StarcoinFramework::Hash;

    struct StarcoinMerkle has key {
        merkle_root: vector<u8>,
    }

    struct Node has store, drop {
        hash1: vector<u8>,
        hash2: vector<u8>,
    }

    const HASH_LEN_IN_BIT: u64 = 32 * 8;
    const SPARSE_MERKLE_LEAF_NODE: vector<u8> = b"SparseMerkleLeafNode";
    const SPARSE_MERKLE_INTERNAL_NODE: vector<u8> = b"SparseMerkleInternalNode";
    public fun create(signer: &signer, merkle_root: vector<u8>) {
        let s = StarcoinMerkle {
            merkle_root
        };
        move_to(signer, s);
    }

    public fun verify_on(merkle_address: address, account_address: vector<u8>, account_state_root_hash: vector<u8>, proofs: vector<vector<u8>>): bool
    acquires StarcoinMerkle  {
        let merkle = borrow_global<StarcoinMerkle>(merkle_address);

        verify(*&merkle.merkle_root, account_address, account_state_root_hash, proofs)
    }

    public fun verify(expected_root: vector<u8>, account_address: vector<u8>, account_state_root_hash: vector<u8>, proofs: vector<vector<u8>>): bool {
        let address_hash = Hash::sha3_256(account_address);
        let leaf_node = Node { hash1: copy address_hash, hash2: account_state_root_hash};
        let current_hash = MerkleProofStructuredHash::hash(SPARSE_MERKLE_LEAF_NODE, &leaf_node);
        let i = 0;
        let proof_length = Vector::length(&proofs);
        while (i < proof_length) {
            let sibling = *Vector::borrow(&proofs, i);
            let bit = Bit::get_bit(&address_hash, proof_length - i - 1);
            let internal_node = if (bit) {
                Node {hash1: sibling, hash2: current_hash}
            } else {
                Node {hash1: current_hash, hash2: sibling}
            };
            current_hash = MerkleProofStructuredHash::hash(SPARSE_MERKLE_INTERNAL_NODE, &internal_node);
            i = i+1;
        };
        current_hash == expected_root
    }
}

module Bridge::Bit {
    use StarcoinFramework::Vector;
    public fun get_bit(data: &vector<u8>, index: u64): bool {
        let pos = index / 8;
        let bit = (7 - index % 8);
        (*Vector::borrow(data, pos) >> (bit as u8)) & 1u8 != 0
    }
}

#[test_only]
module Bridge::StarcoinVerifyTest {
    use StarcoinFramework::Debug::{Self};
    use StarcoinFramework::Vector;
    use Bridge::StarcoinVerifier;
    use Bridge::MerkleProofStructuredHash;

    struct StarcoinProof has key, store, drop  {
        state: vector<u8>,
        account_state: vector<u8>,
        account_proof: ProofInfo,
        account_state_proof: ProofInfo,
        state_root: vector<u8>,
        address: vector<u8>,
    }

    struct ProofInfo has key, store, drop  {
        leaf: vector<vector<u8>>,
        siblings: vector<vector<u8>>,
    }

//    // starcoin block
//    pub struct BlockHeader {
//        #[serde(skip)]
//        id: Option<HashValue>,
//        // Parent hash.
//        parent_hash: HashValue,
//        // Block timestamp.
//        timestamp: u64,
//        // Block number.
//        number: BlockNumber,
//        // Block author.
//        author: AccountAddress,
//        // Block author auth key.
//        // this field is deprecated
//        author_auth_key: Option<AuthenticationKey>,
//        // The transaction accumulator root hash after executing this block.
//        txn_accumulator_root: HashValue,
//        // The parent block info's block accumulator root hash.
//        block_accumulator_root: HashValue,
//        // The last transaction state_root of this block after execute.
//        state_root: HashValue,
//        // Gas used for contracts execution.
//        gas_used: u64,
//        // Block difficulty
//        #[schemars(with = "String")]
//        difficulty: U256,
//        // hash for block body
//        body_hash: HashValue,
//        // The chain id
//        chain_id: ChainId,
//        // Consensus nonce field.
//        nonce: u32,
//        // block header extra
//        extra: BlockHeaderExtra,
//    }


    public fun init_starcoin_proof(): StarcoinProof {
        StarcoinProof {
            state: x"204b82e5dca0a69a5dc11853530b8f480b598b8cbfd4536ecbe88aa1cfaffa7a6201598b8cbfd4536ecbe88aa1cfaffa7a6201598b8cbfd4536ecbe88aa1cfaffa7a626600000000000000180000000000000000598b8cbfd4536ecbe88aa1cfaffa7a622829000000000000180100000000000000598b8cbfd4536ecbe88aa1cfaffa7a620600000000000000180200000000000000598b8cbfd4536ecbe88aa1cfaffa7a628900000000000000",
            account_state: x"02012042f8b41b427b440624d2e0c09df070591e6a04fe97ae60ed0ee05fc7ff6aa087012032ed8f47f7fc3523fa63d814cfd96a5bb4c35433e2ecdc144e8e0e11ba87bd25",
//            account_state: b"0x02012042f8b41b427b440624d2e0c09df070591e6a04fe97ae60ed0ee05fc7ff6aa087012032ed8f47f7fc3523fa63d814cfd96a5bb4c35433e2ecdc144e8e0e11ba87bd25",
            state_root: x"69cd2d882c034f2cc1f2548a79df15dd983463c4ec0ab48219decf2d948969d6",
            address: x"598b8cbfd4536ecbe88aa1cfaffa7a62",

            account_proof: init_account_proof(),
            account_state_proof: init_account_state_proof(),
        }
    }

    public fun init_account_proof(): ProofInfo {
        let leaf_slice_0:vector<u8> = x"11a2463511d0e430115d0dd6a295add08ef16376ad68667af9059fb1dc8ed014";
        let leaf_slice_1:vector<u8> = x"896e42d78668e7c8441c84a6817fe41f77c1d7e5a01230e0a389b3830b9c031a";
        let leaf = Vector::empty();
        Vector::push_back(&mut leaf, leaf_slice_0);
        Vector::push_back(&mut leaf, leaf_slice_1);

        let siblings_slice_0:vector<u8> = x"6f26fb46d8f3b5cd54c0fb8bdfa7eca3cccef6b4716c21259259899efd53bdd7";
        let siblings_slice_1:vector<u8> = x"5350415253455f4d45524b4c455f504c414345484f4c4445525f484153480000";
        let siblings_slice_2:vector<u8> = x"9ee0d79af1a76f538c3e80e86cddcc381942bb28e1160e7d395d633fc2a4ff01";
        let siblings_slice_3:vector<u8> = x"387c20683a0698e9876d33bf5def92c919456a1d162e60f06c79ac9190b71256";
        let siblings_slice_4:vector<u8> = x"bd21d98f08b6a11c0b20d574d1a8e94351389d179d459362089fce342bf31e5d";
        let siblings_slice_5:vector<u8> = x"3b9ed483e8603866e0edd1bd7fc550dd4639ae22319456527b3bbe28e7a36d6c";
        let siblings_slice_6:vector<u8> = x"e816ca0bed50f6dc02c759322c856f383392b840cfce2a20b099308d1fc245b5";
        let siblings_slice_7:vector<u8> = x"d3b6cef6c3aca2499262f9fb48b0457d2f01bbfb5ef0f10bcde33e3e6fbc5621";
        let siblings_slice_8:vector<u8> = x"dcc98df59fc49041824f66c4652341884d17d0ebc88a1ac28a6ac000ad4dea97";
        let siblings_slice_9:vector<u8> = x"bfd27ade840ae8a17224051b05aab232af6347f36c1e9550e1c3619c42929d1a";
        let siblings_slice_10:vector<u8> = x"6cad4851722580dd7aef55635ff90495f9898e014b072aa8d95d7799d9cc072f";
        let siblings_slice_11:vector<u8> = x"ba3a89873e6f3df314b9b21ab90e6dcfdac79e24e4f179f26892112fdbda49d7";
        let siblings_slice_12:vector<u8> = x"5a3c685b6f4b1804a2facecb80f15be2f293076b99d570596f47f747b0442bc3";
        let siblings_slice_13:vector<u8> = x"efc40acc6af3bbf90ef11a8f30a98972419d272c0abaf7c223170cc29f30428e";
        let siblings_slice_14:vector<u8> = x"4cbcc96016b7bb1dc837e7d4b2b4cd359aa25a54f73de5092a3b77ce0abcccc3";
        let siblings = Vector::empty();
        Vector::push_back(&mut siblings, siblings_slice_0);
        Vector::push_back(&mut siblings, siblings_slice_1);
        Vector::push_back(&mut siblings, siblings_slice_2);
        Vector::push_back(&mut siblings, siblings_slice_3);
        Vector::push_back(&mut siblings, siblings_slice_4);
        Vector::push_back(&mut siblings, siblings_slice_5);
        Vector::push_back(&mut siblings, siblings_slice_6);
        Vector::push_back(&mut siblings, siblings_slice_7);
        Vector::push_back(&mut siblings, siblings_slice_8);
        Vector::push_back(&mut siblings, siblings_slice_9);
        Vector::push_back(&mut siblings, siblings_slice_10);
        Vector::push_back(&mut siblings, siblings_slice_11);
        Vector::push_back(&mut siblings, siblings_slice_12);
        Vector::push_back(&mut siblings, siblings_slice_13);
        Vector::push_back(&mut siblings, siblings_slice_14);

        ProofInfo {
            leaf: leaf,
            siblings: siblings,
        }
    }


    public fun init_account_state_proof(): ProofInfo {
        let leaf_slice_0:vector<u8> = x"9b079b5aef808c36133c95bacbc3d3411d1e8cce4fbc4b524ffab31202eaaa11";
        let leaf_slice_1:vector<u8> = x"76ff35e2cef4404d3c24f1921a49efadd667c912296973b9e3d2733c845f3663";
        let leaf = Vector::empty();
        Vector::push_back(&mut leaf, leaf_slice_0);
        Vector::push_back(&mut leaf, leaf_slice_1);

        let siblings_slice_0:vector<u8> = x"d90fac1a52d1120153241618fb419641ef65539d000fe79bc85ff58826cfbb28";
        let siblings_slice_1:vector<u8> = x"ed111439c6feb43f79451db5110154ea7f28df0fc905886b70ef1176816c0602";
        let siblings_slice_2:vector<u8> = x"5350415253455f4d45524b4c455f504c414345484f4c4445525f484153480000";
        let siblings_slice_3:vector<u8> = x"c1398afdd860b740910ba05a228413e85ee367af22ef1ff22841b0223706581d";
        let siblings_slice_4:vector<u8> = x"b0ce7707bc07c7f14d1d895840442fc5fd022bf889e5e1dd3d3710ff27654e";
        let siblings_slice_5:vector<u8> = x"de1ff7ad372bfd265b576fb5e9f2c5ac2fc7caf156cb04618b1a55e7c0c4fd8b";
        let siblings_slice_6:vector<u8> = x"004c9a82653c9553d83a200dea60afd40f26aaa449da6bd26424a80ca5dd5ad2";

        let siblings = Vector::empty();
        Vector::push_back(&mut siblings, siblings_slice_0);
        Vector::push_back(&mut siblings, siblings_slice_1);
        Vector::push_back(&mut siblings, siblings_slice_2);
        Vector::push_back(&mut siblings, siblings_slice_3);
        Vector::push_back(&mut siblings, siblings_slice_4);
        Vector::push_back(&mut siblings, siblings_slice_5);
        Vector::push_back(&mut siblings, siblings_slice_6);


        ProofInfo {
            leaf: leaf,
            siblings: siblings,
        }
    }


    #[test]
    public fun test_state_prove() {
        let starcoin_proof = init_starcoin_proof();

        let expected_root = *&starcoin_proof.state_root;
        let account_address = *&starcoin_proof.address;
        let proof = *(&starcoin_proof.account_proof.siblings);
        let account_state_root_hash = MerkleProofStructuredHash::hash<vector<u8>>(b"Blob", &starcoin_proof.account_state);

        let result = StarcoinVerifier::verify(expected_root, account_address, account_state_root_hash, proof);

        Debug::print<bool>(&result);
        assert!(result == true, 1103);
    }

    #[test]
    public fun test_vec_u8_length() {
        let len = Vector::length<u8>(&x"6c6e4784a4692516afaf129656f58dd40770f93aba116647afdd80ddc69b206f");
        Debug::print(&len);
        assert!(len == 32, 1104);
    }

}
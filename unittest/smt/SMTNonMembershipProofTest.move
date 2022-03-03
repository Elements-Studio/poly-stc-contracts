address 0x18351d311d32201149a4df2a9fc2db8a {
module SMTNonMembershipProofTest {
    use 0x1::Vector;
    use 0x1::Debug;
    use 0x1::BitOperators;
    use 0x1::Hash;

    use 0x18351d311d32201149a4df2a9fc2db8a::Bytes;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTProofs;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTProofUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTreeHasher;
    use 0x18351d311d32201149a4df2a9fc2db8a::CrossChainSMTProofs;

    const TEST_CHAIN_ID: u64 = 218;

    struct MerkleInternalNode has store, drop {
        left_child: vector<u8>,
        right_child: vector<u8>,
    }

    #[test]
    public fun test_iter_bits() {
        let hash = x"1000000000000000000000000000000000000000000000000000000000000000";
        Debug::print(&Hash::sha3_256(*&hash));

        let bit_vec = SMTProofUtils::path_bits_to_bool_vector_from_msb(&hash);
        Debug::print(&bit_vec);
        assert(Vector::length<bool>(&bit_vec) == 256, 1101);

        let sub_bits = Bytes::slice_range_with_template<bool>(&bit_vec, 252, 256);
        Debug::print(&sub_bits);
        assert(Vector::length<bool>(&sub_bits) == 4, 1102);
    }

    #[test]
    public fun test_bit() {
        assert(BitOperators::and(1, 2) == 0, 1103);
        assert(BitOperators::and(1, 3) == 1, 1104);
        assert(BitOperators::and(1, 16 >> 4) == 1, 1105);
    }

    #[test]
    public fun test_print_fix_keyword() {
        let k1 = x"01";
        let k2 = b"helloworld";
        Debug::print(&k1);
        Debug::print(&k2);
        Debug::print(&Hash::sha3_256(k1));
        Debug::print(&Hash::sha3_256(k2));
    }


    #[test]
    public fun test_get_bit() {
        // Print origin hash
        let origin_hash = x"1000000000000000000000000000000000000000000000000000000000000001";
        Debug::print(&origin_hash);

        // Expect first byte is 'F', which binary is 11111111
        let first_byte = *Vector::borrow(&origin_hash, 0);
        Debug::print(&first_byte);

        let bit = BitOperators::and(BitOperators::rshift((first_byte as u64), 4), (1 as u64));
        Debug::print(&bit);
        assert((first_byte >> 4 & 1) == 1, 1106);

        let bit_hash = Vector::empty();
        let i = 0;
        while (i < 256) {
            Vector::push_back(&mut bit_hash, SMTUtils::get_bit_at_from_msb(&origin_hash, i));
            i = i + 1;
        };
        Debug::print(&bit_hash);

        // Test skip bit
        Vector::reverse(&mut bit_hash);
        let skip_bits = Bytes::slice_range_with_template<bool>(&bit_hash, 252, 256);
        Debug::print(&skip_bits);

        let skip_bits_1 = Bytes::slice_range_with_template<bool>(&bit_hash, 0, 1);
        Debug::print(&skip_bits_1);
    }

    #[test]
    public fun test_fixed_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let expect = x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488";

        let crypto_hash =  SMTreeHasher::digest_leaf_data(&data);

        Debug::print(&crypto_hash);
        Debug::print(&expect);
        assert(crypto_hash == expect, 1107);
    }

    #[test]
    public fun test_fixed_internal_node_data() {
        let left = x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb";
        let right = x"42bfc776a76b35ca641ee761a5f4bc6ebf2d4e2441c517f8a8e085dec3ca443c";
        let expect = x"060aec78413605e993f9338255b661ac794a68729ffa50022aca72b01586a306";

        let (crypto_hash, _) = SMTreeHasher::digest_node(&left, &right);

        Debug::print(&crypto_hash);
        Debug::print(&expect);

        assert(crypto_hash == expect, 1108);
    }

    #[test]
    fun test_common_prefix_bits_len() {
        let bits1 = SMTProofUtils::path_bits_to_bool_vector_from_msb(&x"0000000000000000000000000000000000000000000000000000000000000000");
        let bits2 = SMTProofUtils::path_bits_to_bool_vector_from_msb(&x"1000000000000000000000000000000000000000000000000000000000000000");
        Debug::print(&bits1);
        Debug::print(&bits2);
        let len = SMTUtils::count_vector_common_prefix<bool>(&bits1, &bits2);
        Debug::print(&len);
        assert(len == 3, 1109);
    }

    #[test]
    public fun test_fixed_split_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let (leaf_node_path, leaf_node_value) = SMTreeHasher::parse_leaf(&data);
        //assert(prefix == x"00", 1110);

        Debug::print(&leaf_node_path);
        Debug::print(&x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01");
        assert(leaf_node_path == x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01", 1106);

        Debug::print(&leaf_node_value);
        Debug::print(&x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7");
        assert(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 1107);
    }

    public fun gen_proof_path_hash(tx_hash: &vector<u8>): vector<u8> {
        CrossChainSMTProofs::generate_leaf_path(TEST_CHAIN_ID, tx_hash)
    }

    #[test]
    public fun test_non_exiests_line_1() {
        let element_path = gen_proof_path_hash(&x"666f6f");
        let expect_root_hash = x"0000000000000000000000000000000000000000000000000000000000000000";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_2() {
        let element_path = gen_proof_path_hash(&x"746573744b6571");
        let expect_root_hash = x"86ceff92ad19b4454f03cf9d7eab04ea3fbeae5722db50ecd282ee627d9187f3";
        let leaf_data = x"00b218dd388cf26f40cc29d7f10df15c85b32b58554ff10d5bc749e744c17d8c682767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_3() {
        let element_path = gen_proof_path_hash(&x"746573744b657932");
        let expect_root_hash = x"0fb4ee35913fb9a3ee693a6690240163f9de66dc498b0e21acfdaa6314d1fec7";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_4() {
        let element_path = gen_proof_path_hash(&x"746573744b657933");
        let expect_root_hash = x"f454cefe2f7ece4f34eaa98e407bc0d194bf93f2f8bc43a1b545179502268333";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"1f43c0566fb5f61ac487b3e5f9b8e909b847711a2fc19f372d1dd6e80c31eb0e");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_5() {
        let element_path = gen_proof_path_hash(&x"746573744b657934");
        let expect_root_hash = x"e79eb517102e78f68b8b9a8d2585aef4a09e03c522f2b6a086c6341d324ca66f";
        let leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"3c34845e6a3188ce53258212b6034be91e3dc37d8026c394fc35be78da3bd978");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_6() {
        let element_path = gen_proof_path_hash(&x"746573744b657935");
        let expect_root_hash = x"0e3d08e9150f21294dccac6d896c62beb480752f07cbe774d3351d0fd4fcb82f";
        let leaf_data = x"006320474efd45e15d289a09129f5c44a149bbd7619390e4c05810a3c2c6ba92ca2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_7() {
        let element_path = gen_proof_path_hash(&x"746573744b657936");
        let expect_root_hash = x"c89574b1f7c772b744255434f15d392d0851c421bfb881b2c963d33255015ce6";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"fc11114b562f54c77db86daf8d5f70fca6f3d97f2212576719146f0a1409d89c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_8() {
        let element_path = gen_proof_path_hash(&x"746573744b657937");
        let expect_root_hash = x"f1716245c79ccfb351e4f17a6e5268b2cbf9ab8ee87fd6a143b58f83b1a2167e";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"5694f05dee02e0c173612f53530e4a87f0d7efce76287d72827bd4f0a3e76670");
        Vector::push_back(&mut siblings, x"1c7724175413f87bcdd400fee295fc446ef6123f3a0bc05b16a9bbc046a2525c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_9() {
        let element_path = gen_proof_path_hash(&x"746573744b657938");
        let expect_root_hash = x"20db0fe063bcbc8bd73e3a785ec3b274227f9e03ee4511c2cd759bf81b5a4f2f";
        let leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3");
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_10() {
        let element_path = gen_proof_path_hash(&x"746573744b657939");
        let expect_root_hash = x"e12e95cee66ba3866b02ac8da4fe70252954773bdc6a9ba9df479d848668e360";
        let leaf_data = x"00b218dd388cf26f40cc29d7f10df15c85b32b58554ff10d5bc749e744c17d8c682767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"9645e3888dbe5874f9c8e07bdd1e105808580984e14ae3e923cc4fb0816cacc1");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"cd853e8eddd33ea48f4c0cf47c53e6b7167415834c7bcd44c7a5a5e3cd56720a");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }


    fun test_non_exiests(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {
        let checked = SMTProofs::verify_non_membership_proof_by_leaf_path(
            expect_root_hash,
            leaf_data,
            siblings,
            element_path);
        assert(checked, 1112);
    }

    fun test_update_leaf(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {
        let new_root_hash = SMTProofs::compute_root_hash_new_leaf_included(
            element_path,
            &CrossChainSMTProofs::leaf_default_value_hash(),
            leaf_data,
            siblings);
        Debug::print(&new_root_hash);
        Debug::print(expect_root_hash);
        assert(new_root_hash == *expect_root_hash, 1113);
    }

    #[test]
    fun test_root_update_leaf_line_1() {
        let element_path = gen_proof_path_hash(&x"666f6f");
        let expect_root_hash = x"86ceff92ad19b4454f03cf9d7eab04ea3fbeae5722db50ecd282ee627d9187f3";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_2() {
        let element_path = gen_proof_path_hash(&x"746573744b6579");
        let expect_root_hash = x"0fb4ee35913fb9a3ee693a6690240163f9de66dc498b0e21acfdaa6314d1fec7";
        let leaf_data = x"00b218dd388cf26f40cc29d7f10df15c85b32b58554ff10d5bc749e744c17d8c682767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_3() {
        let element_path = gen_proof_path_hash(&x"746573744b657932");
        let expect_root_hash = x"f454cefe2f7ece4f34eaa98e407bc0d194bf93f2f8bc43a1b545179502268333";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_4() {
        let element_path = gen_proof_path_hash(&x"746573744b657933");
        let expect_root_hash = x"e79eb517102e78f68b8b9a8d2585aef4a09e03c522f2b6a086c6341d324ca66f";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"1f43c0566fb5f61ac487b3e5f9b8e909b847711a2fc19f372d1dd6e80c31eb0e");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_5() {
        let element_path = gen_proof_path_hash(&x"746573744b657934");
        let expect_root_hash = x"0e3d08e9150f21294dccac6d896c62beb480752f07cbe774d3351d0fd4fcb82f";
        let leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"3c34845e6a3188ce53258212b6034be91e3dc37d8026c394fc35be78da3bd978");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_6() {
        let element_path = gen_proof_path_hash(&x"746573744b657935");
        let expect_root_hash = x"c89574b1f7c772b744255434f15d392d0851c421bfb881b2c963d33255015ce6";
        let leaf_data = x"006320474efd45e15d289a09129f5c44a149bbd7619390e4c05810a3c2c6ba92ca2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_7() {
        let element_path = gen_proof_path_hash(&x"746573744b657936");
        let expect_root_hash = x"f1716245c79ccfb351e4f17a6e5268b2cbf9ab8ee87fd6a143b58f83b1a2167e";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"fc11114b562f54c77db86daf8d5f70fca6f3d97f2212576719146f0a1409d89c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_8() {
        let element_path = gen_proof_path_hash(&x"746573744b657937");
        let expect_root_hash = x"20db0fe063bcbc8bd73e3a785ec3b274227f9e03ee4511c2cd759bf81b5a4f2f";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"5694f05dee02e0c173612f53530e4a87f0d7efce76287d72827bd4f0a3e76670");
        Vector::push_back(&mut siblings, x"1c7724175413f87bcdd400fee295fc446ef6123f3a0bc05b16a9bbc046a2525c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_9() {
        let element_path = gen_proof_path_hash(&x"746573744b657938");
        let expect_root_hash = x"e12e95cee66ba3866b02ac8da4fe70252954773bdc6a9ba9df479d848668e360";
        let leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3");
        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_create_membership_proof_and_verify_line_9() {
        let tx_hash = x"746573744b657938";
        let key = CrossChainSMTProofs::generate_key(TEST_CHAIN_ID, &tx_hash);
        let leaf_path = gen_proof_path_hash(&tx_hash);
        assert(SMTreeHasher::digest(&key) == *&leaf_path, 1161);
        let leaf_value = CrossChainSMTProofs::leaf_default_value_hash();

        let non_membership_leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let side_nodes = Vector::empty<vector<u8>>();
        Vector::push_back(&mut side_nodes, x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3");
        Vector::push_back(&mut side_nodes, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut side_nodes, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut side_nodes, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");

        let non_membership_root_hash = x"20db0fe063bcbc8bd73e3a785ec3b274227f9e03ee4511c2cd759bf81b5a4f2f";
        // Verify non-membership proof
        let v_non_member = SMTProofs::verify_non_membership_proof_by_key(
            &non_membership_root_hash,
            &non_membership_leaf_data,
            &side_nodes,
            &key);
        assert(v_non_member, 1162);

        // Create membership proof from non-membership proof info.
        let expected_membership_root_hash = x"e12e95cee66ba3866b02ac8da4fe70252954773bdc6a9ba9df479d848668e360";
        //Debug::print<vector<u8>>(&expected_membership_root_hash);
        let (new_root_hash, new_side_nodes) = SMTProofs::create_membership_proof(&leaf_path, &leaf_value, &non_membership_leaf_data, &side_nodes);
        //Debug::print<vector<u8>>(&new_root_hash);
        assert(expected_membership_root_hash == *&new_root_hash, 1165);

        // Verify membership proof
        let v = SMTProofs::verify_membership_proof(&new_root_hash, &new_side_nodes, &leaf_path, &leaf_value);
        assert(v, 1166);
    }

}
}
address 0x2d81a0427d64ff61b11ede9085efa5ad {
module MerkleProofNonExistsTest {
    use 0x1::Vector;
    use 0x1::Debug;
    use 0x1::BitOperators;
    use 0x1::Hash;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofNonExists;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofElementBits;

    struct MerkleInternalNode has store, drop {
        left_child: vector<u8>,
        right_child: vector<u8>,
    }

    #[test]
    public fun test_iter_bits() {
        let hash = x"1000000000000000000000000000000000000000000000000000000000000000";
        Debug::print(&Hash::sha3_256(*&hash));

        let bit_vec = MerkleProofElementBits::iter_bits(&hash);
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
            Vector::push_back(&mut bit_hash, MerkleProofElementBits::get_bit(&origin_hash, i));
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

        let crypto_hash = MerkleProofNonExists::crypto_leaf_node_hash(&data);

        Debug::print(&crypto_hash);
        Debug::print(&expect);
        assert(crypto_hash == expect, 1107);
    }

    #[test]
    public fun test_fixed_internal_node_data() {
        let left = x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb";
        let right = x"42bfc776a76b35ca641ee761a5f4bc6ebf2d4e2441c517f8a8e085dec3ca443c";
        let expect = x"060aec78413605e993f9338255b661ac794a68729ffa50022aca72b01586a306";

        let crypto_hash = MerkleProofNonExists::crypto_internal_node_hash(&left, &right);

        Debug::print(&crypto_hash);
        Debug::print(&expect);

        assert(crypto_hash == expect, 1108);
    }

    #[test]
    fun test_common_prefix_bits_len() {
        let bits1 = MerkleProofElementBits::iter_bits(&x"0000000000000000000000000000000000000000000000000000000000000000");
        let bits2 = MerkleProofElementBits::iter_bits(&x"1000000000000000000000000000000000000000000000000000000000000000");
        Debug::print(&bits1);
        Debug::print(&bits2);
        let len = MerkleProofElementBits::common_prefix_bits_len<bool>(&bits1, &bits2);
        Debug::print(&len);
        assert(len == 3, 1109);
    }

    #[test]
    public fun test_fixed_split_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let (prefix, leaf_node_path, leaf_node_value) = MerkleProofNonExists::split_leaf_node_data(&data);
        assert(prefix == x"00", 1110);

        Debug::print(&leaf_node_path);
        Debug::print(&x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01");
        assert(leaf_node_path == x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01", 1106);

        Debug::print(&leaf_node_value);
        Debug::print(&x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7");
        assert(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 1107);
    }


    // 0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7
    #[test]
    public fun test_proof_not_exists_in_root() {
        let none_existing_key = x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01";
        let except_root_hash = x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let checked = MerkleProofNonExists::proof_not_exists_in_root(
            &except_root_hash,
            &none_existing_key,
            &leaf_data,
            &Vector::empty<vector<u8>>());
        assert(checked, 1111);
    }


    // 4
    // testKey3
    // c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278
    // 191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb
    // ["a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd","da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488"]
    // 00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7
    #[test]
    public fun test_proof_not_exists_in_root_line_4() {
        let none_existing_key = x"c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278";
        let except_root_hash = x"191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        let checked = MerkleProofNonExists::proof_not_exists_in_root(
            &except_root_hash,
            &none_existing_key,
            &leaf_data,
            &siblings);
        assert(checked, 1112);
    }

    #[test]
    fun test_root_update_leaf_line_3() {
        let element_key = x"b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c239";
        let except_root_hash = x"191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");

        let new_root_hash = MerkleProofNonExists::update_leaf(
            &element_key,
            &leaf_data,
            &siblings);
        Debug::print(&new_root_hash);
        Debug::print(&except_root_hash);
        assert(new_root_hash == except_root_hash, 1113);
    }

    #[test]
    fun test_root_update_leaf_line_4() {
        let element_key = x"c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278";
        let except_root_hash = x"7a379f33e0def9fe3555bc83b4f67f0b8ac23927352829603bff53c03fc58992";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");

        let new_root_hash = MerkleProofNonExists::update_leaf(
            &element_key,
            &leaf_data,
            &siblings);
        Debug::print(&new_root_hash);
        Debug::print(&except_root_hash);
        assert(new_root_hash == except_root_hash, 1114);
    }

    #[test]
    fun test_root_update_leaf_new_data_no_pass() {
        let element_key = x"8b4a296734b97f3c2028326c695f076e35de3183ada9d07cb7b9a32f1451d71f";
        let except_root_hash = x"755e48a4526b0c5b3f7e26d00da398ffec97dc784777e16132681aa208b16be3";
        let leaf_data = x"0080be6638e99f15d7942bd0130b9118125010293dcc2054fdbf26bf997d0173f42767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"6f9bb267d56d0feecdd121f682df52b22d366fa7652975bec3ddabe457207eab");

        let new_root_hash = MerkleProofNonExists::update_leaf(
            &element_key,
            &leaf_data,
            &siblings);
        Debug::print(&new_root_hash);
        Debug::print(&except_root_hash);
        assert(new_root_hash == except_root_hash, 1115);

    }


}
}
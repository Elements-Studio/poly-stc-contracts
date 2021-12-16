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
        assert(Vector::length<bool>(&bit_vec) == 256, 101);

        let sub_bits = Bytes::slice_range_with_template<bool>(&bit_vec, 252, 256);
        Debug::print(&sub_bits);
        assert(Vector::length<bool>(&sub_bits) == 4, 102);
    }

    #[test]
    public fun test_bit() {
        assert(BitOperators::and(1, 2) == 0, 101);
        assert(BitOperators::and(1, 3) == 1, 102);
        assert(BitOperators::and(1, 16 >> 4) == 1, 103);
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
        assert((first_byte >> 4 & 1) == 1, 101);

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
        assert(crypto_hash == expect, 101);
    }

    #[test]
    public fun test_fixed_internal_node_data() {
        let left = x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb";
        let right = x"42bfc776a76b35ca641ee761a5f4bc6ebf2d4e2441c517f8a8e085dec3ca443c";
        let expect = x"060aec78413605e993f9338255b661ac794a68729ffa50022aca72b01586a306";

        let crypto_hash = MerkleProofNonExists::crypto_internal_node_hash(&left, &right);

        Debug::print(&crypto_hash);
        Debug::print(&expect);

        assert(crypto_hash == expect, 101);
    }

    #[test]
    fun test_common_prefix_bits_len() {
        let bits1 = MerkleProofElementBits::iter_bits(&x"0000000000000000000000000000000000000000000000000000000000000000");
        let bits2 = MerkleProofElementBits::iter_bits(&x"1000000000000000000000000000000000000000000000000000000000000000");
        Debug::print(&bits1);
        Debug::print(&bits2);
        let len = MerkleProofElementBits::common_prefix_bits_len<bool>(&bits1, &bits2);
        Debug::print(&len);
        assert(len == 3, 101);
    }

    #[test]
    public fun test_fixed_split_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let (prefix, leaf_node_path, leaf_node_value) = MerkleProofNonExists::split_leaf_node_data(&data);
        assert(prefix == x"00", 101);

        Debug::print(&leaf_node_path);
        Debug::print(&x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01");
        assert(leaf_node_path == x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01", 102);

        Debug::print(&leaf_node_value);
        Debug::print(&x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7");
        assert(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 103);
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
        assert(checked, 101);
    }


    // 4
    // testKey3
    // c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278
    // 191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb
    // ["a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd","da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488"]
    // 00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7
    #[test]
    public fun test_proof_not_exists_in_root_key3() {
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
        assert(checked, 101);
    }

    #[test]
    fun test_root_update_leaf_check() {
        let except_root_hash = x"4c24d7b106c27a5282129191550489b32c5a2373b8d21e2cd7a4eb1f38e23f6c";
        let none_existing_key = x"1000000000000000000000000000000000000000000000000000000000000000";
        let new_root_hash = MerkleProofNonExists::update_leaf(
            &none_existing_key,
            &Vector::empty<u8>(),
            &Vector::empty<vector<u8>>());
        Debug::print(&new_root_hash);
        Debug::print(&except_root_hash);
        assert(new_root_hash == except_root_hash, 101);
    }

}
}
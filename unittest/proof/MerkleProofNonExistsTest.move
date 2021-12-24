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


    #[test]
    public fun test_non_exiests_line_1() {
        let element_path = x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01";
        let expect_root_hash = x"0000000000000000000000000000000000000000000000000000000000000000";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_2() {
        let element_path = x"c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e";
        let expect_root_hash = x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_3() {
        let element_path = x"b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c239";
        let expect_root_hash = x"68dd764c1b0f69306a8610256b3d7bb5dcf00520cbeee2993002b0766b17413f";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_4() {
        let element_path = x"c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278";
        let expect_root_hash = x"191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_5() {
        let element_path = x"ea8ff72f511e908fa5c76d90dda3f5b20637e997a7714dd5a478336318d7f18d";
        let expect_root_hash = x"7a379f33e0def9fe3555bc83b4f67f0b8ac23927352829603bff53c03fc58992";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"53940891fb47466448864d5661927480758e6a3ce4a9ae1c105373f6eb02bfe6");
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_6() {
        let element_path = x"d183cebd61efedfaed545752b77af6fd65b41129d087141e0e619399e9440efc";
        let expect_root_hash = x"e98464d82a851333cc1de74ca374ecc9698c6c53ed5b2320b2f9af1b7c1208a1";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"5bfdd2882daaca047a621d699ab1ddd2befc9d683719d38015acb5b5f12abf7e");
        Vector::push_back(&mut siblings, x"38317ab229040f451df13895fbd3efa3036c57755bf5ad90fdfd1f81dc6e8f45");
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_7() {
        let element_path = x"4c24d7b106c27a5282129191550489b32c5a2373b8d21e2cd7a4eb1f38e23f6c";
        let expect_root_hash = x"32af595a1da170d6c064d2f9a73a1f251e2fdab05b9583d76c62501420df092d";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"33c67dd97bedc86b5dcbc970f55a6041581e1e82139b58adeb4510f694a081ac");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_8() {
        let element_path = x"b57b3fd8b7aecf83fb19a54d1266e7a05a0b1b9ceb9c2269530764306bbe5ac2";
        let expect_root_hash = x"a35f4cf34198ad5c2390bca35d88ed5d7fc9a29c14d36e99d65422aad0aaa486";
        let leaf_data = x"00b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c2392767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"95332c0e4f0672298b04f47038cdbee4986b681da77e4c7d15bb84777d8ccad8");
        Vector::push_back(&mut siblings, x"c2c55004a423ddeb8a72b5b7d88fae70056f2d5c7f69eeb6807eb943e9128de2");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_9() {
        let element_path = x"ff36af91dcaa6e6a9761fe44f1ac12f40c89f499dca288936ea3bcbf85c42a81";
        let expect_root_hash = x"5e3f3bd883005e5038841debdb88f9fd40b81b3eda5ef37cc86e4580795a9aca";
        let leaf_data = x"00ea8ff72f511e908fa5c76d90dda3f5b20637e997a7714dd5a478336318d7f18d2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb");
        Vector::push_back(&mut siblings, x"0085b48186bf55552073c90452f3deee65ccb47455f0dbfd2df11eefa1dfa9c2");
        Vector::push_back(&mut siblings, x"c2c55004a423ddeb8a72b5b7d88fae70056f2d5c7f69eeb6807eb943e9128de2");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_10() {
        let element_path = x"4e0a39c4f2b86076bfcc46fcb2bbc363601f5c22d22ad479003267634ce528a5";
        let expect_root_hash = x"1a6aabce3ac1fed66a3d008b39f1a891f9d86f6df039bc02f4c6a948b765b06a";
        let leaf_data = x"004c24d7b106c27a5282129191550489b32c5a2373b8d21e2cd7a4eb1f38e23f6c2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut siblings, x"9970e108bb8608a5c9b8f796401d6b1264502abe710f45a14aae1978e8c75d38");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }


    fun test_non_exiests(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {
        let checked = MerkleProofNonExists::proof_not_exists_in_root(
            expect_root_hash,
            element_path,
            leaf_data,
            siblings);
        assert(checked, 1112);
    }

    fun test_update_leaf(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {
        let new_root_hash = MerkleProofNonExists::update_leaf(
            element_path,
            leaf_data,
            siblings);
        Debug::print(&new_root_hash);
        Debug::print(expect_root_hash);
        assert(new_root_hash == *expect_root_hash, 1113);
    }

    #[test]
    fun test_root_update_leaf_line_1() {
        let element_path = x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01";
        let expect_root_hash = x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_2() {
        let element_path = x"c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e";
        let expect_root_hash = x"68dd764c1b0f69306a8610256b3d7bb5dcf00520cbeee2993002b0766b17413f";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_3() {
        let element_path = x"b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c239";
        let expect_root_hash = x"191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_4() {
        let element_path = x"c6281edc54637499646ddbd7e93636f91b8d3bb6974d7191452983fa6a015278";
        let expect_root_hash = x"7a379f33e0def9fe3555bc83b4f67f0b8ac23927352829603bff53c03fc58992";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_5() {
        let element_path = x"ea8ff72f511e908fa5c76d90dda3f5b20637e997a7714dd5a478336318d7f18d";
        let expect_root_hash = x"e98464d82a851333cc1de74ca374ecc9698c6c53ed5b2320b2f9af1b7c1208a1";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"53940891fb47466448864d5661927480758e6a3ce4a9ae1c105373f6eb02bfe6");
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_6() {
        let element_path = x"d183cebd61efedfaed545752b77af6fd65b41129d087141e0e619399e9440efc";
        let expect_root_hash = x"32af595a1da170d6c064d2f9a73a1f251e2fdab05b9583d76c62501420df092d";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"5bfdd2882daaca047a621d699ab1ddd2befc9d683719d38015acb5b5f12abf7e");
        Vector::push_back(&mut siblings, x"38317ab229040f451df13895fbd3efa3036c57755bf5ad90fdfd1f81dc6e8f45");
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_7() {
        let element_path = x"4c24d7b106c27a5282129191550489b32c5a2373b8d21e2cd7a4eb1f38e23f6c";
        let expect_root_hash = x"a35f4cf34198ad5c2390bca35d88ed5d7fc9a29c14d36e99d65422aad0aaa486";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"33c67dd97bedc86b5dcbc970f55a6041581e1e82139b58adeb4510f694a081ac");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_8() {
        let element_path = x"b57b3fd8b7aecf83fb19a54d1266e7a05a0b1b9ceb9c2269530764306bbe5ac2";
        let expect_root_hash = x"5e3f3bd883005e5038841debdb88f9fd40b81b3eda5ef37cc86e4580795a9aca";
        let leaf_data = x"00b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c2392767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"95332c0e4f0672298b04f47038cdbee4986b681da77e4c7d15bb84777d8ccad8");
        Vector::push_back(&mut siblings, x"c2c55004a423ddeb8a72b5b7d88fae70056f2d5c7f69eeb6807eb943e9128de2");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_9() {
        let element_path = x"ff36af91dcaa6e6a9761fe44f1ac12f40c89f499dca288936ea3bcbf85c42a81";
        let expect_root_hash = x"1a6aabce3ac1fed66a3d008b39f1a891f9d86f6df039bc02f4c6a948b765b06a";
        let leaf_data = x"00ea8ff72f511e908fa5c76d90dda3f5b20637e997a7714dd5a478336318d7f18d2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb");
        Vector::push_back(&mut siblings, x"0085b48186bf55552073c90452f3deee65ccb47455f0dbfd2df11eefa1dfa9c2");
        Vector::push_back(&mut siblings, x"c2c55004a423ddeb8a72b5b7d88fae70056f2d5c7f69eeb6807eb943e9128de2");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
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
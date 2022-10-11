// Sparse Merkle Tree proof for non-membership,
// reference Starcoin project's source file located at: "commons/forkable-jellyfish-merkle/src/proof.rs"
//
// Computes the hash of internal node according to [`JellyfishTree`](crate::JellyfishTree)
// data structure in the logical view. `start` and `nibble_height` determine a subtree whose
// root hash we want to get. For an internal node with 16 children at the bottom level, we compute
// the root hash of it as if a full binary Merkle tree with 16 leaves as below:
//
// ```text
//   4 ->              +------ root hash ------+
//                     |                       |
//   3 ->        +---- # ----+           +---- # ----+
//               |           |           |           |
//   2 ->        #           #           #           #
//             /   \       /   \       /   \       /   \
//   1 ->     #     #     #     #     #     #     #     #
//           / \   / \   / \   / \   / \   / \   / \   / \
//   0 ->   0   1 2   3 4   5 6   7 8   9 A   B C   D E   F
//   ^
// height
// ```
//
// As illustrated above, at nibble height 0, `0..F` in hex denote 16 chidren hashes.  Each `#`
// means the hash of its two direct children, which will be used to generate the hash of its
// parent with the hash of its sibling. Finally, we can get the hash of this internal node.
//
// However, if an internal node doesn't have all 16 chidren exist at height 0 but just a few of
// them, we have a modified hashing rule on top of what is stated above:
// 1. From top to bottom, a node will be replaced by a leaf child if the subtree rooted at this
// node has only one child at height 0 and it is a leaf child.
// 2. From top to bottom, a node will be replaced by the placeholder node if the subtree rooted at
// this node doesn't have any child at height 0. For example, if an internal node has 3 leaf
// children at index 0, 3, 8, respectively, and 1 internal node at index C, then the computation
// graph will be like:
//
// ```text
//   4 ->              +------ root hash ------+
//                     |                       |
//   3 ->        +---- # ----+           +---- # ----+
//               |           |           |           |
//   2 ->        #           @           8           #
//             /   \                               /   \
//   1 ->     0     3                             #     @
//                                               / \
//   0 ->                                       C   @
//   ^
// height
// Note: @ denotes placeholder hash.
// ```
module Bridge::SMTProofs {

    use StarcoinFramework::Errors;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Debug;

    use Bridge::SMTUtils;
    use Bridge::SMTreeHasher;

    spec module {
        pragma verify = true;
    }

    const ERROR_KEY_ALREADY_EXISTS_IN_PROOF: u64 = 101;
    const ERROR_COUNT_COMMON_PREFIX: u64 = 102;
    const BIT_RIGHT: bool = true;

    public fun verify_non_membership_proof_by_key(root_hash: &vector<u8>,
                                                  non_membership_leaf_data: &vector<u8>,
                                                  side_nodes: &vector<vector<u8>>,
                                                  key: &vector<u8>): bool {
        let leaf_path = SMTreeHasher::digest(key);
        verify_non_membership_proof_by_leaf_path(root_hash, non_membership_leaf_data, side_nodes, &leaf_path)
    }

    // Verify non-membership proof by leaf path.
    // Return true if leaf path(key) is not in the tree.
    public fun verify_non_membership_proof_by_leaf_path(root_hash: &vector<u8>,
                                                        non_membership_leaf_data: &vector<u8>,
                                                        side_nodes: &vector<vector<u8>>,
                                                        leaf_path: &vector<u8>): bool {
        let non_membership_leaf_hash = if (Vector::length<u8>(non_membership_leaf_data) > 0) {
            let (non_membership_leaf_path, _) = SMTreeHasher::parse_leaf(non_membership_leaf_data);
            assert!(*leaf_path != *&non_membership_leaf_path, Errors::invalid_state(ERROR_KEY_ALREADY_EXISTS_IN_PROOF));
            assert!((SMTUtils::count_common_prefix(leaf_path, &non_membership_leaf_path) >= Vector::length(side_nodes)), ERROR_COUNT_COMMON_PREFIX);
            SMTreeHasher::digest_leaf_data(non_membership_leaf_data)
        } else {
            SMTreeHasher::placeholder()
        };
        compute_root_hash(leaf_path, &non_membership_leaf_hash, side_nodes) == *root_hash
    }

    public fun verify_membership_proof_by_key_value(root_hash: &vector<u8>,
                                                    side_nodes: &vector<vector<u8>>,
                                                    key: &vector<u8>,
                                                    value: &vector<u8>,
                                                    is_raw_value: bool): bool {
        let leaf_path = SMTreeHasher::digest(key);
        let leaf_value_hash = if (is_raw_value) {
            &SMTreeHasher::digest(value)
        } else {
            value
        };
        verify_membership_proof(root_hash, side_nodes, &leaf_path, leaf_value_hash)
    }

    public fun verify_membership_proof(root_hash: &vector<u8>,
                                       side_nodes: &vector<vector<u8>>,
                                       leaf_path: &vector<u8>,
                                       leaf_value_hash: &vector<u8>): bool {
        let (leaf_hash, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value_hash);
        compute_root_hash(leaf_path, &leaf_hash, side_nodes) == *root_hash
    }

    public fun compute_root_hash_by_leaf(leaf_path: &vector<u8>,
                                         leaf_value_hash: &vector<u8>,
                                         side_nodes: &vector<vector<u8>>): vector<u8> {
        let (leaf_hash, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value_hash);
        compute_root_hash(leaf_path, &leaf_hash, side_nodes)
    }

    // Compute root hash after a new leaf included.
    public fun compute_root_hash_new_leaf_included(leaf_path: &vector<u8>,
                                                   leaf_value_hash: &vector<u8>,
                                                   non_membership_leaf_data: &vector<u8>,
                                                   side_nodes: &vector<vector<u8>>): vector<u8> {
        let (new_side_nodes, leaf_node_hash) = create_membership_side_nodes(leaf_path, leaf_value_hash, non_membership_leaf_data, side_nodes);

        compute_root_hash(leaf_path, &leaf_node_hash, &new_side_nodes)
    }

    // Create membership proof from non-membership proof.
    // Return root hash, side nodes.
    public fun create_membership_proof(leaf_path: &vector<u8>,
                                       leaf_value_hash: &vector<u8>,
                                       non_membership_leaf_data: &vector<u8>,
                                       side_nodes: &vector<vector<u8>>): (vector<u8>, vector<vector<u8>>) {
        let (new_side_nodes, leaf_node_hash) = create_membership_side_nodes(leaf_path, leaf_value_hash, non_membership_leaf_data, side_nodes);
        let new_root_hash = compute_root_hash(leaf_path, &leaf_node_hash, &new_side_nodes);
        (new_root_hash, new_side_nodes)
    }

    // Create membership proof side nodes from non-membership proof.
    fun create_membership_side_nodes(leaf_path: &vector<u8>,
                                     leaf_value_hash: &vector<u8>,
                                     non_membership_leaf_data: &vector<u8>,
                                     side_nodes: &vector<vector<u8>>): (vector<vector<u8>>, vector<u8>) {
        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);
        let (new_leaf_hash, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value_hash);
        let new_side_nodes = if (Vector::length(non_membership_leaf_data) > 0) {
            let (non_membership_leaf_path, _) = SMTreeHasher::parse_leaf(non_membership_leaf_data);
            assert!(*leaf_path != *&non_membership_leaf_path, Errors::invalid_state(ERROR_KEY_ALREADY_EXISTS_IN_PROOF));

            let common_prefix_count = SMTUtils::count_common_prefix(leaf_path, &non_membership_leaf_path);
            let old_leaf_hash = SMTreeHasher::digest_leaf_data(non_membership_leaf_data);
            let new_side_nodes = Vector::empty<vector<u8>>();

            Vector::push_back(&mut new_side_nodes, old_leaf_hash);
            if (common_prefix_count > side_nodes_len) {
                let place_holder_len = (common_prefix_count - side_nodes_len);
                // Put placeholders
                let idx = 0;
                while ({
                    spec {
                        invariant idx <= place_holder_len;
                    };
                    idx < place_holder_len
                }) {
                    Vector::push_back(&mut new_side_nodes, SMTreeHasher::placeholder());
                    idx = idx + 1;
                };
            };
            new_side_nodes
        } else {
            Vector::empty<vector<u8>>()
        };

        // Push old siblings into the new siblings array
        let idx = 0;
        while ({
            spec {
                invariant idx <= len(side_nodes);
            };
            idx < side_nodes_len
        }) {
            Vector::push_back(&mut new_side_nodes, *Vector::borrow(side_nodes, idx));
            idx = idx + 1;
        };
        (new_side_nodes, new_leaf_hash)
    }

    spec create_membership_side_nodes {
        pragma verify;
    }

    // Compute root hash.
    // The parameter `node_hash` is leaf or internal node hash.
    fun compute_root_hash(path: &vector<u8>,
                          node_hash: &vector<u8>,
                          side_nodes: &vector<vector<u8>>): vector<u8> {

        Debug::print(side_nodes);
        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);

        spec {
            assume len(node_hash) == 256;
        };

        let i = 0;
        let current_hash = *node_hash;
        while ({
            spec {
                invariant i <= side_nodes_len;
                invariant len(current_hash) == 256;
            };
            i < side_nodes_len
        }) {
            let bit = SMTUtils::get_bit_at_from_msb(path, side_nodes_len - i - 1);
            let sibling_hash = Vector::borrow<vector<u8>>(side_nodes, i);
            if (bit == BIT_RIGHT) {
                (current_hash, _) = SMTreeHasher::digest_node(sibling_hash, &current_hash);
            } else { // left
                (current_hash, _) = SMTreeHasher::digest_node(&current_hash, sibling_hash);
            };
            i = i + 1;
        };
        current_hash
    }

    spec compute_root_hash {
        pragma verify;
        ensures len(result) == 256;
    }

    //    struct SparseMerkleInternalNode has store, drop {
    //        left_child: vector<u8>,
    //        right_child: vector<u8>,
    //    }

    //    struct SparseMerkleLeafNode has store, drop {
    //        key: vector<u8>,
    //    }

}

#[test_only]
module Bridge::SMTNonMembershipProofTest {
    use StarcoinFramework::Vector;
    use StarcoinFramework::Debug;
    use StarcoinFramework::BitOperators;
    use StarcoinFramework::Hash;

    use Bridge::Bytes;
    use Bridge::SMTProofs;
    use Bridge::SMTProofUtils;
    use Bridge::SMTUtils;
    use Bridge::SMTreeHasher;
    use Bridge::CrossChainSMTProofs;

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
        assert!(Vector::length<bool>(&bit_vec) == 256, 1101);

        let sub_bits = Bytes::slice_range_with_template<bool>(&bit_vec, 252, 256);
        Debug::print(&sub_bits);
        assert!(Vector::length<bool>(&sub_bits) == 4, 1102);
    }

    #[test]
    public fun test_bit() {
        assert!(BitOperators::and(1, 2) == 0, 1103);
        assert!(BitOperators::and(1, 3) == 1, 1104);
        assert!(BitOperators::and(1, 16 >> 4) == 1, 1105);
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
        assert!((first_byte >> 4 & 1) == 1, 1106);

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
        assert!(crypto_hash == expect, 1107);
    }

    #[test]
    public fun test_fixed_internal_node_data() {
        let left = x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb";
        let right = x"42bfc776a76b35ca641ee761a5f4bc6ebf2d4e2441c517f8a8e085dec3ca443c";
        let expect = x"060aec78413605e993f9338255b661ac794a68729ffa50022aca72b01586a306";

        let (crypto_hash, _) = SMTreeHasher::digest_node(&left, &right);

        Debug::print(&crypto_hash);
        Debug::print(&expect);

        assert!(crypto_hash == expect, 1108);
    }

    #[test]
    fun test_common_prefix_bits_len() {
        let bits1 = SMTProofUtils::path_bits_to_bool_vector_from_msb(&x"0000000000000000000000000000000000000000000000000000000000000000");
        let bits2 = SMTProofUtils::path_bits_to_bool_vector_from_msb(&x"1000000000000000000000000000000000000000000000000000000000000000");
        Debug::print(&bits1);
        Debug::print(&bits2);
        let len = SMTUtils::count_vector_common_prefix<bool>(&bits1, &bits2);
        Debug::print(&len);
        assert!(len == 3, 1109);
    }

    #[test]
    public fun test_fixed_split_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let (leaf_node_path, leaf_node_value) = SMTreeHasher::parse_leaf(&data);
        //assert!(prefix == x"00", 1110);

        Debug::print(&leaf_node_path);
        Debug::print(&x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01");
        assert!(leaf_node_path == x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01", 1106);

        Debug::print(&leaf_node_value);
        Debug::print(&x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7");
        assert!(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 1107);
    }

    public fun get_proof_leaf_path_by_cross_chain_tx_hash(tx_hash: &vector<u8>): vector<u8> {
        CrossChainSMTProofs::generate_leaf_path(TEST_CHAIN_ID, tx_hash)
    }

    #[test]
    public fun test_non_exiests_line_1() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"666f6f");
        let expect_root_hash = x"0000000000000000000000000000000000000000000000000000000000000000";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_2() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b6571");
        let expect_root_hash = x"86ceff92ad19b4454f03cf9d7eab04ea3fbeae5722db50ecd282ee627d9187f3";
        let leaf_data = x"00b218dd388cf26f40cc29d7f10df15c85b32b58554ff10d5bc749e744c17d8c682767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_3() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657932");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657933");
        let expect_root_hash = x"f454cefe2f7ece4f34eaa98e407bc0d194bf93f2f8bc43a1b545179502268333";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"1f43c0566fb5f61ac487b3e5f9b8e909b847711a2fc19f372d1dd6e80c31eb0e");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_5() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657934");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657935");
        let expect_root_hash = x"0e3d08e9150f21294dccac6d896c62beb480752f07cbe774d3351d0fd4fcb82f";
        let leaf_data = x"006320474efd45e15d289a09129f5c44a149bbd7619390e4c05810a3c2c6ba92ca2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_7() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657936");
        let expect_root_hash = x"c89574b1f7c772b744255434f15d392d0851c421bfb881b2c963d33255015ce6";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"fc11114b562f54c77db86daf8d5f70fca6f3d97f2212576719146f0a1409d89c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_non_exiests(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    public fun test_non_exiests_line_8() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657937");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657938");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657939");
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
        assert!(checked, 1112);
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
        assert!(new_root_hash == *expect_root_hash, 1113);
    }

    #[test]
    fun test_root_update_leaf_line_1() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"666f6f");
        let expect_root_hash = x"86ceff92ad19b4454f03cf9d7eab04ea3fbeae5722db50ecd282ee627d9187f3";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_2() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b6579");
        let expect_root_hash = x"0fb4ee35913fb9a3ee693a6690240163f9de66dc498b0e21acfdaa6314d1fec7";
        let leaf_data = x"00b218dd388cf26f40cc29d7f10df15c85b32b58554ff10d5bc749e744c17d8c682767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_3() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657932");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657933");
        let expect_root_hash = x"e79eb517102e78f68b8b9a8d2585aef4a09e03c522f2b6a086c6341d324ca66f";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"1f43c0566fb5f61ac487b3e5f9b8e909b847711a2fc19f372d1dd6e80c31eb0e");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_5() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657934");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657935");
        let expect_root_hash = x"c89574b1f7c772b744255434f15d392d0851c421bfb881b2c963d33255015ce6";
        let leaf_data = x"006320474efd45e15d289a09129f5c44a149bbd7619390e4c05810a3c2c6ba92ca2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_7() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657936");
        let expect_root_hash = x"f1716245c79ccfb351e4f17a6e5268b2cbf9ab8ee87fd6a143b58f83b1a2167e";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"fc11114b562f54c77db86daf8d5f70fca6f3d97f2212576719146f0a1409d89c");
        Vector::push_back(&mut siblings, x"36cc38e3a828b15aedc1908cfdb3746019d4c3c71006969f8ff4ef67470b801f");
        test_update_leaf(&element_path, &expect_root_hash, &leaf_data, &siblings);
    }

    #[test]
    fun test_root_update_leaf_line_8() {
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657937");
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
        let element_path = get_proof_leaf_path_by_cross_chain_tx_hash(&x"746573744b657938");
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
        let leaf_path = get_proof_leaf_path_by_cross_chain_tx_hash(&tx_hash);
        assert!(SMTreeHasher::digest(&key) == *&leaf_path, 1161);
        let leaf_value_hash = CrossChainSMTProofs::leaf_default_value_hash();

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
        assert!(v_non_member, 1162);

        // Create membership proof from non-membership proof info.
        let expected_membership_root_hash = x"e12e95cee66ba3866b02ac8da4fe70252954773bdc6a9ba9df479d848668e360";
        //Debug::print<vector<u8>>(&expected_membership_root_hash);
        let (new_root_hash, new_side_nodes) = SMTProofs::create_membership_proof(&leaf_path, &leaf_value_hash, &non_membership_leaf_data, &side_nodes);
        //Debug::print<vector<u8>>(&new_root_hash);
        assert!(expected_membership_root_hash == *&new_root_hash, 1165);

        // Verify membership proof
        let v = SMTProofs::verify_membership_proof(&new_root_hash, &new_side_nodes, &leaf_path, &leaf_value_hash);
        assert!(v, 1166);
    }

    fun test_compute_root_hash_by_leaf_line_9() {

        let leaf_data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let side_nodes = Vector::empty<vector<u8>>();
        Vector::push_back(&mut side_nodes, x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3");
        Vector::push_back(&mut side_nodes, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
        Vector::push_back(&mut side_nodes, x"0000000000000000000000000000000000000000000000000000000000000000");
        Vector::push_back(&mut side_nodes, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");
        let expected_root_hash = x"20db0fe063bcbc8bd73e3a785ec3b274227f9e03ee4511c2cd759bf81b5a4f2f";

        let (leaf_path, leaf_value_hash) = SMTreeHasher::parse_leaf(&leaf_data);
        let root_hash = SMTProofs::compute_root_hash_by_leaf(&leaf_path, &leaf_value_hash, &side_nodes);

        assert!(expected_root_hash == root_hash, 1167);
    }


    #[test]
    fun test_compute_root_hash_new_leaf_included_17() {
        let leaf_path = x"f9d7b13ae9d011a4b012e352beeed4233b398d52b917ebc1ef01221ff3cdcfe6";
        let leaf_value_hash = CrossChainSMTProofs::leaf_default_value_hash();
        let non_membership_leaf_data = x"00fc5211253bbe9d6e01ce802efe89a7f5521ef8a783d32d8a8affbeecefdfceac2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let side_nodes = Vector::empty<vector<u8>>();
        Vector::push_back(&mut side_nodes, x"aea4db371d829dc5fa56a30eedba283c80f38f4417a7e0f0213b3051328da981");
        Vector::push_back(&mut side_nodes, x"9cf2d9de2a06197afb781f44ff7ac9a63d5941e7fa69b3e11aed71aacd992a76");
        Vector::push_back(&mut side_nodes, x"7b6a156cc468301e48256c262bb9a0f6dbbcd0bfbe0fc60686c4f4ad13224216");
        let new_root_hash = SMTProofs::compute_root_hash_new_leaf_included(&leaf_path, &leaf_value_hash, &non_membership_leaf_data, &side_nodes);
        Debug::print<vector<u8>>(&new_root_hash);
        assert!(x"e7f7d1b12f99f3275fee521aaebdf1b1cc07dc7f97f111e84cf91a649ed0c3d2" == new_root_hash, 1171);
    }

}
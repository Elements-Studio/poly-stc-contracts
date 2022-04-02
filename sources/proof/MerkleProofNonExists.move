address Bridge {

/// Merkle proof for non exists,
/// reference Starcoin project which locate file named: "./commons/forkable-jellyfish-merkle/src/proof.rs"
///
/// Computes the hash of internal node according to [`JellyfishTree`](crate::JellyfishTree)
/// data structure in the logical view. `start` and `nibble_height` determine a subtree whose
/// root hash we want to get. For an internal node with 16 children at the bottom level, we compute
/// the root hash of it as if a full binary Merkle tree with 16 leaves as below:
///
/// ```text
///   4 ->              +------ root hash ------+
///                     |                       |
///   3 ->        +---- # ----+           +---- # ----+
///               |           |           |           |
///   2 ->        #           #           #           #
///             /   \       /   \       /   \       /   \
///   1 ->     #     #     #     #     #     #     #     #
///           / \   / \   / \   / \   / \   / \   / \   / \
///   0 ->   0   1 2   3 4   5 6   7 8   9 A   B C   D E   F
///   ^
/// height
/// ```
///
/// As illustrated above, at nibble height 0, `0..F` in hex denote 16 chidren hashes.  Each `#`
/// means the hash of its two direct children, which will be used to generate the hash of its
/// parent with the hash of its sibling. Finally, we can get the hash of this internal node.
///
/// However, if an internal node doesn't have all 16 chidren exist at height 0 but just a few of
/// them, we have a modified hashing rule on top of what is stated above:
/// 1. From top to bottom, a node will be replaced by a leaf child if the subtree rooted at this
/// node has only one child at height 0 and it is a leaf child.
/// 2. From top to bottom, a node will be replaced by the placeholder node if the subtree rooted at
/// this node doesn't have any child at height 0. For example, if an internal node has 3 leaf
/// children at index 0, 3, 8, respectively, and 1 internal node at index C, then the computation
/// graph will be like:
///
/// ```text
///   4 ->              +------ root hash ------+
///                     |                       |
///   3 ->        +---- # ----+           +---- # ----+
///               |           |           |           |
///   2 ->        #           @           8           #
///             /   \                               /   \
///   1 ->     0     3                             #     @
///                                               / \
///   0 ->                                       C   @
///   ^
/// height
/// Note: @ denotes placeholder hash.
/// ```
module MerkleProofNonExists {

    use StarcoinFramework::Errors;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Debug;

    use Bridge::Bytes;
    use Bridge::MerkleProofElementBits;
    #[test_only]
    use StarcoinFramework::BitOperators;
    #[test_only]
    use Bridge::MerkleProofHelper;




    const ERROR_ELEMENT_KEY_EXISTS_IN_PROOF: u64 = 101;
    const ERROR_LEFA_NODE_DATA_INVALID: u64 = 102;
    const ERROR_INTERNAL_NODE_DATA_INVALID: u64 = 103;

    /// vector u8 is SPARSE_MERKLE_PLACEHOLDER_HASH
    const SPARSE_MERKLE_PLACEHOLDER_HASH: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const SPARSE_MERKLE_LEAF_NODE_PREFIX: vector<u8> = x"00";
    const SPARSE_MERKLE_NODE_VALUE_HASH: vector<u8> = x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
    const SPARSE_MERKLE_INTERNAL_NODE_PREFIX: vector<u8> = x"01";

    /// Leaf node include: prefix + leaf_path + leaf_value hash
    const SPARSE_MERKLE_LEAF_DATA_LENGTH: u64 = 65;
    const SPARSE_MERKLE_INTER_NODE_LENGTH: u64 = 32;
    const SPARSE_MERKLE_LEAF_PATH_LENGTH: u64 = 32;


    struct SparseMerkleInternalNode has store, drop {
        left_child: vector<u8>,
        right_child: vector<u8>,
    }

    struct SparseMerkleLeafNode has store, drop {
        key: vector<u8>,
    }

    /// Verify an expect root hash from found proof informations
    public fun proof_not_exists_in_root(except_root_hash: &vector<u8>,
                                        element_key: &vector<u8>,
                                        proof_leaf: &vector<u8>,
                                        proof_siblings: &vector<vector<u8>>): bool {
        let current_hash = if (Vector::length<u8>(proof_leaf) > 0) {
            let (_, leaf_node_path, _) = split_leaf_node_data(proof_leaf);
            assert!(*element_key != leaf_node_path, Errors::invalid_state(ERROR_ELEMENT_KEY_EXISTS_IN_PROOF));
            crypto_leaf_node_hash(proof_leaf)
        } else {
            SPARSE_MERKLE_PLACEHOLDER_HASH
        };
        calculate_root_hash(element_key, &current_hash, proof_siblings) == *except_root_hash
    }

    /// Update leaf to the SMT for generate new root hash
    public fun update_leaf(element_path: &vector<u8>,
                           proof_leaf: &vector<u8>,
                           proof_siblings: &vector<vector<u8>>): vector<u8> {
        let proof_leaf_len = Vector::length(proof_leaf);
        let proof_siblings_len = Vector::length<vector<u8>>(proof_siblings);

        let (current_hash, new_siblings) = if (proof_leaf_len > 0) {
            let (_, leaf_node_path, _) = split_leaf_node_data(proof_leaf);
            assert!(*element_path != *&leaf_node_path, Errors::invalid_state(ERROR_ELEMENT_KEY_EXISTS_IN_PROOF));

            let new_leaf_path_bits = MerkleProofElementBits::iter_bits(element_path);
            let old_leaf_path_bits = MerkleProofElementBits::iter_bits(&leaf_node_path);
            let common_prefix_count =
                MerkleProofElementBits::common_prefix_bits_len<bool>(
                    &old_leaf_path_bits,
                    &new_leaf_path_bits);
            let old_leaf_hash = crypto_leaf_node_hash(proof_leaf);
            let new_leaf_hash = crypto_leaf_node_from_path(element_path);

            let current_hash = if (*Vector::borrow<bool>(&new_leaf_path_bits, common_prefix_count)) {
                crypto_internal_node_hash(&old_leaf_hash, &new_leaf_hash)
            } else {
                crypto_internal_node_hash(&new_leaf_hash, &old_leaf_hash)
            };

            let new_siblings = Vector::empty<vector<u8>>();
            if (common_prefix_count > proof_siblings_len) {
                let place_holder_len = (common_prefix_count - proof_siblings_len);

                // Put placeholder
                let idx = 0;
                while (idx < place_holder_len) {
                    Vector::push_back(&mut new_siblings, SPARSE_MERKLE_PLACEHOLDER_HASH);
                    idx = idx + 1;
                };
            };
            (current_hash, new_siblings)
        } else {
            (crypto_leaf_node_from_path(element_path), Vector::empty<vector<u8>>())
        };

        // Extend old siblings to new siblings array
        let idx = 0;
        while (idx < proof_siblings_len) {
            Vector::push_back(&mut new_siblings, *Vector::borrow(proof_siblings, idx));
            idx = idx + 1;
        };

        // Generate root hash
        calculate_root_hash(element_path, &current_hash, &new_siblings)
    }

    /// Calculate root hash from element key and siblings
    public fun calculate_root_hash(element_key: &vector<u8>,
                                   current_hash: &vector<u8>,
                                   siblings: &vector<vector<u8>>): vector<u8> {
        let sibling_len = Vector::length<vector<u8>>(siblings);

        // Transfer element key to bits
        let element_key_bits = MerkleProofElementBits::iter_bits(element_key);
        let element_key_bits_len = Vector::length<bool>(&element_key_bits);

        // Reverse all bits
        Vector::reverse(&mut element_key_bits);

        // Skip sibling length
        let skiped_element_key_bits = Bytes::slice_range_with_template<bool>(
            &element_key_bits,
            element_key_bits_len - sibling_len,
            element_key_bits_len);

        Debug::print(siblings);

        let i = 0;
        let result_hash = *current_hash;
        while (i < sibling_len) {
            let bit = *Vector::borrow<bool>(&skiped_element_key_bits, i);
            let sibling_hash = Vector::borrow<vector<u8>>(siblings, i);
            if (bit) { // right
                result_hash = crypto_internal_node_hash(sibling_hash, &result_hash);
            } else { // left
                result_hash = crypto_internal_node_hash(&result_hash, sibling_hash);
            };
            i = i + 1;
        };
        result_hash
    }

    /// Crypto a leaf node from path vector
    fun crypto_leaf_node_from_path(path: &vector<u8>) :vector<u8> {
        let new_leaf_data = Vector::empty<u8>();
        new_leaf_data = Bytes::concat(&new_leaf_data, SPARSE_MERKLE_LEAF_NODE_PREFIX);
        new_leaf_data = Bytes::concat(&new_leaf_data, *path);
        new_leaf_data = Bytes::concat(&new_leaf_data, SPARSE_MERKLE_NODE_VALUE_HASH);
        crypto_leaf_node_hash(&new_leaf_data)
    }

    /// Crypto hash encapsulation function for crypto leaf node
    public fun crypto_leaf_node_hash(data: &vector<u8>): vector<u8> {
        let leaf_data_len = Vector::length(data);
        assert!(leaf_data_len == SPARSE_MERKLE_LEAF_DATA_LENGTH, Errors::invalid_state(ERROR_LEFA_NODE_DATA_INVALID));
        Hash::sha3_256(*data)
    }

    /// Split node data from given data
    /// Return value:
    ///     prefix value
    ///     leaf node path hash
    ///     leaf node value hash
    public fun split_leaf_node_data(data: &vector<u8>): (vector<u8>, vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);

        assert!(data_len == SPARSE_MERKLE_LEAF_DATA_LENGTH, Errors::invalid_state(ERROR_LEFA_NODE_DATA_INVALID));
        let prefix_len = Vector::length(&SPARSE_MERKLE_LEAF_NODE_PREFIX);

        let start = 0;
        let end = prefix_len;
        let prefix = Bytes::slice(data, start, end);

        start = end;
        end = start + SPARSE_MERKLE_LEAF_PATH_LENGTH;
        let leaf_node_path = Bytes::slice(data, start, end);

        start = end;
        end = start + SPARSE_MERKLE_LEAF_PATH_LENGTH;
        let leaf_node_value = Bytes::slice(data, start, end);
        (prefix, leaf_node_path, leaf_node_value)
    }

    /// Crypto hash encapsulation function for internal node
    public fun crypto_internal_node_hash(left_child: &vector<u8>, right_child: &vector<u8>): vector<u8> {
        assert!(Vector::length(left_child) == SPARSE_MERKLE_INTER_NODE_LENGTH, Errors::invalid_state(ERROR_INTERNAL_NODE_DATA_INVALID));
        assert!(Vector::length(right_child) == SPARSE_MERKLE_INTER_NODE_LENGTH, Errors::invalid_state(ERROR_INTERNAL_NODE_DATA_INVALID));

        let result = SPARSE_MERKLE_INTERNAL_NODE_PREFIX;
        result = Bytes::concat(&result, *left_child);
        result = Bytes::concat(&result, *right_child);

        Hash::sha3_256(result)
    }

    public fun get_place_holder_hash(): vector<u8> {
        SPARSE_MERKLE_PLACEHOLDER_HASH
    }

    #[test]
    public fun test_iter_bits() {


        let hash = x"1000000000000000000000000000000000000000000000000000000000000000";
        Debug::print(&Hash::sha3_256(*&hash));

        let bit_vec = MerkleProofElementBits::iter_bits(&hash);
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

        let crypto_hash = crypto_leaf_node_hash(&data);

        Debug::print(&crypto_hash);
        Debug::print(&expect);
        assert!(crypto_hash == expect, 1107);
    }

    #[test]
    public fun test_fixed_internal_node_data() {
        
        let left = x"24a7e02bc5b39e8a4b7d2396d2e637632d0938944d16d571f0485168461f46eb";
        let right = x"42bfc776a76b35ca641ee761a5f4bc6ebf2d4e2441c517f8a8e085dec3ca443c";
        let expect = x"060aec78413605e993f9338255b661ac794a68729ffa50022aca72b01586a306";

        let crypto_hash = crypto_internal_node_hash(&left, &right);

        Debug::print(&crypto_hash);
        Debug::print(&expect);

        assert!(crypto_hash == expect, 1108);
    }

    #[test]
    fun test_common_prefix_bits_len() {


        let bits1 = MerkleProofElementBits::iter_bits(&x"0000000000000000000000000000000000000000000000000000000000000000");
        let bits2 = MerkleProofElementBits::iter_bits(&x"1000000000000000000000000000000000000000000000000000000000000000");
        Debug::print(&bits1);
        Debug::print(&bits2);
        let len = MerkleProofElementBits::common_prefix_bits_len<bool>(&bits1, &bits2);
        Debug::print(&len);
        assert!(len == 3, 1109);
    }

    #[test]
    public fun test_fixed_split_leaf_node_data() {
        let data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let (prefix, leaf_node_path, leaf_node_value) = split_leaf_node_data(&data);
        assert!(prefix == x"00", 1110);

        Debug::print(&leaf_node_path);
        Debug::print(&x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01");
        assert!(leaf_node_path == x"76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01", 1106);

        Debug::print(&leaf_node_value);
        Debug::print(&x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7");
        assert!(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 1107);
    }

    #[test_only]
    public fun gen_proof_path_hash(tx_hash: &vector<u8>): vector<u8> {

       MerkleProofHelper::gen_proof_path(218, tx_hash)
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


    #[test_only]
    fun test_non_exiests(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {
        let checked = proof_not_exists_in_root(
            expect_root_hash,
            element_path,
            leaf_data,
            siblings);
        assert!(checked, 1112);
    }

    #[test_only]
    fun test_update_leaf(element_path: &vector<u8>,
                         expect_root_hash: &vector<u8>,
                         leaf_data: &vector<u8>,
                         siblings: &vector<vector<u8>>) {

        let new_root_hash = update_leaf(
            element_path,
            leaf_data,
            siblings);
        Debug::print(&new_root_hash);
        Debug::print(expect_root_hash);
        assert!(new_root_hash == *expect_root_hash, 1113);
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
   

}
}
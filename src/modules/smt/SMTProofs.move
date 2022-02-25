address 0x18351d311d32201149a4df2a9fc2db8a {

/// Sparse Merkle Tree proof for non-membership,
/// reference Starcoin project's source file located at: "commons/forkable-jellyfish-merkle/src/proof.rs"
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
module SMTProofs {

    use 0x1::Errors;
    use 0x1::Vector;
    use 0x1::Debug;

    use 0x18351d311d32201149a4df2a9fc2db8a::SMTUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTProofUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTreeHasher;

    const ERROR_KEY_ALREADY_EXISTS_IN_PROOF: u64 = 101;

//    struct SparseMerkleInternalNode has store, drop {
//        left_child: vector<u8>,
//        right_child: vector<u8>,
//    }

    struct SparseMerkleLeafNode has store, drop {
        key: vector<u8>,
    }

    /// Verify non-membership proof by leaf path.
    /// Return true if verification passed.
    public fun verify_non_membership_proof_by_leaf_path(root_hash: &vector<u8>,
                                           non_membership_leaf_data: &vector<u8>,
                                           side_nodes: &vector<vector<u8>>,
                                           leaf_path: &vector<u8>): bool {
        let non_membership_leaf_hash = if (Vector::length<u8>(non_membership_leaf_data) > 0) {
            let (non_membership_leaf_path, _) = SMTreeHasher::parse_leaf(non_membership_leaf_data);
            assert(*leaf_path != non_membership_leaf_path, Errors::invalid_state(ERROR_KEY_ALREADY_EXISTS_IN_PROOF));
            SMTreeHasher::digest_leaf_data(non_membership_leaf_data)
        } else {
            SMTreeHasher::placeholder()
        };
        compute_root_hash(leaf_path, &non_membership_leaf_hash, side_nodes) == *root_hash
    }

    /// Compute root hash after a new leaf included.
    public fun compute_root_hash_new_leaf_included(leaf_path: &vector<u8>,
                           leaf_value: &vector<u8>,
                           non_membership_leaf_data: &vector<u8>,
                           side_nodes: &vector<vector<u8>>): vector<u8> {

        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);

        let (node_hash, new_side_nodes) = if (Vector::length(non_membership_leaf_data) > 0) {
            let (non_membership_leaf_path, _) = SMTreeHasher::parse_leaf(non_membership_leaf_data);
            assert(*leaf_path != *&non_membership_leaf_path, Errors::invalid_state(ERROR_KEY_ALREADY_EXISTS_IN_PROOF));

            let new_leaf_path_bits = SMTProofUtils::path_bits_to_bool_vector_from_msb(leaf_path);
            let old_leaf_path_bits = SMTProofUtils::path_bits_to_bool_vector_from_msb(&non_membership_leaf_path);
            let common_prefix_count = SMTUtils::count_vector_common_prefix<bool>(
                    &old_leaf_path_bits,
                    &new_leaf_path_bits);
            let old_leaf_hash = SMTreeHasher::digest_leaf_data(non_membership_leaf_data);
            let (new_leaf_hash, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value);

            let current_hash = if (*Vector::borrow<bool>(&new_leaf_path_bits, common_prefix_count)) {
                let (s, _) = SMTreeHasher::digest_node(&old_leaf_hash, &new_leaf_hash);
                s
            } else {
                let (s, _) = SMTreeHasher::digest_node(&new_leaf_hash, &old_leaf_hash);
                s
            };

            let new_side_nodes = Vector::empty<vector<u8>>();
            if (common_prefix_count > side_nodes_len) {
                let place_holder_len = (common_prefix_count - side_nodes_len);
                // Put placeholders
                let idx = 0;
                while (idx < place_holder_len) {
                    Vector::push_back(&mut new_side_nodes, SMTreeHasher::placeholder());
                    idx = idx + 1;
                };
            };
            (current_hash, new_side_nodes)
        } else {
            let (s, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value);
            (s, Vector::empty<vector<u8>>())
        };

        // Push old siblings into the new siblings array
        let idx = 0;
        while (idx < side_nodes_len) {
            Vector::push_back(&mut new_side_nodes, *Vector::borrow(side_nodes, idx));
            idx = idx + 1;
        };

        // Compute root hash
        compute_root_hash(leaf_path, &node_hash, &new_side_nodes)
    }

    /// Compute root hash.
    /// The parameter `node_hash` is leaf or internal node hash.
    fun compute_root_hash(leaf_path: &vector<u8>,
                          node_hash: &vector<u8>,
                          side_nodes: &vector<vector<u8>>): vector<u8> {

        Debug::print(side_nodes);
        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);
        let leaf_path_bits = SMTProofUtils::path_bits_to_bool_vector_from_msb(leaf_path);
        let leaf_path_bits_len = Vector::length<bool>(&leaf_path_bits);

        // Reverse all bits
        Vector::reverse(&mut leaf_path_bits);

        let side_node_leaf_path_bits = SMTUtils::sub_vector<bool>(
            &leaf_path_bits,
            leaf_path_bits_len - side_nodes_len,
            leaf_path_bits_len);

        let i = 0;
        let result_hash = *node_hash;
        while (i < side_nodes_len) {
            let bit = *Vector::borrow<bool>(&side_node_leaf_path_bits, i);
            let sibling_hash = Vector::borrow<vector<u8>>(side_nodes, i);
            if (bit) { // right
                (result_hash, _) = SMTreeHasher::digest_node(sibling_hash, &result_hash);
            } else { // left
                (result_hash, _) = SMTreeHasher::digest_node(&result_hash, sibling_hash);
            };
            i = i + 1;
        };
        result_hash
    }


}
}


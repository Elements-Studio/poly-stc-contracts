address 0x416b32009fe49fcab1d5f2ba0153838f {

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

    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTUtils;
    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTreeHasher;

    const ERROR_KEY_ALREADY_EXISTS_IN_PROOF: u64 = 101;
    const BIT_RIGHT: bool = true;

    public fun verify_non_membership_proof_by_key(root_hash: &vector<u8>,
                                                  non_membership_leaf_data: &vector<u8>,
                                                  side_nodes: &vector<vector<u8>>,
                                                  key: &vector<u8>): bool {
        let leaf_path = SMTreeHasher::digest(key);
        verify_non_membership_proof_by_leaf_path(root_hash, non_membership_leaf_data, side_nodes, &leaf_path)
    }

    /// Verify non-membership proof by leaf path.
    /// Return true if leaf path(key) is not in the tree.
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

    /// Compute root hash after a new leaf included.
    public fun compute_root_hash_new_leaf_included(leaf_path: &vector<u8>,
                                                   leaf_value_hash: &vector<u8>,
                                                   non_membership_leaf_data: &vector<u8>,
                                                   side_nodes: &vector<vector<u8>>): vector<u8> {
        let (new_side_nodes, leaf_node_hash) = create_membership_side_nodes(leaf_path, leaf_value_hash, non_membership_leaf_data, side_nodes);

        compute_root_hash(leaf_path, &leaf_node_hash, &new_side_nodes)
    }

    /// Create membership proof from non-membership proof.
    /// Return root hash, side nodes.
    public fun create_membership_proof(leaf_path: &vector<u8>,
                                       leaf_value_hash: &vector<u8>,
                                       non_membership_leaf_data: &vector<u8>,
                                       side_nodes: &vector<vector<u8>>): (vector<u8>, vector<vector<u8>>) {
        let (new_side_nodes, leaf_node_hash) = create_membership_side_nodes(leaf_path, leaf_value_hash, non_membership_leaf_data, side_nodes);
        let new_root_hash = compute_root_hash(leaf_path, &leaf_node_hash, &new_side_nodes);
        (new_root_hash, new_side_nodes)
    }

    /// Create membership proof side nodes from non-membership proof.
    fun create_membership_side_nodes(leaf_path: &vector<u8>,
                                     leaf_value_hash: &vector<u8>,
                                     non_membership_leaf_data: &vector<u8>,
                                     side_nodes: &vector<vector<u8>>): (vector<vector<u8>>, vector<u8>) {
        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);
        let (new_leaf_hash, _) = SMTreeHasher::digest_leaf(leaf_path, leaf_value_hash);
        let new_side_nodes = if (Vector::length(non_membership_leaf_data) > 0) {
            let (non_membership_leaf_path, _) = SMTreeHasher::parse_leaf(non_membership_leaf_data);
            assert(*leaf_path != *&non_membership_leaf_path, Errors::invalid_state(ERROR_KEY_ALREADY_EXISTS_IN_PROOF));

            let common_prefix_count = SMTUtils::count_common_prefix(leaf_path, &non_membership_leaf_path);
            let old_leaf_hash = SMTreeHasher::digest_leaf_data(non_membership_leaf_data);
            let new_side_nodes = Vector::empty<vector<u8>>();

            Vector::push_back(&mut new_side_nodes, old_leaf_hash);
            if (common_prefix_count > side_nodes_len) {
                let place_holder_len = (common_prefix_count - side_nodes_len);
                // Put placeholders
                let idx = 0;
                while (idx < place_holder_len) {
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
        while (idx < side_nodes_len) {
            Vector::push_back(&mut new_side_nodes, *Vector::borrow(side_nodes, idx));
            idx = idx + 1;
        };
        (new_side_nodes, new_leaf_hash)
    }

    /// Compute root hash.
    /// The parameter `node_hash` is leaf or internal node hash.
    fun compute_root_hash(path: &vector<u8>,
                          node_hash: &vector<u8>,
                          side_nodes: &vector<vector<u8>>): vector<u8> {

        Debug::print(side_nodes);
        let side_nodes_len = Vector::length<vector<u8>>(side_nodes);

        let i = 0;
        let current_hash = *node_hash;
        while (i < side_nodes_len) {
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

    //    struct SparseMerkleInternalNode has store, drop {
    //        left_child: vector<u8>,
    //        right_child: vector<u8>,
    //    }

    //    struct SparseMerkleLeafNode has store, drop {
    //        key: vector<u8>,
    //    }

}
}


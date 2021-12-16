address 0x2d81a0427d64ff61b11ede9085efa5ad {

/// Merkle proof for non exists,
/// reference Starcoin project which locate file named: "./commons/forkable-jellyfish-merkle/src/proof.rs"
///
module MerkleProofNonExists {

    use 0x1::Errors;
    use 0x1::Vector;
    use 0x1::Hash;
    //use 0x1::Debug;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofElementBits;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofStructuredHash;

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
            assert(*element_key != leaf_node_path, Errors::invalid_state(ERROR_ELEMENT_KEY_EXISTS_IN_PROOF));
            crypto_leaf_node_hash(proof_leaf)
        } else {
            SPARSE_MERKLE_PLACEHOLDER_HASH
        };
        calculate_root_hash(element_key, &current_hash, proof_siblings) == *except_root_hash
    }

    /// Update leaf to the SMT for generate new root hash
    public fun update_leaf(element_key: &vector<u8>,
                           proof_leaf: &vector<u8>,
                           proof_siblings: &vector<vector<u8>>): vector<u8> {
        let proof_leaf_len = Vector::length(proof_leaf);
        let proof_siblings_len = Vector::length<vector<u8>>(proof_siblings);

        let new_siblings = if (proof_leaf_len > 0) {
            let (_, leaf_node_path, _) = split_leaf_node_data(proof_leaf);
            assert(*element_key != *&leaf_node_path, Errors::invalid_state(ERROR_ELEMENT_KEY_EXISTS_IN_PROOF));

            // Handle leaf
            // Auto fill 0 to proof
            let this_leaf_path = MerkleProofStructuredHash::create_literal_hash(&leaf_node_path);

            // Find common prefix bits from two keys, and put place holer to `new_siblings`
            let new_siblings = Vector::empty<vector<u8>>();
            Vector::push_back(&mut new_siblings, Hash::sha3_256(*proof_leaf));
            let this_leaf_path_bits = MerkleProofElementBits::iter_bits(&this_leaf_path);
            let prefix_len = MerkleProofElementBits::common_prefix_bits_len<bool>(
                &this_leaf_path_bits,
                &MerkleProofElementBits::iter_bits(element_key));

            if (prefix_len > proof_siblings_len) {
                let place_holder_len = (prefix_len - proof_siblings_len) + 1;

                // Put placeholder
                let idx = 0;
                while (idx < place_holder_len) {
                    Vector::push_back(&mut new_siblings, SPARSE_MERKLE_PLACEHOLDER_HASH);
                    idx = idx + 1;
                };
            };
            new_siblings
        } else {
            Vector::empty<vector<u8>>()
        };

        let new_leaf_data = Vector::empty<u8>();
        new_leaf_data = Bytes::concat(&new_leaf_data, SPARSE_MERKLE_LEAF_NODE_PREFIX);
        new_leaf_data = Bytes::concat(&new_leaf_data, *element_key);
        new_leaf_data = Bytes::concat(&new_leaf_data, SPARSE_MERKLE_NODE_VALUE_HASH);

        let current_hash = crypto_leaf_node_hash(&new_leaf_data);

        // Extend old siblings
        let idx = 0;
        while (idx < proof_siblings_len) {
            Vector::push_back(&mut new_siblings, *Vector::borrow(proof_siblings, idx));
            idx = idx + 1;
        };

        // Generate root hash
        calculate_root_hash(element_key, &current_hash, &new_siblings)
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

        let i = 0;
        let result_hash = *current_hash;
        while (i < sibling_len) {
            //Debug::print(&111111111);

            let bit = *Vector::borrow<bool>(&skiped_element_key_bits, i);
            let sibling_hash = Vector::borrow<vector<u8>>(siblings, i);

            //Debug::print(sibling_hash);
            //Debug::print(&result_hash);

            if (bit) {
                result_hash = crypto_internal_node_hash(sibling_hash, &result_hash);
            } else {
                result_hash = crypto_internal_node_hash(&result_hash, sibling_hash);
            };
            //Debug::print(&result_hash);
            //Debug::print(&22222222);
            i = i + 1;
        };
        result_hash
    }

    /// Crypto hash encapsulation function for crypto leaf node
    public fun crypto_leaf_node_hash(data: &vector<u8>): vector<u8> {
        let leaf_data_len = Vector::length(data);
        assert(leaf_data_len == SPARSE_MERKLE_LEAF_DATA_LENGTH, Errors::invalid_state(ERROR_LEFA_NODE_DATA_INVALID));
        Hash::sha3_256(*data)
    }

    /// Split node data from given data
    /// Return value:
    ///     prefix value
    ///     leaf node path hash
    ///     leaf node value hash
    public fun split_leaf_node_data(data: &vector<u8>): (vector<u8>, vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);

        assert(data_len == SPARSE_MERKLE_LEAF_DATA_LENGTH, Errors::invalid_state(ERROR_LEFA_NODE_DATA_INVALID));
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
        //Debug::print(&11111111);

        assert(Vector::length(left_child) == SPARSE_MERKLE_INTER_NODE_LENGTH, Errors::invalid_state(ERROR_INTERNAL_NODE_DATA_INVALID));
        assert(Vector::length(right_child) == SPARSE_MERKLE_INTER_NODE_LENGTH, Errors::invalid_state(ERROR_INTERNAL_NODE_DATA_INVALID));
        let result = SPARSE_MERKLE_INTERNAL_NODE_PREFIX;
        result = Bytes::concat(&result, *left_child);
        result = Bytes::concat(&result, *right_child);
        //Debug::print(&result);
        //Debug::print(&11111111);

        Hash::sha3_256(result)
    }

    /// Get placeholder hash
    public fun get_place_holder_hash(): vector<u8> {
        SPARSE_MERKLE_PLACEHOLDER_HASH
    }
}
}
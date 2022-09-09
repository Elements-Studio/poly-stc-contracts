module Bridge::SMTreeHasher {

    use Bridge::SMTHash;
    use Bridge::SMTUtils;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Vector;

    // sparse merkle tree leaf(node) prefix.
    const LEAF_PREFIX: vector<u8> = x"00";
    // sparse merkle tree (internal)node prefix.
    const NODE_PREFIX: vector<u8> = x"01";

    // Leaf node data include: prefix + leaf_path + leaf_value_hash
    //const LEAF_DATA_LENGTH: u64 = 65;
    //const NODE_LEFT_RIGHT_DATA_LENGTH: u64 = 32;
    //const LEAF_PATH_LENGTH: u64 = 32;

    const ERROR_INVALID_LEAF_DATA: u64 = 102;
    const ERROR_INVALID_NODE_DATA: u64 = 103;
    const ERROR_INVALID_LEAF_DATA_LENGTH: u64 = 104;
    const ERROR_INVALID_NODE_DATA_LENGTH: u64 = 105;

    // Parse leaf data.
    // Return values:
    //     leaf node path.
    //     leaf node value.
    public fun parse_leaf(data: &vector<u8>): (vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);

        let prefix_len = Vector::length(&LEAF_PREFIX);
        assert!(data_len >= prefix_len + path_size(), Errors::invalid_argument(ERROR_INVALID_LEAF_DATA));
        assert!(SMTUtils::sub_u8_vector(data, 0, prefix_len) == LEAF_PREFIX, Errors::invalid_argument(ERROR_INVALID_LEAF_DATA));

        let start = 0;
        let end = prefix_len;
        _ = start;//let prefix = SMTUtils::sub_u8_vector(data, start, end);

        start = end;
        end = start + path_size();
        let leaf_node_path = SMTUtils::sub_u8_vector(data, start, end);

        start = end;
        end = Vector::length(data);
        let leaf_node_value = SMTUtils::sub_u8_vector(data, start, end);
        (leaf_node_path, leaf_node_value)
    }

    //    #[test]
    //    #[expected_failure]
    //    public fun test_parse_leaf_1() {
    //        let data = x"0189bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
    //        let (leaf_node_path, leaf_node_value) = parse_leaf(&data);
    //        assert!(leaf_node_path == x"89bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef81", 101);
    //        assert!(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 101);
    //    }
    //
    //    #[test]
    //    public fun test_parse_leaf_2() {
    //        let data = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
    //        let (leaf_node_path, leaf_node_value) = parse_leaf(&data);
    //        assert!(leaf_node_path == x"89bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef81", 101);
    //        assert!(leaf_node_value == x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7", 101);
    //    }

    public fun parse_node(data: &vector<u8>): (vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);
        let prefix_len = Vector::length(&NODE_PREFIX);
        assert!(data_len == prefix_len + path_size() * 2, Errors::invalid_argument(ERROR_INVALID_NODE_DATA));
        assert!(SMTUtils::sub_u8_vector(data, 0, prefix_len) == NODE_PREFIX, Errors::invalid_argument(ERROR_INVALID_NODE_DATA));

        let start = 0;
        let end = prefix_len;
        _ = start;//let prefix = SMTUtils::sub_u8_vector(data, start, end);

        start = end;
        end = start + path_size();
        let left_data = SMTUtils::sub_u8_vector(data, start, end);

        start = end;
        end = Vector::length(data);
        let right_data = SMTUtils::sub_u8_vector(data, start, end);
        (left_data, right_data)
    }

    public fun digest_leaf(path: &vector<u8>, leaf_value: &vector<u8>): (vector<u8>, vector<u8>) {
        let value = LEAF_PREFIX;
        value = SMTUtils::concat_u8_vectors(&value, *path);
        value = SMTUtils::concat_u8_vectors(&value, *leaf_value);
        (SMTHash::hash(&value), value)
    }

    public fun create_leaf_data(path: &vector<u8>, leaf_value: &vector<u8>): vector<u8> {
        let value = LEAF_PREFIX;
        value = SMTUtils::concat_u8_vectors(&value, *path);
        value = SMTUtils::concat_u8_vectors(&value, *leaf_value);
        value
    }

    // Digest leaf data. The parameter `data` includes leaf key and value.
    public fun digest_leaf_data(data: &vector<u8>): vector<u8> {
        let data_len = Vector::length(data);
        let prefix_len = Vector::length(&LEAF_PREFIX);
        assert!(data_len >= prefix_len + path_size(), Errors::invalid_state(ERROR_INVALID_LEAF_DATA_LENGTH));
        assert!(SMTUtils::sub_u8_vector(data, 0, prefix_len) == LEAF_PREFIX, Errors::invalid_argument(ERROR_INVALID_LEAF_DATA));
        SMTHash::hash(data)
    }

    public fun digest_node(left_data: &vector<u8>, right_data: &vector<u8>): (vector<u8>, vector<u8>) {
        let node_left_right_data_length = SMTHash::size();
        assert!(Vector::length(left_data) == node_left_right_data_length, Errors::invalid_state(ERROR_INVALID_NODE_DATA_LENGTH));
        assert!(Vector::length(right_data) == node_left_right_data_length, Errors::invalid_state(ERROR_INVALID_NODE_DATA_LENGTH));

        let value = NODE_PREFIX;
        value = SMTUtils::concat_u8_vectors(&value, *left_data);
        value = SMTUtils::concat_u8_vectors(&value, *right_data);
        (SMTHash::hash(&value), value)
    }

    public fun path(key: &vector<u8>): vector<u8> {
        digest(key)
    }

    public fun digest(data: &vector<u8>): vector<u8> {
        SMTHash::hash(data)
    }

    public fun path_size(): u64 {
        SMTHash::size()
    }

    public fun path_size_in_bits(): u64 {
        SMTHash::size() * 8
    }

    public fun placeholder(): vector<u8> {
        SMTHash::size_zero_bytes()
    }
}
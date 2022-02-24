address 0x18351d311d32201149a4df2a9fc2db8a {
module TreeHasher {

    use 0x1::Vector;
    use 0x1::Errors;
    use 0x18351d311d32201149a4df2a9fc2db8a::Hasher;

    const ERROR_INVALID_LEAF_DATA: u64 = 102;
    const ERROR_INVALID_NODE_DATA: u64 = 103;

    /// sparse merkle tree leaf(node) prefix.
    const LEAF_PREFIX: vector<u8> = x"00";
    /// sparse merkle tree (internal)node prefix.
    const NODE_PREFIX: vector<u8> = x"01";

    /// Parse leaf data.
    /// Return values:
    ///     leaf node path.
    ///     leaf node value.
    public fun parse_leaf(data: &vector<u8>): (vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);

        let prefix_len = Vector::length(&LEAF_PREFIX);
        assert(data_len >= prefix_len + path_size(), Errors::invalid_argument(ERROR_INVALID_LEAF_DATA));

        let start = 0;
        let end = prefix_len;
        //let prefix = sub_u8_vector(data, start, end);

        start = end;
        end = start + path_size();
        let leaf_node_path = sub_u8_vector(data, start, end);

        start = end;
        end = Vector::length(data);
        let leaf_node_value = sub_u8_vector(data, start, end);
        (leaf_node_path, leaf_node_value)
    }

    public fun parse_node(data: &vector<u8>): (vector<u8>, vector<u8>) {
        let data_len = Vector::length(data);

        let prefix_len = Vector::length(&LEAF_PREFIX);
        assert(data_len == prefix_len + path_size()*2, Errors::invalid_argument(ERROR_INVALID_NODE_DATA));

        let start = 0;
        let end = prefix_len;
        //let prefix = sub_u8_vector(data, start, end);

        start = end;
        end = start + path_size();
        let left_data = sub_u8_vector(data, start, end);

        start = end;
        end = Vector::length(data);
        let right_data = sub_u8_vector(data, start, end);
        (left_data, right_data)
    }

    public fun digest_leaf(path: &vector<u8>, leaf_data: &vector<u8>): (vector<u8>, vector<u8>) {
        let value = LEAF_PREFIX;
        value = concat_u8_vectors(&value, *path);
        value = concat_u8_vectors(&value, *leaf_data);
        (Hasher::sum(&value), value)
    }

    public fun digest_node(left_data: &vector<u8>, right_data: &vector<u8>): (vector<u8>, vector<u8>) {
        let value = NODE_PREFIX;
        value = concat_u8_vectors(&value, *left_data);
        value = concat_u8_vectors(&value, *right_data);
        (Hasher::sum(&value), value)
    }

    public fun path(key: &vector<u8>): vector<u8> {
        digest(key)
    }

    public fun digest(data: &vector<u8>): vector<u8> {
        Hasher::sum(data)
    }

    public fun path_size(): u64 {
        Hasher::size()
    }

    fun concat_u8_vectors(v1: &vector<u8>, v2: vector<u8>): vector<u8> {
        let data = *v1;
        Vector::append(&mut data, v2);
        data
    }

    fun sub_u8_vector(data: &vector<u8>, start: u64, end: u64): vector<u8> {
        let i = start;
        let result = Vector::empty<u8>();
        let data_len = Vector::length(data);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end) {
            Vector::push_back(&mut result, *Vector::borrow(data, i));
            i = i + 1;
        };
        result
    }
}
}
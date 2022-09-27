module Bridge::SMTProofUtils {

    use StarcoinFramework::Vector;
    use StarcoinFramework::Errors;
    use Bridge::SMTUtils;
    use Bridge::SMTreeHasher;
    use Bridge::SMTHash;

    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict = true;
    }
    
    const ERROR_INVALID_PATH_BYTES_LENGTH: u64 = 101;
    const ERROR_INVALID_PATH_BITS_LENGTH: u64 = 102;
    const ERROR_INVALID_NODES_DATA_PACKAGE_LENGTH: u64 = 103;
    //const NODE_DATA_LENGTH: u64 = 32;


    public fun path_bits_to_bool_vector_from_msb(path: &vector<u8>): vector<bool> {
        let path_len = Vector::length<u8>(path);
        assert!(path_len == SMTreeHasher::path_size(), Errors::invalid_argument(ERROR_INVALID_PATH_BYTES_LENGTH));
        let result_vec = SMTUtils::bits_to_bool_vector_from_msb(path);
        assert!(Vector::length<bool>(&result_vec) == SMTreeHasher::path_size_in_bits(), Errors::invalid_state(ERROR_INVALID_PATH_BITS_LENGTH));
        result_vec
    }

    spec path_bits_to_bool_vector_from_msb {
        pragma aborts_if_is_partial;
        aborts_if len(path) != SMTreeHasher::path_size();
        ensures len(result) == SMTreeHasher::path_size_in_bits();
    }

    // Split sibling nodes data from concatenated data.
    // Due `Move` API call not yet support the parameter type such as vector<vector<u8>>,
    // so we concat all vectors into one vector<u8>.
    public fun split_side_nodes_data(side_nodes_data: &vector<u8>): vector<vector<u8>> {
        let node_data_length = SMTHash::size();
        let len = Vector::length(side_nodes_data);
        assert!(len % node_data_length == 0, Errors::invalid_state(ERROR_INVALID_NODES_DATA_PACKAGE_LENGTH));

        if (len > 0) {
            let result = Vector::empty<vector<u8>>();
            let size = len / node_data_length;
            let idx = 0;
            while ({
                spec {
                    invariant idx <= len(side_nodes_data) / SMTHash::size();
                };
                idx < size
            }) {
                let start = idx * node_data_length;
                let end = start + node_data_length;
                Vector::push_back(&mut result, SMTUtils::sub_u8_vector(side_nodes_data, start, end));
                idx = idx + 1;
            };
            result
        } else {
            Vector::empty<vector<u8>>()
        }
    }

    spec split_side_nodes_data {
        aborts_if len(side_nodes_data) % SMTHash::size() != 0;
    }
}
address 0x18351d311d32201149a4df2a9fc2db8a {

module SMTProofUtils {

    use 0x1::Vector;
    use 0x1::Errors;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTreeHasher;

    const ERROR_INVALID_PATH_BYTES_LENGTH: u64 = 101;
    const ERROR_INVALID_PATH_BITS_LENGTH: u64 = 102;


    public fun path_bits_to_bool_vector_from_msb(path: &vector<u8>): vector<bool> {
        let path_len = Vector::length<u8>(path);
        assert(path_len == SMTreeHasher::path_size(), Errors::invalid_argument(ERROR_INVALID_PATH_BYTES_LENGTH));
        let result_vec = SMTUtils::bits_to_bool_vector_from_msb(path);
        assert(Vector::length<bool>(&result_vec) == SMTreeHasher::path_size_in_bits(), Errors::invalid_state(ERROR_INVALID_PATH_BITS_LENGTH));
        result_vec
    }

}
}
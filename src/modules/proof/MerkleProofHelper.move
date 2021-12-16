address 0x2d81a0427d64ff61b11ede9085efa5ad {
module MerkleProofHelper {

    use 0x1::Vector;
    use 0x1::Errors;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;

    const ERROR_SIBLING_PACKAGE_LENGTH_INVALID: u64 = 101;

    const SIBLING_LENGTH: u64 = 64;

    /// Extract siblings from packed siblings serialize data
    /// Due `Move` API call not support the parameter type such as vector<vector<u8>>
    /// so we compact all array element into one vector<u8>
    public fun extract_sibling(sibling_serial: &vector<u8>): vector<vector<u8>> {
        let len = Vector::length(sibling_serial);
        assert(len % SIBLING_LENGTH == 0, Errors::invalid_state(ERROR_SIBLING_PACKAGE_LENGTH_INVALID));

        if (len > 0) {
            let result = Vector::empty<vector<u8>>();
            let size = len / SIBLING_LENGTH;
            let idx = 0;
            while (idx < size) {
                let start = idx * SIBLING_LENGTH;
                let end = start + SIBLING_LENGTH;
                Vector::push_back(&mut result, Bytes::slice(sibling_serial, start, end));
                idx = idx + 1;
            };
            result
        } else {
            Vector::empty<vector<u8>>()
        }
    }
}
}
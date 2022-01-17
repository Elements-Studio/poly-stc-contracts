address NamedAddr {
module MerkleProofHelper {

    use StarcoinFramework::Vector;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Hash;
    use NamedAddr::Bytes;
    use NamedAddr::ZeroCopySink;

    const ERROR_SIBLING_PACKAGE_LENGTH_INVALID: u64 = 101;

    const SIBLING_LENGTH: u64 = 32;

    /// Extract siblings from packed siblings serialize data
    /// Due `Move` API call not support the parameter type such as vector<vector<u8>>
    /// so we compact all array element into one vector<u8>
    public fun extract_sibling(sibling_serial: &vector<u8>): vector<vector<u8>> {
        let len = Vector::length(sibling_serial);

        assert!(len % SIBLING_LENGTH == 0, Errors::invalid_state(ERROR_SIBLING_PACKAGE_LENGTH_INVALID));

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

    /// Generate proof path hash from chain id and transaction hash
    public fun gen_proof_path(chain_id: u64, tx_hash: &vector<u8>): vector<u8> {
        let buff = Vector::empty<u8>();
        buff = Bytes::concat(&buff, ZeroCopySink::write_u64(chain_id));
        buff = Bytes::concat(&buff, ZeroCopySink::write_var_bytes(tx_hash));
        Hash::sha3_256(buff)
    }

    #[test] use StarcoinFramework::Debug;

    #[test] public fun test_extract_sibling() {
        let data = x"df0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788ddf0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788ddf0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788d";
        let results = extract_sibling(&data);
        let len = Vector::length<vector<u8>>(&results);
        Debug::print(&len);
        assert!(len == 3, 1101);

        let data1 = x"6f9bb267d56d0feecdd121f682df52b22d366fa7652975bec3ddabe457207eab";
        let results1 = extract_sibling(&data1);
        let len1 = Vector::length<vector<u8>>(&results1);
        Debug::print(&len1);
        assert!(len1 == 1, 1102);

        let data2 = x"";
        let results2 = extract_sibling(&data2);
        let len2 = Vector::length<vector<u8>>(&results2);
        Debug::print(&len2);
        assert!(len2 == 0, 1103);
    }
}
}
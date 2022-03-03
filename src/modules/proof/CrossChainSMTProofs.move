address 0x18351d311d32201149a4df2a9fc2db8a {
module CrossChainSMTProofs {
    use 0x1::Vector;
    use 0x1::Hash;
    use 0x18351d311d32201149a4df2a9fc2db8a::SMTUtils;
    use 0x18351d311d32201149a4df2a9fc2db8a::ZeroCopySink;


    const LEAF_DEFAULT_VALUE_HASH: vector<u8> = x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";

    public fun leaf_default_value_hash(): vector<u8> {
       LEAF_DEFAULT_VALUE_HASH
    }

    /// Generate leaf path from chain id and transaction hash
    public fun generate_leaf_path(chain_id: u64, tx_hash: &vector<u8>): vector<u8> {
        let buff = Vector::empty<u8>();
        buff = SMTUtils::concat_u8_vectors(&buff, ZeroCopySink::write_u64(chain_id));
        buff = SMTUtils::concat_u8_vectors(&buff, ZeroCopySink::write_var_bytes(tx_hash));
        Hash::sha3_256(buff)
    }

    //    public fun diget_leaf_with_default_value_hash(path: &vector<u8>): vector<u8> {
    //        let (s, _) = SMTreeHasher::digest_leaf(path, &SPARSE_MERKLE_TREE_LEAF_DEFAULT_VALUE_HASH);
    //        s
    //    }

    //    #[test] use 0x1::Debug;
    //
    //    #[test] public fun test_split_nodes_data() {
    //        let data = x"df0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788ddf0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788ddf0254bd96f7bc830a65bf798dafc527f1a118cdfbe0c6453d4c689bbc9b788d";
    //        let results = split_side_nodes_data(&data);
    //        let len = Vector::length<vector<u8>>(&results);
    //        Debug::print(&len);
    //        assert(len == 3, 1101);
    //
    //        let data1 = x"6f9bb267d56d0feecdd121f682df52b22d366fa7652975bec3ddabe457207eab";
    //        let results1 = split_side_nodes_data(&data1);
    //        let len1 = Vector::length<vector<u8>>(&results1);
    //        Debug::print(&len1);
    //        assert(len1 == 1, 1102);
    //
    //        let data2 = x"";
    //        let results2 = split_side_nodes_data(&data2);
    //        let len2 = Vector::length<vector<u8>>(&results2);
    //        Debug::print(&len2);
    //        assert(len2 == 0, 1103);
    //    }

}
}

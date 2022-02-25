address 0x18351d311d32201149a4df2a9fc2db8a {
module CrossChainSMTProofs {

    const LEAF_DEFAULT_VALUE_HASH: vector<u8> = x"2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";

    public fun leaf_default_value_hash(): vector<u8> {
       LEAF_DEFAULT_VALUE_HASH
    }

//    public fun diget_leaf_with_default_value_hash(path: &vector<u8>): vector<u8> {
//        let (s, _) = TreeHasher::digest_leaf(path, &SPARSE_MERKLE_TREE_LEAF_DEFAULT_VALUE_HASH);
//        s
//    }

}
}

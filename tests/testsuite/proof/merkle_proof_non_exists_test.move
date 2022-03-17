//! account: alice, 800000000000000 0x1::STC::STC

//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::Vector;
    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTProofs;

    fun test_root_hash_check() {
        let root_hash = x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488";
        let none_existing_key = x"c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e";
        let leaf_data = x"0076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c012767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        assert(SMTProofs::verify_non_membership_proof_by_leaf_path(&root_hash, &leaf_data, &Vector::empty<vector<u8>>(), &none_existing_key), 1001);
    }
}
// check: EXECUTED


//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::Vector;
    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTProofs;

    fun test_root_hash_check() {
        let element_key = x"b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c239";
        let root_hash = x"68dd764c1b0f69306a8610256b3d7bb5dcf00520cbeee2993002b0766b17413f";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");

        assert(SMTProofs::verify_non_membership_proof_by_leaf_path(&root_hash, &leaf_data, &siblings, &element_key), 1002);
    }
}
// check: EXECUTED


//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::Vector;
    use 0x1::Debug;

    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTProofs;
    use 0x416b32009fe49fcab1d5f2ba0153838f::CrossChainSMTProofs;


    fun test_root_update_leaf_check() {
        // Update to leaf
        let element_key = x"b736de0143487e6d2f87a525edb9ef795a9db5be7b031979726a197af1e4c239";
        let expect_root_hash = x"191b6b150df0f6c3b38190d2b9c4979e0b23c15da1d56045e49a5fd37e8b68eb";
        let leaf_data = x"00c0359bc303b37a066ce3a91aa14628accb3eb5dd6ed2c49c93f7bc60d29c797e2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");

        let new_root_hash = SMTProofs::compute_root_hash_new_leaf_included(&element_key,
            &CrossChainSMTProofs::leaf_default_value_hash(),
            &leaf_data,
            &siblings);
        Debug::print(&expect_root_hash);
        Debug::print(&new_root_hash);
        assert(*&new_root_hash == expect_root_hash, 1003);
    }
}
// check: EXECUTED

//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::Vector;
    use 0x1::Debug;

    use 0x416b32009fe49fcab1d5f2ba0153838f::SMTProofs;

    /// index=5 txn="Test key 4",
    fun test_root_update_leaf_check() {
        // Update to leaf
        let element_key = x"ea8ff72f511e908fa5c76d90dda3f5b20637e997a7714dd5a478336318d7f18d";
        let expect_root_hash = x"e98464d82a851333cc1de74ca374ecc9698c6c53ed5b2320b2f9af1b7c1208a1";
        let leaf_data = x"";
        let siblings = Vector::empty<vector<u8>>();
        Vector::push_back(&mut siblings, x"53940891fb47466448864d5661927480758e6a3ce4a9ae1c105373f6eb02bfe6");
        Vector::push_back(&mut siblings, x"a18880b51b4475f45c663c66e9baff5bfdf01f9e552c9cfd84cfeb2494ea0bbd");
        Vector::push_back(&mut siblings, x"da3c17cfd8be129f09b61272f8afcf42bf5b77cf7e405f5aa20c30684a205488");

        let new_root_hash = SMTProofs::compute_root_hash_new_leaf_included(&element_key,
            &CrossChainSMTProofs::leaf_default_value_hash(),
            &leaf_data,
            &siblings);
        Debug::print(&expect_root_hash);
        Debug::print(&new_root_hash);
        assert(*&new_root_hash == expect_root_hash, 1004);
    }
}
// check: EXECUTED

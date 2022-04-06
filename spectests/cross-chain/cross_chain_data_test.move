//# init -n test --public-keys Bridge=0x57e74d84273e190d80e736c0fd82e0f6a00fb3f93ff2a8a95d1f3ad480da36ce

//# faucet --addr bob --amount 10000000000000000

//# faucet --addr Bridge --amount 10000000000000000


//# run --signers Bridge
script {
    use Bridge::CrossChainData;
    use StarcoinFramework::Vector;
    fun test_initialize_chain_placeholder(signer: signer) {
        CrossChainData::init_genesis(&signer);
        
        let root_hash = x"0000000000000000000000000000000000000000000000000000000000000000";
        let tx_hash = x"61341c16ec50ec4b2c364ee3dfc3ccdb5af540eba38c89160de75afd3322052d";
        let proof_leaf = Vector::empty<u8>();
        let proof_siblings = Vector::empty<vector<u8>>();
        let checked =
            CrossChainData::check_chain_tx_not_exists(
                &tx_hash,
                &root_hash,
                &proof_leaf,
                &proof_siblings);
        assert!(checked, 1001);
    }
}

// check: EXECUTED

//# run --signers Bridge
script {
    use Bridge::CrossChainGlobal;
    use Bridge::TokenMock;
    


    fun test_cross_chain_id_storage(signer: signer) {

        CrossChainGlobal::set_chain_id<TokenMock::Starcoin>(&signer, 1);
        assert!(CrossChainGlobal::chain_id_match<TokenMock::Starcoin>(1), 1001);

        CrossChainGlobal::set_chain_id<TokenMock::Ethereum>(&signer, 2);
        assert!(CrossChainGlobal::chain_id_match<TokenMock::Ethereum>(2), 1002);

        CrossChainGlobal::set_chain_id<TokenMock::Bitcoin>(&signer, 3);
        assert!(CrossChainGlobal::chain_id_match<TokenMock::Bitcoin>(3), 1003);

        CrossChainGlobal::set_asset_hash<TokenMock::TokenA>(&signer, &b"10000001");
        assert!(CrossChainGlobal::asset_hash_match<TokenMock::TokenA>(&b"10000001"), 1004);
    }
}
// check: EXECUTED
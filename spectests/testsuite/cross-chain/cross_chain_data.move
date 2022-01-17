//! account: admin, NamedAddr, 10000000000 StarcoinFramework::STC::STC
//! account: bob, 0x49156896A605F092ba1862C50a9036c9, 10000000000 StarcoinFramework::STC::STC

//! new-transaction
//! sender: admin
address admin = {{admin}};
module admin::CrossChainType {
    struct TokenA has copy, drop, store {}

    struct TokenB has copy, drop, store {}

    struct TokenC has copy, drop, store {}

    struct Starcoin has key, store {}

    struct Ethereum has key, store {}

    struct Bitcoin has key, store {}
}

//! new-transaction
//! sender: admin
address admin = {{admin}};
script {
    use StarcoinFramework::Vector;
    use NamedAddr::CrossChainData;

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

//! new-transaction
//! sender: admin
address admin = {{admin}};
script {
    use NamedAddr::CrossChainGlobal;
    use admin::CrossChainType;

    fun test_cross_chain_id_storage(signer: signer) {
        CrossChainGlobal::set_chain_id<CrossChainType::Starcoin>(&signer, 1);
        assert!(CrossChainGlobal::chain_id_match<CrossChainType::Starcoin>(1), 1001);

        CrossChainGlobal::set_chain_id<CrossChainType::Ethereum>(&signer, 2);
        assert!(CrossChainGlobal::chain_id_match<CrossChainType::Ethereum>(2), 1002);

        CrossChainGlobal::set_chain_id<CrossChainType::Bitcoin>(&signer, 3);
        assert!(CrossChainGlobal::chain_id_match<CrossChainType::Bitcoin>(3), 1003);

        CrossChainGlobal::set_asset_hash<CrossChainType::TokenA>(&signer, &b"10000001");
        assert!(CrossChainGlobal::asset_hash_match<CrossChainType::TokenA>(&b"10000001"), 1004);
    }
}
// check: EXECUTED
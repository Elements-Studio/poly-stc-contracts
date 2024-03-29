//# init -n test --public-keys Bridge=0x8085e172ecf785692da465ba3339da46c4b43640c3f92a45db803690cc3c4a36

//# faucet --addr Bridge --amount 10000000000

//# faucet --addr bob --amount 10000000000000000

//# publish
module Bridge::CrossChainType {
    struct TokenA has copy, drop, store {}

    struct TokenB has copy, drop, store {}

    struct TokenC has copy, drop, store {}

    struct Starcoin has key, store {}

    struct Ethereum has key, store {}

    struct Bitcoin has key, store {}
}

//# run --signers Bridge
script {
    use StarcoinFramework::Vector;
    use Bridge::CrossChainData;

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
    use Bridge::CrossChainType;

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
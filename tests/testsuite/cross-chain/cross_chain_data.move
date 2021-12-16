//! account: admin, 0x2d81a0427d64ff61b11ede9085efa5ad, 10000000000 0x1::STC::STC
//! account: bob, 0x49156896A605F092ba1862C50a9036c9, 10000000000 0x1::STC::STC

//! new-transaction
//! sender: admin
address admin = {{admin}};
module admin::MockTokenType {
    struct TokenA has copy, drop, store {}

    struct TokenB has copy, drop, store {}

    struct TokenC has copy, drop, store {}
}

//! new-transaction
//! sender: admin
address admin = {{admin}};
script {
    use 0x1::Vector;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainData;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainType;

    fun test_initialize_chain_placeholder(signer: signer) {
        CrossChainData::init_genesis(&signer);
        CrossChainData::init_txn_exists_proof<CrossChainType::Starcoin>(&signer);

        let root_hash = x"0000000000000000000000000000000000000000000000000000000000000000";
        let tx_hash = x"61341c16ec50ec4b2c364ee3dfc3ccdb5af540eba38c89160de75afd3322052d";
        let proof_leaf = Vector::empty<u8>();
        let proof_siblings = Vector::empty<vector<u8>>();
        let checked =
            CrossChainData::check_chain_tx_not_exists<CrossChainType::Starcoin>(
                &tx_hash,
                &root_hash,
                &proof_leaf,
                &proof_siblings);
        assert(checked, 1001);
    }
}
// check: EXECUTED

//! new-transaction
//! sender: admin
address admin = {{admin}};
script {
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use admin::MockTokenType::{TokenA, TokenB, TokenC};

    fun test_cross_chain_id_storage(signer: signer) {
        CrossChainGlobal::set_chain_id<TokenA>(&signer, 1);
        assert(CrossChainGlobal::chain_id_match<TokenA>(1), 1001);

        CrossChainGlobal::set_chain_id<TokenB>(&signer, 2);
        assert(CrossChainGlobal::chain_id_match<TokenB>(2), 1002);

        CrossChainGlobal::set_chain_id<TokenC>(&signer, 3);
        assert(CrossChainGlobal::chain_id_match<TokenC>(3), 1003);
    }
}
// check: EXECUTED
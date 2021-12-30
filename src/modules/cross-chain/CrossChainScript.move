address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainScript {

    use 0x1::STC;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainData;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainRouter;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

    const CHAINID_STARCOIN: u64 = 218;
    const CHAINID_ETHEREUM: u64 = 2;

    /// Initialize genesis from contract owner
    public(script) fun init_genesis(signer: signer,
                                    raw_header: vector<u8>,
                                    pub_key_list: vector<u8>) {
        // Init CCD
        CrossChainData::init_genesis(&signer);

        // Init CCM
        CrossChainManager::init_genesis_block(&signer, &raw_header, &pub_key_list);

        // Init asset proxy asset
        LockProxy::init_event(&signer);

        // Starcoin
        CrossChainRouter::bind_asset_and_proxy<STC::STC, CrossChainGlobal::STARCOIN_CHAIN>(
            &signer,
            CHAINID_STARCOIN,
            &b"0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainScript",
            &b"0x1::STC::STC");
    }


    // Lock operation from user call
    public(script) fun lock<TokenType: store, ChainType: store>(signer: signer, to_address: vector<u8>, amount: u128) {
        let (
            chain_id,
            proxy_hash,
            fun_name,
            tx_data,
            event,
            execution_cap
        ) = LockProxy::lock<TokenType, ChainType>(&signer, &to_address, amount);

        // Do crosschain option from cross chain manager
        CrossChainManager::cross_chain(&signer, chain_id, &proxy_hash, &fun_name, &tx_data, execution_cap);

        // Publish lock event
        LockProxy::publish_lock_event(event);
    }

    /// Check book keeper information
    public(script) fun changeBookKeeper(signer: signer,
                                        raw_header: vector<u8>,
                                        pub_key_list: vector<u8>,
                                        sig_list: vector<u8>) {
        CrossChainManager::change_book_keeper(&signer, &raw_header, &pub_key_list, &sig_list);
    }

    /// Verify header and execute transaction
    public(script) fun verifyHeaderAndExecuteTx(proof: vector<u8>,
                                                raw_header: vector<u8>,
                                                header_proof: vector<u8>,
                                                cur_raw_header: vector<u8>,
                                                header_sig: vector<u8>,
                                                merkle_proof_root: vector<u8>,
                                                merkle_proof_leaf: vector<u8>,
                                                merkle_proof_siblings: vector<u8>) {
        CrossChainRouter::verify_header_and_execute_tx(
            &proof, &raw_header, &header_proof, &cur_raw_header, &header_sig, &merkle_proof_root, &merkle_proof_leaf, &merkle_proof_siblings);
    }

    /// Get Current Epoch Start Height of Poly chain block
    public fun getCurEpochStartHeight(): u64 {
        CrossChainData::get_cur_epoch_start_height()
    }

    /// Get Consensus book Keepers Public Key Bytes
    public fun getCurEpochConPubKeyBytes(): vector<u8> {
        CrossChainData::get_cur_epoch_con_pubkey_bytes()
    }
}
}
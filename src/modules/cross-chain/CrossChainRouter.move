address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainRouter {

    use 0x1::STC;
    use 0x1::Errors;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::XUSDT;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::XETH;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofHelper;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

    const ERROR_NO_SUPPORT_UNLOCK_ASSET_TYPE: u64 = 101;
    const ERROR_NO_SUPPORT_UNLOCK_CHAIN_TYPE: u64 = 102;
    const ERROR_NO_SUPPORT_UNLOCK_OPTION: u64 = 103;

    /// Verify header and execute transaction
    public fun verify_header_and_execute_tx(proof: &vector<u8>,
                                            raw_header: &vector<u8>,
                                            header_proof: &vector<u8>,
                                            cur_raw_header: &vector<u8>,
                                            header_sig: &vector<u8>,
                                            merkle_proof_root: &vector<u8>,
                                            merkle_proof_leaf: &vector<u8>,
                                            input_merkle_proof_siblings: &vector<u8>) {
        let merkle_proof_siblings = MerkleProofHelper::extract_sibling(input_merkle_proof_siblings);

        // Verify header and parse method and args from proof vector
        let (
            method,
            args,
            chain_id,
            cap,
            cross_chain_tx_hash,
        ) = CrossChainManager::verify_header(
            proof,
            raw_header,
            header_proof,
            cur_raw_header,
            header_sig);

        CrossChainManager::check_and_mark_transaction_exists(
            chain_id,
            &cross_chain_tx_hash,
            merkle_proof_root,
            merkle_proof_leaf,
            &merkle_proof_siblings,
            &mut cap);

        if (*&method == b"unlock") {
            let (to_asset_hash, to_address, amount) = LockProxy::deserialize_tx_args(args);

            let ret = if (CrossChainGlobal::asset_hash_match<STC::STC>(&to_asset_hash)) {
                do_unlock<STC::STC>(
                    chain_id,
                    &to_asset_hash,
                    &to_address,
                    amount,
                    &cross_chain_tx_hash,
                    &cap)
            } else if (CrossChainGlobal::asset_hash_match<XUSDT::XUSDT>(&to_asset_hash)) {
                do_unlock<XUSDT::XUSDT>(
                    chain_id,
                    &to_asset_hash,
                    &to_address,
                    amount,
                    &cross_chain_tx_hash,
                    &cap)
            } else if (CrossChainGlobal::asset_hash_match<XETH::XETH>(&to_asset_hash)) {
                do_unlock<XETH::XETH>(
                    chain_id,
                    &to_asset_hash,
                    &to_address,
                    amount,
                    &cross_chain_tx_hash,
                    &cap)
            } else {
                false
            };
            assert(ret, Errors::invalid_state(ERROR_NO_SUPPORT_UNLOCK_ASSET_TYPE));
        };
        CrossChainManager::undefine_execution(cap);
    }

    /// Do unlock operation on inner calling
    public fun do_unlock<TokenT: store>(chain_id: u64,
                                        to_asset_hash: &vector<u8>,
                                        to_address: &vector<u8>,
                                        amount: u128,
                                        tx_hash: &vector<u8>,
                                        cap: &CrossChainGlobal::ExecutionCapability): bool {
        let unlock_event = LockProxy::unlock<TokenT>(
            to_asset_hash,
            to_address,
            amount,
            tx_hash,
            cap);

        let ret = if (CrossChainGlobal::chain_id_match<CrossChainGlobal::STARCOIN_CHAIN>(chain_id)) {
            LockProxy::emit_unlock_event<TokenT, CrossChainGlobal::STARCOIN_CHAIN>(unlock_event)
        } else if (CrossChainGlobal::chain_id_match<CrossChainGlobal::ETHEREUM_CHAIN>(chain_id)) {
            LockProxy::emit_unlock_event<TokenT, CrossChainGlobal::ETHEREUM_CHAIN>(unlock_event)
        } else {
            false
        };
        assert(ret, Errors::invalid_state(ERROR_NO_SUPPORT_UNLOCK_CHAIN_TYPE));
        true
    }

    /// Bind a new token type and chain type  proxy and asset to contract
    public fun bind_asset_and_proxy<TokenType: store, ChainType: store>(signer: &signer,
                                                                        chain_id: u64,
                                                                        proxy_hash: &vector<u8>,
                                                                        asset_hash: &vector<u8>) {
        CrossChainGlobal::set_chain_id<ChainType>(signer, chain_id);
        LockProxy::bind_asset_and_proxy<TokenType, ChainType>(signer, chain_id, proxy_hash, asset_hash);
    }
}
}
address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainRouter {

    use 0x1::STC;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::XUSDT;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::XETH;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofHelper;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainData;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

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


        if (*&method == b"unlock") {
            check_exists_and_execute_unlock<STC::STC, CrossChainGlobal::STARCOIN_CHAIN>(
                chain_id, &args, &cross_chain_tx_hash, merkle_proof_root, merkle_proof_leaf, &merkle_proof_siblings, &mut cap) ||
            check_exists_and_execute_unlock<XUSDT::XUSDT, CrossChainGlobal::ETHEREUM_CHAIN>(
                chain_id, &args, &cross_chain_tx_hash, merkle_proof_root, merkle_proof_leaf, &merkle_proof_siblings, &mut cap) ||
            check_exists_and_execute_unlock<XETH::XETH, CrossChainGlobal::ETHEREUM_CHAIN>(
                chain_id, &args, &cross_chain_tx_hash, merkle_proof_root, merkle_proof_leaf, &merkle_proof_siblings, &mut cap);
        };

        CrossChainManager::undefine_execution(cap);
    }

    /// Check transaction is exists in the root hash
    fun check_exists_and_execute_unlock<TokenType: store, ChainType: store>(chain_id: u64,
                                                                            args: &vector<u8>,
                                                                            tx_hash: &vector<u8>,
                                                                            merkle_proof_root: &vector<u8>,
                                                                            merkle_proof_leaf: &vector<u8>,
                                                                            merkle_proof_siblings: &vector<vector<u8>>,
                                                                            cap: &mut CrossChainGlobal::ExecutionCapability): bool {
        if (CrossChainGlobal::chain_id_match<ChainType>(chain_id)) {
            CrossChainManager::check_and_mark_transaction_exists<ChainType>(
                chain_id, tx_hash, merkle_proof_root, merkle_proof_leaf, merkle_proof_siblings, cap);
            LockProxy::unlock<TokenType, ChainType>(args, tx_hash, chain_id, cap);
            true
        } else {
            false
        }
    }

    /// Bind a new token type and chain type  proxy and asset to contract
    public fun bind_asset_and_proxy<TokenType: store, ChainType: store>(signer: &signer,
                                                                        chain_id: u64,
                                                                        proxy_hash: &vector<u8>,
                                                                        asset_hash: &vector<u8>) {
        CrossChainGlobal::set_chain_id<ChainType>(signer, chain_id);
        CrossChainData::init_txn_exists_proof<ChainType>(signer);
        LockProxy::bind_asset_and_proxy<TokenType, ChainType>(signer, chain_id, proxy_hash, asset_hash);
    }
}
}
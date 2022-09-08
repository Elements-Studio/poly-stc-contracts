module Bridge::CrossChainRouter {

    use StarcoinFramework::STC;
    use StarcoinFramework::Errors;

    use Bridge::XUSDT;
    use Bridge::XETH;
    use Bridge::SMTProofUtils;
    use Bridge::CrossChainManager;
    use Bridge::CrossChainGlobal;
    use Bridge::LockProxy;
    use Bridge::CrossChainProcessCombinator;

    const ERROR_NO_SUPPORT_UNLOCK_ASSET_TYPE: u64 = 101;
    const ERROR_NO_SUPPORT_UNLOCK_CHAIN_TYPE: u64 = 102;
    const ERROR_NO_SUPPORT_UNLOCK_OPTION: u64 = 103;
    const ERROR_NO_SUPPORT_LOCK_ASSET_TYPE: u64 = 104;
    const ERROR_NO_SUPPORT_LOCK_CHAIN_TYPE: u64 = 105;
    const ERROR_NO_SUPPORT_BIND_ASSET_TYPE: u64 = 106;
    const ERROR_NO_SUPPORT_BIND_CHAIN_TYPE: u64 = 107;
    const ERROR_NO_SUPPORT_METHOD: u64 = 108;
    //const ERROR_NO_TOO_MUCH_FEE: u64 = 108;

    // This function is meant to be invoked by the user,
    // a certin amount teokens will be locked in the proxy contract the invoker/msg.sender immediately.
    // Then the same amount of tokens will be unloked from target chain proxy contract at the target chain with chainId later.
    public fun lock(signer: &signer,
                    from_asset_hash: &vector<u8>,
                    to_chain_id: u64,
                    to_address: &vector<u8>,
                    amount: u128) {
        if (CrossChainGlobal::asset_hash_match<STC::STC>(from_asset_hash)) {
            inner_do_lock<STC::STC>(signer, to_chain_id, to_address, amount);
        } else if (CrossChainGlobal::asset_hash_match<XUSDT::XUSDT>(from_asset_hash)) {
            inner_do_lock<XUSDT::XUSDT>(signer, to_chain_id, to_address, amount);
        } else if (CrossChainGlobal::asset_hash_match<XETH::XETH>(from_asset_hash)) {
            inner_do_lock<XETH::XETH>(signer, to_chain_id, to_address, amount);
        } else {
            assert!(false, Errors::invalid_state(ERROR_NO_SUPPORT_BIND_ASSET_TYPE));
        }
    }

    public fun lock_with_stc_fee(signer: &signer,
                                 from_asset_hash: &vector<u8>,
                                 to_chain_id: u64,
                                 to_address: &vector<u8>,
                                 amount: u128,
                                 fee: u128,
                                 id: u128) {
        if (CrossChainGlobal::asset_hash_match<STC::STC>(from_asset_hash)) {
            inner_do_lock<STC::STC>(signer, to_chain_id, to_address, amount);
            LockProxy::lock_stc_fee<STC::STC>(signer, to_chain_id, to_address, amount, fee, id);
        } else if (CrossChainGlobal::asset_hash_match<XUSDT::XUSDT>(from_asset_hash)) {
            inner_do_lock<XUSDT::XUSDT>(signer, to_chain_id, to_address, amount);
            LockProxy::lock_stc_fee<XUSDT::XUSDT>(signer, to_chain_id, to_address, amount, fee, id);
        } else if (CrossChainGlobal::asset_hash_match<XETH::XETH>(from_asset_hash)) {
            inner_do_lock<XETH::XETH>(signer, to_chain_id, to_address, amount);
            LockProxy::lock_stc_fee<XETH::XETH>(signer, to_chain_id, to_address, amount, fee, id);
        } else {
            assert!(false, Errors::invalid_state(ERROR_NO_SUPPORT_BIND_ASSET_TYPE));
        }
    }

    // Do lock operation on inner calling
    public fun inner_do_lock<TokenT: store>(signer: &signer,
                                            to_chain_id: u64,
                                            to_address: &vector<u8>,
                                            amount: u128) {
        if (CrossChainGlobal::chain_id_match<CrossChainGlobal::STARCOIN_CHAIN>(to_chain_id)) {
            let (lock_parameters, event) =
                LockProxy::lock_with_param_pack<TokenT, CrossChainGlobal::STARCOIN_CHAIN>(signer, to_chain_id, to_address, amount);
            // Do crosschain option from cross chain manager
            CrossChainManager::cross_chain_with_param_pack(signer, lock_parameters);
            // Publish lock event
            LockProxy::emit_lock_event(event);
        } else if (CrossChainGlobal::chain_id_match<CrossChainGlobal::ETHEREUM_CHAIN>(to_chain_id)) {
            let (lock_parameters, event) =
                LockProxy::lock_with_param_pack<TokenT, CrossChainGlobal::ETHEREUM_CHAIN>(signer, to_chain_id, to_address, amount);
            // Do crosschain option from cross chain manager
            CrossChainManager::cross_chain_with_param_pack(signer, lock_parameters);
            // Publish lock event
            LockProxy::emit_lock_event(event);
        } else {
            assert!(false, Errors::invalid_state(ERROR_NO_SUPPORT_LOCK_CHAIN_TYPE));
        };
    }


    // Verify header and execute transaction
    public fun verify_header_and_execute_tx(proof: &vector<u8>,
                                            raw_header: &vector<u8>,
                                            header_proof: &vector<u8>,
                                            cur_raw_header: &vector<u8>,
                                            header_sig: &vector<u8>,
                                            merkle_proof_root: &vector<u8>,
                                            merkle_proof_leaf: &vector<u8>,
                                            input_merkle_proof_siblings: &vector<u8>) {
        CrossChainGlobal::require_not_freezing();

        // Verify header and parse method and args from proof vector
        let header_verified_params = CrossChainManager::verify_header_with_param_pack(
            proof,
            raw_header,
            header_proof,
            cur_raw_header,
            header_sig
        );

        let certificate =
            CrossChainProcessCombinator::create_proof_certificate(
                &header_verified_params,
                merkle_proof_root,
                merkle_proof_leaf,
                &SMTProofUtils::split_side_nodes_data(input_merkle_proof_siblings)
            );

        let method = CrossChainProcessCombinator::lookup_method(&header_verified_params);
        if (*&method == b"unlock") {
            let to_asset_hash = CrossChainProcessCombinator::lookup_asset_hash(&header_verified_params);

            let ret = if (CrossChainGlobal::asset_hash_match<STC::STC>(&to_asset_hash)) {
                inner_do_unlock<STC::STC>(header_verified_params, certificate)
            } else if (CrossChainGlobal::asset_hash_match<XUSDT::XUSDT>(&to_asset_hash)) {
                inner_do_unlock<XUSDT::XUSDT>(header_verified_params, certificate)
            } else if (CrossChainGlobal::asset_hash_match<XETH::XETH>(&to_asset_hash)) {
                inner_do_unlock<XETH::XETH>(header_verified_params, certificate)
            } else {
                false
            };
            assert!(ret, Errors::invalid_state(ERROR_NO_SUPPORT_UNLOCK_ASSET_TYPE));
        } else {
            abort Errors::invalid_state(ERROR_NO_SUPPORT_METHOD)
        };
    }

    // Do unlock operation on inner calling
    public fun inner_do_unlock<TokenT: store>(header_verified_params: CrossChainProcessCombinator::HeaderVerifyedParamPack,
                                              certificate: CrossChainProcessCombinator::MerkleProofCertificate): bool {
        let from_chain_id = CrossChainProcessCombinator::lookup_from_chain_id(&header_verified_params);
        let ret = if (CrossChainGlobal::chain_id_match<CrossChainGlobal::STARCOIN_CHAIN>(from_chain_id)) {
            let unlock_event = LockProxy::unlock_with_pack<TokenT, CrossChainGlobal::STARCOIN_CHAIN>(header_verified_params, certificate);
            LockProxy::emit_unlock_event<TokenT, CrossChainGlobal::STARCOIN_CHAIN>(unlock_event)
        } else if (CrossChainGlobal::chain_id_match<CrossChainGlobal::ETHEREUM_CHAIN>(from_chain_id)) {
            let unlock_event = LockProxy::unlock_with_pack<TokenT, CrossChainGlobal::ETHEREUM_CHAIN>(header_verified_params, certificate);
            LockProxy::emit_unlock_event<TokenT, CrossChainGlobal::ETHEREUM_CHAIN>(unlock_event)
        } else {
            abort Errors::invalid_state(ERROR_NO_SUPPORT_UNLOCK_CHAIN_TYPE)
        };
        ret
    }


    public fun bind_proxy_hash(signer: &signer,
                               to_chain_id: u64,
                               target_proxy_hash: &vector<u8>) {
        if (CrossChainGlobal::chain_id_match<CrossChainGlobal::STARCOIN_CHAIN>(to_chain_id)) {
            LockProxy::bind_proxy_hash<CrossChainGlobal::STARCOIN_CHAIN>(signer, to_chain_id, target_proxy_hash);
        } else if (CrossChainGlobal::chain_id_match<CrossChainGlobal::ETHEREUM_CHAIN>(to_chain_id)) {
            LockProxy::bind_proxy_hash<CrossChainGlobal::ETHEREUM_CHAIN>(signer, to_chain_id, target_proxy_hash);
        } else {
            abort Errors::invalid_state(ERROR_NO_SUPPORT_BIND_CHAIN_TYPE)
        };
    }

    public fun bind_asset_hash(signer: &signer,
                               from_asset_hash: &vector<u8>,
                               to_chain_id: u64,
                               to_asset_hash: &vector<u8>) {
        if (CrossChainGlobal::asset_hash_match<STC::STC>(from_asset_hash)) {
            inner_do_bind_asset_hash<STC::STC>(signer, to_chain_id, to_asset_hash);
        } else if (CrossChainGlobal::asset_hash_match<XUSDT::XUSDT>(from_asset_hash)) {
            inner_do_bind_asset_hash<XUSDT::XUSDT>(signer, to_chain_id, to_asset_hash);
        } else if (CrossChainGlobal::asset_hash_match<XETH::XETH>(from_asset_hash)) {
            inner_do_bind_asset_hash<XETH::XETH>(signer, to_chain_id, to_asset_hash);
        } else {
            assert!(false, Errors::invalid_state(ERROR_NO_SUPPORT_BIND_ASSET_TYPE));
        };
    }

    fun inner_do_bind_asset_hash<TokenT: store>(signer: &signer,
                                                to_chain_id: u64,
                                                to_asset_hash: &vector<u8>) {
        if (CrossChainGlobal::chain_id_match<CrossChainGlobal::STARCOIN_CHAIN>(to_chain_id)) {
            LockProxy::bind_asset_hash<TokenT, CrossChainGlobal::STARCOIN_CHAIN>(signer, to_chain_id, to_asset_hash);
        } else if (CrossChainGlobal::chain_id_match<CrossChainGlobal::ETHEREUM_CHAIN>(to_chain_id)) {
            LockProxy::bind_asset_hash<TokenT, CrossChainGlobal::ETHEREUM_CHAIN>(signer, to_chain_id, to_asset_hash);
        } else {
            assert!(false, Errors::invalid_state(ERROR_NO_SUPPORT_BIND_CHAIN_TYPE));
        };
    }
}
module Bridge::CrossChainProcessCombinator {

    use StarcoinFramework::Errors;

    use Bridge::CrossChainSMTProofs;
    use Bridge::CrossChainData;
    use Bridge::CrossChainLibrary;

    struct LockToChainParamPack has drop {
        to_chain_id: u64,
        to_contract: vector<u8>,
        method: vector<u8>,
        tx_data: vector<u8>,
    }

    struct HeaderVerifyedParamPack has store, drop {
        method: vector<u8>,
        // args
        args: vector<u8>,
        // from chain id
        from_chain_id: u64,
        // from_contract
        from_contract: vector<u8>,
        // tx hash
        tx_hash: vector<u8>,
    }

    struct MerkleProofCertificate has drop {
        verified_params: HeaderVerifyedParamPack,
    }

    const ERR_TRANSACTION_EXECUTE_REPEATE: u64 = 101;

    friend Bridge::CrossChainManager;
    friend Bridge::LockProxy;

    public(friend) fun lock_to_chain_parameters(to_chain_id: u64,
                                                to_contract: &vector<u8>,
                                                method: &vector<u8>,
                                                tx_data: &vector<u8>
    ): LockToChainParamPack {
        LockToChainParamPack {
            to_chain_id,
            to_contract: *to_contract,
            method: *method,
            tx_data: *tx_data
        }
    }

    public(friend) fun unpack_lock_to_chain_parameters(cap: LockToChainParamPack): (
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>
    ) {
        let LockToChainParamPack {
            to_chain_id,
            to_contract,
            method,
            tx_data
        } = cap;
        (to_chain_id, to_contract, method, tx_data)
    }

    public(friend) fun pack_header_verified_param(
        method: vector<u8>,
        args: vector<u8>,
        from_chain_id: u64,
        from_contract: vector<u8>,
        tx_hash: vector<u8>,
    ): HeaderVerifyedParamPack {
        HeaderVerifyedParamPack {
            method,
            args,
            from_chain_id,
            from_contract,
            tx_hash
        }
    }

    public fun unpack_head_verified_param(cap: HeaderVerifyedParamPack): (
        vector<u8>,
        vector<u8>, // args
        u64, // from chain id
        vector<u8>, // from_contract
        vector<u8>, // tx hash
    ) {
        let HeaderVerifyedParamPack { method, args, from_chain_id, from_contract, tx_hash } = cap;
        (
            method,
            args,
            from_chain_id,
            from_contract,
            tx_hash,
        )
    }

    public fun create_proof_certificate(header_verified_params: &HeaderVerifyedParamPack,
                                        merkle_proof_root: &vector<u8>,
                                        merkle_proof_leaf: &vector<u8>,
                                        merkle_proof_siblings: &vector<vector<u8>>): MerkleProofCertificate {
        let proof_path_hash = CrossChainSMTProofs::generate_leaf_path(
            header_verified_params.from_chain_id, &header_verified_params.tx_hash);

        assert!(
            CrossChainData::check_chain_tx_not_exists(
                &proof_path_hash, merkle_proof_root, merkle_proof_leaf, merkle_proof_siblings),
            Errors::invalid_state(ERR_TRANSACTION_EXECUTE_REPEATE)
        );
        CrossChainData::mark_from_chain_tx_exists(&proof_path_hash, merkle_proof_leaf, merkle_proof_siblings);

        // Create a certificate for verfied parameters
        MerkleProofCertificate {
            verified_params: HeaderVerifyedParamPack {
                method: *&header_verified_params.method,
                args: *&header_verified_params.args,
                from_chain_id: *&header_verified_params.from_chain_id,
                from_contract: *&header_verified_params.from_contract,
                tx_hash: *&header_verified_params.tx_hash,
            }
        }
    }


    public fun verify_proof_certificate(cer: MerkleProofCertificate,
                                        verified_header_params: &HeaderVerifyedParamPack): bool {
        let MerkleProofCertificate {
            verified_params: cert_params
        } = cer;
        *&cert_params.method == *&verified_header_params.method &&
            *&cert_params.args == *&verified_header_params.args &&
            *&cert_params.from_chain_id == *&verified_header_params.from_chain_id &&
            *&cert_params.from_contract == *&verified_header_params.from_contract &&
            *&cert_params.tx_hash == *&verified_header_params.tx_hash
    }

    public fun lookup_asset_hash(parameters: &HeaderVerifyedParamPack): vector<u8> {
        let (to_asset_hash, _, _) = CrossChainLibrary::deserialize_tx_args(*&parameters.args);
        to_asset_hash
    }

    public fun lookup_from_chain_id(parameters: &HeaderVerifyedParamPack): u64 {
        *&parameters.from_chain_id
    }

    public fun lookup_method(parameters: &HeaderVerifyedParamPack): vector<u8> {
        *&parameters.method
    }
}

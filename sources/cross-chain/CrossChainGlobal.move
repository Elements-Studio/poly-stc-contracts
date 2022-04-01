address Bridge {

module CrossChainGlobal {

    use StarcoinFramework::Errors;
    use StarcoinFramework::Signer;
    use Bridge::CrossChainConfig;

    friend Bridge::CrossChainManager;
    friend Bridge::LockProxy;

    const ERR_INVALID_ACCOUNT: u64 = 101;
    const ERR_TOKEN_TYPE_INVALID: u64 = 102;
    const ERR_GLOBAL_HAS_FROZEN: u64 = 103;

    struct STARCOIN_CHAIN has key, store {}

    struct ETHEREUM_CHAIN has key, store {}

    struct ExecutionCapability {
        tx_data: vector<u8>,
        proof_tx_non_exists: bool,
    }

    struct ChainId<phantom ChainType> has key, store {
        chain_id: u64,
    }

    struct AssetType<phantom TokenT> has key, store {
        asset_hash: vector<u8>,
    }

    /// Genesis account permission check
    public fun require_genesis_account(account: address) {
        CrossChainConfig::assert_genesis(account)
    }

    public fun require_not_freezing() {
        assert!(!CrossChainConfig::freezing(), Errors::invalid_state(ERR_GLOBAL_HAS_FROZEN))
    }

    /// Admin account permission check
    public fun require_admin_account(account: address) {
        assert!(account == CrossChainConfig::admin_account() ||
               account == CrossChainConfig::genesis_account(),
            Errors::invalid_argument(ERR_INVALID_ACCOUNT));
    }

    /// Get admin account from config
    public fun admin_account(): address {
        CrossChainConfig::admin_account()
    }

    /// Get fee collection account from config
    public fun fee_collection_account(): address {
        CrossChainConfig::fee_collection_account()
    }

    public fun genesis_account(): address {
        CrossChainConfig::genesis_account()
    }

    public(friend) fun generate_execution_cap(tx_data: &vector<u8>,
                                              proof_tx_non_exists: bool): ExecutionCapability {
        ExecutionCapability{
            tx_data: *tx_data,
            proof_tx_non_exists
        }
    }

    public(friend) fun destroy_execution_cap(cap: ExecutionCapability) {
        let ExecutionCapability{
            tx_data : _,
            proof_tx_non_exists: _
        } = cap;
    }


    public(friend) fun tx_hash_has_proof(cap: &mut ExecutionCapability) {
        cap.proof_tx_non_exists = true
    }

    public(friend) fun verify_execution_cap(cap: &ExecutionCapability,
                                            tx_data: &vector<u8>): bool {
        (*&cap.tx_data == *tx_data && cap.proof_tx_non_exists)
    }

    public(friend) fun verify_execution_tx_non_exists(cap: &ExecutionCapability): bool {
        cap.proof_tx_non_exists
    }

    /// Set chain ID of ChainType
    public fun set_chain_id<ChainType: store>(signer: &signer, chain_id: u64) acquires ChainId {
        let account = Signer::address_of(signer);
        require_admin_account(account);

        if (exists<ChainId<ChainType>>(genesis_account())) {
            let chain_id_store = borrow_global_mut<ChainId<ChainType>>(genesis_account());
            chain_id_store.chain_id = chain_id;
        } else {
            move_to(signer, ChainId<ChainType>{
                chain_id
            });
        }
    }

    public fun get_chain_id<ChainType: store>(): u64 acquires ChainId {
        if (exists<ChainId<ChainType>>(genesis_account())) {
            let chain_id_store = borrow_global<ChainId<ChainType>>(genesis_account());
            chain_id_store.chain_id
        } else {
            0
        }
    }

    /// Check chain id is matched to type
    public fun chain_id_match<ChainType: store>(chain_id: u64): bool acquires ChainId {
        if (exists<ChainId<ChainType>>(genesis_account())) {
            let chain_id_store = borrow_global<ChainId<ChainType>>(genesis_account());
            chain_id_store.chain_id == chain_id
        } else {
            false
        }
    }

    /// Set asset hash on Starcoin for token type
    public fun set_asset_hash<TokenT: store>(signer: &signer, asset_hash: &vector<u8>) acquires AssetType {
        let account = Signer::address_of(signer);
        require_admin_account(account);

        if (exists<AssetType<TokenT>>(genesis_account())) {
            let asset_type = borrow_global_mut<AssetType<TokenT>>(genesis_account());
            asset_type.asset_hash = *asset_hash;
        } else {
            move_to(signer, AssetType<TokenT>{
                asset_hash: *asset_hash
            });
        }
    }

    /// Check asset type is matched to asset hash
    public fun asset_hash_match<TokenT: store>(asset_hash: &vector<u8>): bool acquires AssetType {
        if (exists<AssetType<TokenT>>(genesis_account())) {
            let asset_type = borrow_global<AssetType<TokenT>>(genesis_account());
            *&asset_type.asset_hash == *asset_hash
        } else {
            false
        }
    }
}
}
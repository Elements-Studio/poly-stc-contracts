module Bridge::zion_lock_proxy_script {
    use Bridge::zion_lock_proxy;

    public(script) fun init(signer: signer) {
        zion_lock_proxy::init(&signer);
    }

    public(script) fun relay_unlock_tx<CoinType: store>(
        account: signer,
        raw_header: vector<u8>,
        raw_seals: vector<u8>,
        account_proof: vector<u8>,
        storage_proof: vector<u8>,
        raw_cross_tx: vector<u8>
    ) {
        zion_lock_proxy::relay_unlock_tx<CoinType>(
            &account,
            raw_header,
            raw_seals,
            account_proof,
            storage_proof,
            raw_cross_tx
        );
    }

    public(script) fun transferOwnerShip(owner: signer, new_owner: address) {
        zion_lock_proxy::transferOwnerShip(&owner, new_owner);
    }

    public(script) fun pause(owner: signer) {
        zion_lock_proxy::pause(&owner);
    }

    public(script) fun unpause(owner: signer) {
        zion_lock_proxy::unpause(&owner);
    }

    public(script) fun bindProxy(
        owner: signer,
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    ) {
        zion_lock_proxy::bindProxy(&owner, to_chain_id, target_proxy_hash);
    }

    public(script) fun unbindProxy(owner: signer, to_chain_id: u64) {
        zion_lock_proxy::unbindProxy(&owner, to_chain_id);
    }

    public(script) fun bindAsset<CoinType>(
        owner: signer,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_asset_decimals: u8
    ) {
        zion_lock_proxy::bindAsset<CoinType>(&owner, to_chain_id, to_asset_hash, to_asset_decimals);
    }

    public(script) fun unbindAsset<CoinType>(owner: signer, to_chain_id: u64) {
        zion_lock_proxy::unbindAsset<CoinType>(&owner, to_chain_id);
    }

    // treasury function
    public(script) fun initTreasury<CoinType: store>(admin: signer) {
        zion_lock_proxy::initTreasury<CoinType>(&admin);
    }
}

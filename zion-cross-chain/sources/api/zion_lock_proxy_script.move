module Bridge::zion_lock_proxy_script {
    use Bridge::zion_lock_proxy;
    use StarcoinFramework::Event;
    use StarcoinFramework::TypeInfo::TypeInfo;
    use StarcoinFramework::Token;
    use StarcoinFramework::Account;
    use StarcoinFramework::TypeInfo;
    use StarcoinFramework::Signer;
    use StarcoinFramework::STC;
    use StarcoinFramework::Errors;

    const ERROR_NO_PRIVILEGE: u64 = 101;

    struct LockWithFeeConfig has key, store {
        billing_account: address,
        lock_with_fee_event: Event::EventHandle<LockWithFeeEvent>
    }

    struct LockWithFeeEvent has store, drop {
        from_asset: TypeInfo,
        from_address: address,
        to_chain_id: u64,
        to_address: vector<u8>,
        amount: u64,
        fee_amount: u64
    }

    public entry fun relay_unlock_tx<CoinType: store>(
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

    public entry fun lock<CoinType: store>(
        account: signer,
        amount: u128,
        fee_amount: u128,
        toChainId: u64,
        toAddress: vector<u8>,
    ) acquires LockWithFeeConfig {
        let fund = Account::withdraw<CoinType>(&account, amount);
        zion_lock_proxy::lock<CoinType>(&account, fund, toChainId, &toAddress);
        let config_ref = borrow_global_mut<LockWithFeeConfig>(@Bridge);

        // ///////// lock STC fee here ///////////
        let stc_token = Account::withdraw<STC::STC>(&account, fee_amount);
        Account::deposit(config_ref.billing_account, stc_token);

        Event::emit_event(
            &mut config_ref.lock_with_fee_event,
            LockWithFeeEvent {
                from_asset: TypeInfo::type_of<Token::Token<CoinType>>(),
                from_address: Signer::address_of(&account),
                to_chain_id: toChainId,
                to_address: toAddress,
                amount: (amount as u64),
                fee_amount: 0,
            },
        );
    }

    public entry fun transferOwnerShip(owner: signer, new_owner: address) {
        zion_lock_proxy::transferOwnerShip(&owner, new_owner);
    }

    public entry fun pause(owner: signer) {
        zion_lock_proxy::pause(&owner);
    }

    public entry fun unpause(owner: signer) {
        zion_lock_proxy::unpause(&owner);
    }

    public entry fun bindProxy(
        owner: signer,
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    ) {
        zion_lock_proxy::bindProxy(&owner, to_chain_id, target_proxy_hash);
    }

    public entry fun unbindProxy(owner: signer, to_chain_id: u64) {
        zion_lock_proxy::unbindProxy(&owner, to_chain_id);
    }

    public entry fun setFeeConfig(owner: signer, billing_account: address) acquires LockWithFeeConfig {
        let owner_addr = Signer::address_of(&owner);
        assert!(Signer::address_of(&owner) == @Bridge, Errors::requires_capability(ERROR_NO_PRIVILEGE));
        if (!exists<LockWithFeeConfig>(owner_addr)) {
            move_to<LockWithFeeConfig>(&owner, LockWithFeeConfig {
                billing_account,
                lock_with_fee_event: Event::new_event_handle<LockWithFeeEvent>(&owner),
            });
        } else {
            let cfg = borrow_global_mut<LockWithFeeConfig>(owner_addr);
            cfg.billing_account = billing_account;
        }
    }

    public entry fun bindAsset<CoinType>(
        owner: signer,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_asset_decimals: u8
    ) {
        zion_lock_proxy::bindAsset<CoinType>(&owner, to_chain_id, to_asset_hash, to_asset_decimals);
    }

    public entry fun unbindAsset<CoinType>(owner: signer, to_chain_id: u64) {
        zion_lock_proxy::unbindAsset<CoinType>(&owner, to_chain_id);
    }

    // treasury function
    public entry fun initTreasury<CoinType: store>(admin: signer) {
        zion_lock_proxy::initTreasury<CoinType>(&admin);
    }
}

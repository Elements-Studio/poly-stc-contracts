module Bridge::UpgradeScript {
    use Bridge::CrossChainConstant;
    use Bridge::CrossChainGlobal;
    use Bridge::LockProxy;

    use StarcoinFramework::Config;
    use StarcoinFramework::Option;
    use StarcoinFramework::PackageTxnManager;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Version;
    use SwapAdmin::STAR;

    // Update `signer`'s module upgrade strategy to `strategy` with min time
    public(script) fun update_module_upgrade_strategy_with_min_time(
        signer: signer,
        strategy: u8,
        min_time_limit: u64,
    ) {
        let account = Signer::address_of(&signer);
        CrossChainGlobal::require_genesis_account(account);

        // 1. check version
        if (strategy == PackageTxnManager::get_strategy_two_phase()) {
            if (!Config::config_exist_by_address<Version::Version>(account)) {
                Config::publish_new_config<Version::Version>(&signer, Version::new_version(1));
            }
        };

        // 2. update strategy
        PackageTxnManager::update_module_upgrade_strategy(
            &signer,
            strategy,
            Option::some<u64>(min_time_limit),
        );
    }

    /// target chainid:
    ///    Testnet = 998
    ///    Mainnet = 41
    /// target_address:
    ///    Testnet = 5962d917110aa25732e5eb0a0dd1390a2744008f95566808046fc95882e23052
    ///    Mainnet = ?
    ///
    public(script) fun upgrade_from_1_0_12_to_1_0_13(signer: signer, aptos_chain_id: u64, target_address: vector<u8>) {
        // let aptos_chain_id = 998;
        // let target_address = b"5962d917110aa25732e5eb0a0dd1390a2744008f95566808046fc95882e23052";

        // Install asset hash in this chain
        CrossChainGlobal::set_asset_hash<STAR::STAR>(
            &signer,
            &CrossChainConstant::get_asset_hash_star()
        );

        let to_proxy_hash = Vector::empty<u8>();
        Vector::append(&mut to_proxy_hash, *&target_address);
        Vector::append(&mut to_proxy_hash, b"::asset::STAR");
        LockProxy::init_proxy_hash<CrossChainGlobal::APTOS_CHAIN>(
            &signer,
            aptos_chain_id,
            &to_proxy_hash
        );

        let to_asset_hash = Vector::empty<u8>();
        CrossChainGlobal::set_chain_id<CrossChainGlobal::APTOS_CHAIN>(&signer, aptos_chain_id);
        Vector::append(&mut to_asset_hash, *&target_address);
        Vector::append(&mut to_asset_hash, b"::starcoin_lock_proxy");
        LockProxy::init_asset_hash<STAR::STAR, CrossChainGlobal::APTOS_CHAIN>(
            &signer,
            aptos_chain_id,
            &to_asset_hash,
        );
    }
}
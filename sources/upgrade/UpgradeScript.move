module PolyBridge::UpgradeScript {
    use ZionBridge::zion_lock_proxy;

    use PolyBridge::CrossChainGlobal;
    use PolyBridge::LockProxy;
    use PolyBridge::XETH::XETH;
    use PolyBridge::XUSDT::XUSDT;
    use StarcoinFramework::Config;
    use StarcoinFramework::Option;
    use StarcoinFramework::PackageTxnManager;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Version;

    // Update `signer`'s module upgrade strategy to `strategy` with min time
    public entry fun update_module_upgrade_strategy_with_min_time(
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

    fun migrate_treasury<TokenT: store>(admin: &signer) {
        zion_lock_proxy::deposit(LockProxy::withdraw_all_treasury<TokenT>(admin));
    }

    ///
    /// When this function is called, all its code will be discarded, and the new code refers to the git library:
    /// https://github.com/Elements-Studio/zion-stc-contracts.git
    ///
    public entry fun upgrade_v1_to_v2_zion(admin: signer) {
        migrate_treasury<STC>(&admin);
        migrate_treasury<XUSDT>(&admin);
        migrate_treasury<XETH>(&admin);
    }
}
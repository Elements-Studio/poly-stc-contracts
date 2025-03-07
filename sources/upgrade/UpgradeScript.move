module Bridge::UpgradeScript {
    use StarcoinFramework::stc_transaction_package_validation as PackageTxnManager;
    use StarcoinFramework::on_chain_config as Config;
    use StarcoinFramework::signer as Signer;
    use StarcoinFramework::stc_version as Version;
    use StarcoinFramework::option;

    use Bridge::CrossChainGlobal;

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
            option::some(min_time_limit),
        );
    }
}
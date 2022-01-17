address 0x18351d311d32201149a4df2a9fc2db8a {

module UpgradeScript {
    use 0x1::PackageTxnManager;
    use 0x1::Config;
    use 0x1::Signer;
    use 0x1::Version;
    use 0x1::Option;

    use 0x18351d311d32201149a4df2a9fc2db8a::CrossChainGlobal;

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
}
}


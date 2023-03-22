module Bridge::zion_upgrade_script {

    use Bridge::SafeMath;
    use Bridge::zion_cross_chain_manager;
    use Bridge::zion_lock_proxy;

    use StarcoinFramework::BCS;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Token;

    fun migration_from_old_treasury() {
        // TODO(Bob Ong):
    }

    public entry fun genesis_init(admin: signer, raw_header: vector<u8>, starcoin_poly_id: u64) {
        // Treasury
        zion_cross_chain_manager::init(&admin, raw_header, starcoin_poly_id);

        let license = zion_cross_chain_manager::issueLicense(&admin, Signer::address_of(&admin), b"zion_lock_proxy");
        zion_lock_proxy::init(&admin);
        zion_lock_proxy::initTreasury<STC>(&admin);
        zion_lock_proxy::receiveLicense(license);

        // Bind STC
        zion_lock_proxy::bindProxy(&admin, starcoin_poly_id, BCS::to_bytes(&@Bridge));
        zion_lock_proxy::bindAsset<STC>(
            &admin,
            starcoin_poly_id,
            b"0x1::STC::STC",
            SafeMath::log10(Token::scaling_factor<STC>())
        );

        // TODO(Bob Ong): Bind XUSDT asset
        // TODO(Bob Ong): Bind XETH asset

        // Fee
        migration_from_old_treasury();
    }
}

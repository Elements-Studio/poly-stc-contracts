module Bridge::zion_cross_chain_manager_script {

    use Bridge::zion_cross_chain_manager;

    public entry fun grantRole(admin: signer, role: u64, account: address) {
        zion_cross_chain_manager::grantRole(&admin, role, account);
    }

    public entry fun revokeRole(admin: signer, role: u64, account: address) {
        zion_cross_chain_manager::grantRole(&admin, role, account);
    }

    public entry fun setBlackList(ca: signer, license_id: vector<u8>, access_level: u8) {
        zion_cross_chain_manager::setBlackList(&ca, license_id, access_level);
    }

    public entry fun init(account: signer, raw_header: vector<u8>, polyId: u64) {
        zion_cross_chain_manager::init(&account, raw_header, polyId);
    }

    public entry fun setPolyId(account: signer, polyId: u64) {
        zion_cross_chain_manager::setPolyId(&account, polyId);
    }

    public entry fun change_epoch(
        account: signer,
        raw_header: vector<u8>,
        raw_seals: vector<u8>
    ) {
        zion_cross_chain_manager::change_epoch(&account, raw_header, raw_seals);
    }
}

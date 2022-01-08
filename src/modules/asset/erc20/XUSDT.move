
address 0x2d81a0427d64ff61b11ede9085efa5ad {
module XUSDT {
    use 0x1::Token;
    use 0x1::Account;

    /// XUSDT token marker.
    struct XUSDT has copy, drop, store {}


    /// precision of XUSDT token.
    const PRECISION: u8 = 9;

    /// XUSDT initialization.
    public fun init(account: &signer) {
        Token::register_token<XUSDT>(account, PRECISION);
        Account::do_accept_token<XUSDT>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        let token = Token::mint<XUSDT>(account, amount);
        Account::deposit_to_self<XUSDT>(account, token)
    }
}

module XUSDTScripts {
    use 0x2d81a0427d64ff61b11ede9085efa5ad::XUSDT;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

    public(script) fun init(account: signer,
                            proxy_hash: vector<u8>,
                            asset_hash: vector<u8>) {
        XUSDT::init(&account);

        // Bind proxy hash and asset hash
        let chain_id = CrossChainGlobal::get_chain_id<CrossChainGlobal::ETHEREUM_CHAIN>();
        LockProxy::bind_proxy_hash<CrossChainGlobal::ETHEREUM_CHAIN>(&account, chain_id, &proxy_hash);
        LockProxy::bind_asset_hash<XUSDT::XUSDT, CrossChainGlobal::ETHEREUM_CHAIN>(&account, chain_id, &asset_hash);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
    }
}


}

address 0x2d81a0427d64ff61b11ede9085efa5ad {
module XUSDT {
    use 0x1::Token;
    use 0x1::Account;

    /// XUSDT token marker.
    struct XUSDT has copy, drop, store {}

    /// Chain type
    struct ETHEREUM has copy, drop, store {}

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
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainRouter;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;

    public(script) fun init(account: signer,
                            proxy_hash: vector<u8>,
                            asset_hash: vector<u8>) {
        XUSDT::init(&account);

        // bind asset and proxy
        CrossChainRouter::bind_asset_and_proxy<
            XUSDT::XUSDT,
            CrossChainGlobal::ETHEREUM_CHAIN>(
            &account,
            CrossChainGlobal::get_chain_id<CrossChainGlobal::ETHEREUM_CHAIN>(),
            &proxy_hash,
            &asset_hash);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
    }
}


}
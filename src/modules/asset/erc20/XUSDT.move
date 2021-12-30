
address 0x2d81a0427d64ff61b11ede9085efa5ad {
module XUSDT {
    use 0x1::Token;
    use 0x1::Account;

    /// XUSDT token marker.
    struct XUSDT has copy, drop, store {}

    /// Chain type
    struct USD_CHAIN has copy, drop, store {}

    /// precision of XUSDT token.
    const PRECISION: u8 = 9;
    const CHAINID: u64 = 200;

    /// XUSDT initialization.
    public fun init(account: &signer) {
        Token::register_token<XUSDT>(account, PRECISION);
        Account::do_accept_token<XUSDT>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        let token = Token::mint<XUSDT>(account, amount);
        Account::deposit_to_self<XUSDT>(account, token)
    }

    public fun get_chain_id() : u64 {
        CHAINID
    }
}

module XUSDTScripts {
    use 0x2d81a0427d64ff61b11ede9085efa5ad::XUSDT;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainRouter;

    public(script) fun init(account: signer,
                            proxy_hash: vector<u8>,
                            asset_hash: vector<u8>) {
        XUSDT::init(&account);

        // bind asset and proxy
        CrossChainRouter::bind_asset_and_proxy<
            XUSDT::XUSDT,
            XUSDT::USD_CHAIN>(
            &account,
            XUSDT::get_chain_id(),
            &proxy_hash,
            &asset_hash);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
    }
}


}
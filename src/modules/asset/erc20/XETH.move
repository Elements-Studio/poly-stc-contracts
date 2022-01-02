
address 0x2d81a0427d64ff61b11ede9085efa5ad {
module XETH {
    use 0x1::Token;
    use 0x1::Account;

    /// XETH token marker.
    struct XETH has copy, drop, store {}

    /// precision of XETH token.
    const PRECISION: u8 = 18;

    /// XETH initialization.
    public fun init(account: &signer) {
        Token::register_token<XETH>(account, PRECISION);
        Account::do_accept_token<XETH>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        let token = Token::mint<XETH>(account, amount);
        Account::deposit_to_self<XETH>(account, token)
    }
}

module XETHScripts {
    use 0x2d81a0427d64ff61b11ede9085efa5ad::XETH;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainRouter;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;

    public(script) fun init(account: signer,
                            proxy_hash: vector<u8>,
                            asset_hash: vector<u8>) {
        XETH::init(&account);

        // bind asset and proxy
        CrossChainRouter::bind_asset_and_proxy<
            XETH::XETH,
            CrossChainGlobal::ETHEREUM_CHAIN>(
            &account,
            CrossChainGlobal::get_chain_id<CrossChainGlobal::ETHEREUM_CHAIN>(),
            &proxy_hash,
            &asset_hash);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XETH::mint(&account, amount);
    }
}

}
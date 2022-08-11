
module Bridge::XETH {
    use StarcoinFramework::Token;
    use StarcoinFramework::Account;

    // XETH token marker.
    struct XETH has copy, drop, store {}

    // precision of XETH token.
    const PRECISION: u8 = 18;

    // XETH initialization.
    public fun init(account: &signer) {
        Token::register_token<XETH>(account, PRECISION);
        Account::do_accept_token<XETH>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        let token = Token::mint<XETH>(account, amount);
        Account::deposit_to_self<XETH>(account, token);
    }
}

module Bridge::XETHScripts {
    use Bridge::XETH;
    use Bridge::LockProxy;

    public(script) fun init(account: signer) {
        XETH::init(&account);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XETH::mint(&account, amount);
        LockProxy::move_to_treasury<XETH::XETH>(&account, amount);
    }
}
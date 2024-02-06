
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

    public fun burn(account: &signer, amount: u128) {
        Token::burn(account, Account::withdraw<XETH>(account, amount));
    }
}

module Bridge::XETHScripts {
    use Bridge::XETH;
    use Bridge::LockProxy;

    public entry fun init(account: signer) {
        XETH::init(&account);
    }

    /// Only called with someone who have burn capability
    public entry fun mint(account: signer, amount: u128) {
        XETH::mint(&account, amount);
        LockProxy::move_to_treasury<XETH::XETH>(&account, amount);
    }

    /// Only called with someone who have burn capability
    public entry fun burn(account: signer, amount: u128) {
        XETH::burn(&account, amount);
    }
}
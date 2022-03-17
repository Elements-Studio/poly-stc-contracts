
address 0x416b32009fe49fcab1d5f2ba0153838f {
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
        Account::deposit_to_self<XETH>(account, token);
    }
}

module XETHScripts {
    use 0x416b32009fe49fcab1d5f2ba0153838f::XETH;
    use 0x416b32009fe49fcab1d5f2ba0153838f::LockProxy;

    public(script) fun init(account: signer) {
        XETH::init(&account);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XETH::mint(&account, amount);
        LockProxy::move_to_treasury<XETH::XETH>(&account, amount);
    }
}

}
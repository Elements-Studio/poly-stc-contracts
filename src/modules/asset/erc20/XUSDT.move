
address 0x416b32009fe49fcab1d5f2ba0153838f {
module XUSDT {
    use 0x1::Token;
    use 0x1::Account;

    /// XUSDT token marker.
    struct XUSDT has copy, drop, store {}


    /// precision of XUSDT token.
    /// https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7#code
    /// see USDT on ethereum Constructor Arguments, _decimals (uint256): 6
    const PRECISION: u8 = 6;

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
    use 0x416b32009fe49fcab1d5f2ba0153838f::XUSDT;
    use 0x416b32009fe49fcab1d5f2ba0153838f::LockProxy;

    public(script) fun init(account: signer) {
        XUSDT::init(&account);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
        LockProxy::move_to_treasury<XUSDT::XUSDT>(&account, amount);
    }
}


}

address 0xe52552637c5897a2d499fbf08216f73e {
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
    use 0xe52552637c5897a2d499fbf08216f73e::XUSDT;
    use 0xe52552637c5897a2d499fbf08216f73e::LockProxy;

    public(script) fun init(account: signer) {
        XUSDT::init(&account);
    }

    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
        LockProxy::move_to_treasury<XUSDT::XUSDT>(&account, amount);
    }
}


}
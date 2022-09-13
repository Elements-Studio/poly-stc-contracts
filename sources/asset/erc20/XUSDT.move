
module Bridge::XUSDT {
    use StarcoinFramework::Token;
    use StarcoinFramework::Account;

    // XUSDT token marker.
    struct XUSDT has copy, drop, store {}


    // precision of XUSDT token.
    // https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7#code
    // see USDT on ethereum Constructor Arguments, _decimals (uint256): 6
    const PRECISION: u8 = 6;

    // XUSDT initialization.
    public fun init(account: &signer) {
        Token::register_token<XUSDT>(account, PRECISION);
        Account::do_accept_token<XUSDT>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        let token = Token::mint<XUSDT>(account, amount);
        Account::deposit_to_self<XUSDT>(account, token)
    }

    public fun burn(account: &signer, amount: u128) {
        Token::burn(account, Account::withdraw<XUSDT>(account, amount));
    }
}

module Bridge::XUSDTScripts {
    use Bridge::XUSDT;
    use Bridge::LockProxy;

    public(script) fun init(account: signer) {
        XUSDT::init(&account);
    }

    /// Only called with someone who have mint capability
    public(script) fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
        LockProxy::move_to_treasury<XUSDT::XUSDT>(&account, amount);
    }

    /// Only called with someone who have burn capability
    public(script) fun burn(account: signer, amount: u128) {
        XUSDT::burn(&account, amount);
    }
}
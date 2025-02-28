
module Bridge::XUSDT {
    use std::signer;
    use StarcoinFramework::coin;
    use StarcoinFramework::managed_coin;

    // XUSDT token marker.
    struct XUSDT has copy, drop, store {}


    // precision of XUSDT token.
    // https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7#code
    // see USDT on ethereum Constructor Arguments, _decimals (uint256): 6
    const PRECISION: u8 = 6;

    // XUSDT initialization.
    public fun init(account: &signer) {
        managed_coin::initialize<XUSDT>(account, b"XUSDT", b"XUSDT", PRECISION, true);
        coin::register<XUSDT>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        managed_coin::mint<XUSDT>(account, signer::address_of(account), (amount as u64));
    }

    public fun burn(account: &signer, amount: u128) {
        managed_coin::burn<XUSDT>(account, (amount as u64));
    }
}

module Bridge::XUSDTScripts {
    use Bridge::XUSDT;
    use Bridge::LockProxy;

    public entry fun init(account: signer) {
        XUSDT::init(&account);
    }

    /// Only called with someone who have mint capability
    public entry fun mint(account: signer, amount: u128) {
        XUSDT::mint(&account, amount);
        LockProxy::move_to_treasury<XUSDT::XUSDT>(&account, amount);
    }

    /// Only called with someone who have burn capability
    public entry fun burn(account: signer, amount: u128) {
        XUSDT::burn(&account, amount);
    }
}
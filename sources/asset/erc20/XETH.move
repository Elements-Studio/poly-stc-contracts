
module Bridge::XETH {
    use starcoin_framework::managed_coin;
    use StarcoinFramework::coin;
    use starcoin_std::signer;

    // XETH token marker.
    struct XETH has copy, drop, store {}

    // precision of XETH token.
    const PRECISION: u8 = 18;

    // XETH initialization.
    public fun init(account: &signer) {
        managed_coin::initialize<XETH>(account, b"XETH", b"XETH", PRECISION, true);
        coin::register<XETH>(account);
    }

    public fun mint(account: &signer, amount: u128) {
        managed_coin::mint<XETH>(account, signer::address_of(account), (amount as u64));
    }

    public fun burn(account: &signer, amount: u128) {
        managed_coin::burn<XETH>(account, (amount as u64));
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
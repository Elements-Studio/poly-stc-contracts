module Bridge::XETHScripts {
    use Bridge::XETH;
    use Bridge::LockProxy;

    public(script) fun init(account: signer) {
        XETH::init(&account);
    }

    /// Only called with someone who have burn capability
    public(script) fun mint(account: signer, amount: u128) {
        XETH::mint(&account, amount);
        LockProxy::move_to_treasury<XETH::XETH>(&account, amount);
    }

    /// Only called with someone who have burn capability
    public(script) fun burn(account: signer, amount: u128) {
        XETH::burn(&account, amount);
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
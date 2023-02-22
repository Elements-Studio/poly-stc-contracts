//# init -n test --public-keys Bridge=0x8085e172ecf785692da465ba3339da46c4b43640c3f92a45db803690cc3c4a36

//# faucet --addr Bridge --amount 10000000000

//# faucet --addr alice --amount 10000000000000000


//# publish
module Bridge::CrossChainType {
    struct TokenA has copy, drop, store {}

    struct TokenB has copy, drop, store {}

    struct TokenC has copy, drop, store {}

    struct Starcoin has key, store {}

    struct Ethereum has key, store {}

    struct Bitcoin has key, store {}
}


//# run --signers Bridge
script {
    use Bridge::SafeMath;
    use Bridge::zion_cross_chain_manager;
    use Bridge::zion_lock_proxy;

    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Token;

    fun test_genesis_initialize(signer: signer) {
        let raw_header = x"f9027fa069b23f144a6145325b1485ad1d322ae3af9a64485eff5653cb8d1ffc0822139ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794258af48e28e4a6846e931ddff8e1cdf8579821e5a0dbf86a3e1d5f09e8da4ddde9fb0d3f43f67ad4bde51761985d2661e6bb343fdda07f0461f077192afc0bd8c8a472309620c4278fdeee493d37f278b2d36a775c39a0d4e4d938901e00ea4da08917593dba522a19b68413162444389bb35251dd96e3b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001830fe2688411e1a30083029bf88463f5c28bb8830000000000000000000000000000000000000000000000000000000000000000f861830fe268830fee20f85494258af48e28e4a6846e931ddff8e1cdf8579821e5946a708455c8777630aac9d1e7702d13f7a865b27c948c09d936a1b408d6e0afaa537ba4e06c4504a0ae94ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c80c080a063746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365880000000000000000";
        zion_cross_chain_manager::init(&signer, raw_header, 318);

        let license = zion_cross_chain_manager::issueLicense(&signer, Signer::address_of(&signer), b"zion_lock_proxy");
        zion_lock_proxy::init(&signer);
        zion_lock_proxy::initTreasury<STC>(&signer);
        zion_lock_proxy::receiveLicense(license);

        // Bind STC
        zion_lock_proxy::bindProxy(&signer, 318, x"e52552637c5897a2d499fbf08216f73e");
        zion_lock_proxy::bindAsset<STC>(&signer, 318, b"0x1::STC::STC", SafeMath::log10(Token::scaling_factor<STC>()));
    }
}
// check: EXECUTED

//# run --signers alice
script {
    use Bridge::zion_lock_proxy;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Account;
    use StarcoinFramework::Token;
    use StarcoinFramework::BCS;

    fun alice_lock_stc(sender: signer) {
        let to_chain_id = 318;
        let amount = 100 * Token::scaling_factor<STC>();
        let stc = Account::withdraw<STC>(&sender, amount);
        let dst_addr = BCS::to_bytes<address>(&@Bridge);
        zion_lock_proxy::lock<STC>(&sender, stc, to_chain_id, &dst_addr);
        assert!(zion_lock_proxy::getBalance<STC>() == amount, 10001);
    }
}
// check: EXECUTED
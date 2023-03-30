//# init -n test --public-keys Bridge=0x8085e172ecf785692da465ba3339da46c4b43640c3f92a45db803690cc3c4a36

//# faucet --addr Bridge --amount 10000000000

//# faucet --addr alice --amount 10000000000000000

//# faucet --addr bob --amount 10000000000000000

//# publish
module Bridge::CrossChainType {
    struct TokenA has copy, drop, store {}

    struct TokenB has copy, drop, store {}

    struct TokenC has copy, drop, store {}

    struct Starcoin has key, store {}

    struct Ethereum has key, store {}

    struct Bitcoin has key, store {}
}

// starcoin poly id = 318

//# run --signers Bridge
script {
    use Bridge::SafeMath;
    use Bridge::zion_cross_chain_manager;
    use Bridge::zion_lock_proxy;

    use StarcoinFramework::BCS;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Token;
    use StarcoinFramework::TypeInfo;
    use StarcoinFramework::Debug;

    fun test_genesis_initialize(signer: signer) {
        let aptos_poly_id = 318; // The poly id of aptos is 998, because the test data was from aptos

        // https://explorer.aptoslabs.com/txn/411144842/payload
        let raw_header = x"f9027ca045222668f471a19044c1680ff108e16f812f1b9f0afb66cfd8a06185ab25c360a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794258af48e28e4a6846e931ddff8e1cdf8579821e5a01abaede3abcb324f60a3d1498cb7cebad9242889ada1162a85209f3be42845d1a090f45e25789803f8ca15ba58ff8775d1ae2d988b8c6d99a0d0bb71ff09fda3aaa0d4e4d938901e00ea4da08917593dba522a19b68413162444389bb35251dd96e3b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001820bb88411e1a30083029bf88463c63b59b8810000000000000000000000000000000000000000000000000000000000000000f85f820bb8821770f85494258af48e28e4a6846e931ddff8e1cdf8579821e5946a708455c8777630aac9d1e7702d13f7a865b27c948c09d936a1b408d6e0afaa537ba4e06c4504a0ae94ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c80c080a063746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365880000000000000000";
        zion_cross_chain_manager::init(&signer, raw_header, aptos_poly_id);

        let license = zion_cross_chain_manager::issueLicense(&signer, @Bridge, b"zion_lock_proxy");
        let license_id = zion_cross_chain_manager::getLicenseId(&license);
        zion_lock_proxy::init(&signer);
        zion_lock_proxy::initTreasury<STC>(&signer);
        zion_lock_proxy::receiveLicense(license);

        Debug::print(&11111111);
        Debug::print(&BCS::to_bytes(&TypeInfo::type_of<STC>()));

        // Bind STC
        zion_lock_proxy::bindProxy(&signer, aptos_poly_id, license_id);
        zion_lock_proxy::bindAsset<STC>(
            &signer,
            aptos_poly_id,
            BCS::to_bytes(&TypeInfo::type_of<STC>()),
            SafeMath::log10(Token::scaling_factor<STC>())
        );
    }
}
// check: EXECUTED

//# run --signers alice
script {
    use Bridge::zion_lock_proxy;
    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::STC::STC;
    use StarcoinFramework::Token;

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

//# run --signers Bridge
script {
    use Bridge::zion_cross_chain_utils;
    use StarcoinFramework::Debug;
    use StarcoinFramework::Vector;

    fun raw_header_check(_sender: signer) {
        // Raw header from https://explorer.aptoslabs.com/txn/436952160/payload, next from the data using in `init` function
        let raw_header = x"f9027fa0c0af2ea5073b2109398dc8edd0ab1fad3ea599614efb98a0473075402d50fa00a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ad3bf5ed640cc72f37bd21d64a65c3c756e9c88ca080e68c19a1e96b4166c5c683189721a4be3939a76e08dbe60d1bbbcf5bd54ce6a0073efd48255496c73a9e4f5825f3d48c61c72a2c2a85acfed3fe601a6f76663fa0d4e4d938901e00ea4da08917593dba522a19b68413162444389bb35251dd96e3b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018311e6088411e1a30083029bf88463fbcde3b8830000000000000000000000000000000000000000000000000000000000000000f8618311e6088311f1c0f85494258af48e28e4a6846e931ddff8e1cdf8579821e5946a708455c8777630aac9d1e7702d13f7a865b27c948c09d936a1b408d6e0afaa537ba4e06c4504a0ae94ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c80c080a063746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365880000000000000000";
        let (epoch_end_height, new_validators) = zion_cross_chain_utils::decode_extra(&raw_header);
        Debug::print(&epoch_end_height);
        Debug::print(&new_validators);
        assert!(epoch_end_height > 0, 10010);
        assert!(Vector::length<vector<u8>>(&new_validators) > 0, 10011);
    }
}
// check: EXECUTED


//# run --signers Bridge
script {
    use Bridge::zion_cross_chain_utils;
    use StarcoinFramework::Debug;

    fun test_eth_tx_param(_sender: signer) {
        let param = zion_cross_chain_utils::encode_tx_param(
            x"61a081eeb1e847d53c9afd9f048a05f3a88e9a2f3a1afafc50a89280c5e3dd7c",
            b"1111",
            b"22222",
            318,
            x"dfe8ca002624bcaecb4188da78d42043",
            b"unlock",
            b"dadafa",
        );
        Debug::print(&param)
    }
}
// check: EXECUTED

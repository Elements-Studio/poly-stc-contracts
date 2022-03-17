address 0xb6d69dd935edf7f2054acf12eb884df8 {
module BCSTest {
    //use 0x1::Vector;
    use 0x1::Debug;
    //use 0x1::BitOperators;
    //use 0x1::Hash;
    use 0x1::BCS;
    use 0x1::STC;
    use 0x1::Token;
    //use 0xb6d69dd935edf7f2054acf12eb884df8::LockProxy;

    struct CrossChainFeeLockEvent has store, drop {
        from_asset: Token::TokenCode,
        sender: address,
        to_chain_id: u64,
        to_address: vector<u8>,
        net: u128,
        fee: u128,
        id: u128,
    }

    #[test]
    public fun test_bcs_serialize() {
        let cc_fee_event = CrossChainFeeLockEvent{
            from_asset: Token::token_code<STC::STC>(),
            sender: @0xb6d69dd935edf7f2054acf12eb884df8,//Signer::address_of(signer),
            to_chain_id: 11,
            to_address: x"18351d311d32201149a4df2a9fc2db8a",//*to_address,
            net: 111,
            fee: 222,
            id: 333,
        };
        let bs = BCS::to_bytes<CrossChainFeeLockEvent>(&cc_fee_event);
        Debug::print<vector<u8>>(&bs);
    }
}
}
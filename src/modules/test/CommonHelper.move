address 0xb6d69dd935edf7f2054acf12eb884df8 {
module CommonHelper {
    use 0x1::Token;
    use 0x1::Account;
    use 0x1::Signer;
//    use 0x1::BitOperators;
//    use 0x1::Vector;
    use 0xb6d69dd935edf7f2054acf12eb884df8::TokenMock;


    const PRECISION_9: u8 = 9;
    const PRECISION_18: u8 = 18;

    public fun safe_accept_token<TokenType: store>(account: &signer) {
        if (!Account::is_accepts_token<TokenType>(Signer::address_of(account))) {
            Account::do_accept_token<TokenType>(account);
        };
    }

    public fun safe_mint<TokenType: store>(account: &signer, token_amount: u128) {
        let is_accept_token = Account::is_accepts_token<TokenType>(Signer::address_of(account));
        if (!is_accept_token) {
            Account::do_accept_token<TokenType>(account);
        };
        let token = TokenMock::mint_token<TokenType>(token_amount);
        Account::deposit<TokenType>(Signer::address_of(account), token);
    }

    public fun transfer<TokenType: store>(account: &signer, token_address: address, token_amount: u128){
        let token = Account::withdraw<TokenType>(account, token_amount);
         Account::deposit(token_address, token);
    }

    public fun get_safe_balance<TokenType: store>(token_address: address): u128{
        let token_balance: u128 = 0;
        if (Account::is_accepts_token<TokenType>(token_address)) {
            token_balance = Account::balance<TokenType>(token_address);
        };
        token_balance
    }

    public fun register_and_mint<TokenType: store>(account: &signer, precision: u8, token_amount: u128) {
        TokenMock::register_token<TokenType>(account, precision);
        safe_mint<TokenType>(account, token_amount);
    }

    public fun pow_amount<Token: store>(amount: u128): u128 {
        amount * Token::scaling_factor<Token>()
    }

    public fun pow_10(exp: u8): u128 {
        pow(10, exp)
    }

    public fun pow(base: u64, exp: u8): u128 {
        let result_val = 1u128;
        let i = 0;
        while (i < exp) {
            result_val = result_val * (base as u128);
            i = i + 1;
        };
        result_val
    }

//    public fun cast_hex_to_u128(hex: vector<u8>): u128 {
//        let number:u128 = 0;
//        let i = 0;
//        let len = Vector::length(&hex);
//        while (i < len){
//            let slice = *Vector::borrow(&hex, i);
//            let bit = (len-(i+1) as u8);
//            number = number + (BitOperators::lshift((slice as u64), bit * 8) as u128);
//            i = i + 1;
//        };
//        number
//    }
}
}
// token holder address, not admin address
module Bridge::TokenMock {
    use StarcoinFramework::type_info;
    use StarcoinFramework::coin;
    use StarcoinFramework::signer;

    struct TokenSharedCapability<phantom TokenType> has key, store {
        mint: coin::MintCapability<TokenType>,
        burn: coin::BurnCapability<TokenType>,
    }

    // mock ETH token
    struct WETH has copy, drop, store {}

    // mock USDT token
    struct WUSDT has copy, drop, store {}

    // mock DAI token
    struct WDAI has copy, drop, store {}

    // mock BTC token
    struct WBTC has copy, drop, store {}

    // mock DOT token
    struct WDOT has copy, drop, store {}


    public fun register_token<TokenType: store>(account: &signer, precision: u8){
        let name = type_info::type_name<TokenType>();
        let (burn_capability, _, mint_capability  ) =
            coin::initialize<TokenType>(account, name, name, precision, true);
        coin::register<TokenType>(account);

        move_to(account, TokenSharedCapability { mint: mint_capability, burn: burn_capability });
    }

    public fun mint_token<TokenType: store>(account: &signer, amount: u64): coin::Coin<TokenType> acquires TokenSharedCapability{
        //token holder address
        let cap = borrow_global<TokenSharedCapability<TokenType>>(signer::address_of(account));
        coin::mint<TokenType>(amount, &cap.mint)
    }

    public fun burn_token<TokenType: store>(account: &signer, tokens: coin::Coin<TokenType>) acquires TokenSharedCapability{
        //token holder address
        let cap = borrow_global<TokenSharedCapability<TokenType>>(signer::address_of(account));
        coin::burn<TokenType>(tokens, &cap.burn);
    }
}
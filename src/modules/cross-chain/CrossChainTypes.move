address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainToken {

    struct X_ETH has key, store {}

    struct X_BTC has key, store {}
}

module CrossChainType {

    struct Ethereum has key, store {}

    struct Bitcoin has key, store {}

    struct Starcoin has key, store {}
}
}
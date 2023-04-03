module PolyBridge::CrossChainConstant {

    use PolyBridge::CrossChainLibrary;
    use StarcoinFramework::Vector;

    const DEFAULT_CHAINID_STARCOIN: u64 = 31;
    const DEFAULT_CHAINID_ETHEREUM: u64 = 2;

    const PROXY_HASH_STARCOIN: vector<u8> = b"::CrossChainScript";

    const ASSET_HASH_STC: vector<u8> = b"0x00000000000000000000000000000001::STC::STC";
    const ASSET_HASH_XETH: vector<u8> = b"::XETH::XETH";
    const ASSET_HASH_XUSDT: vector<u8> = b"::XUSDT::XUSDT";

    public fun get_proxy_hash_starcoin(): vector<u8> {
        let ret = Vector::empty<u8>();
        Vector::append(&mut ret, CrossChainLibrary::address_to_hex_string(@PolyBridge));
        Vector::append(&mut ret, PROXY_HASH_STARCOIN);
        ret
    }

    public fun get_asset_hash_stc(): vector<u8> {
        ASSET_HASH_STC
    }

    public fun get_asset_hash_xeth(): vector<u8> {
        let ret = Vector::empty<u8>();
        Vector::append(&mut ret, CrossChainLibrary::address_to_hex_string(@PolyBridge));
        Vector::append(&mut ret, ASSET_HASH_XETH);
        ret
    }

    public fun get_asset_hash_xusdt(): vector<u8> {
        let ret = Vector::empty<u8>();
        Vector::append(&mut ret, CrossChainLibrary::address_to_hex_string(@PolyBridge));
        Vector::append(&mut ret, ASSET_HASH_XUSDT);
        ret
    }

    public fun get_default_chain_id_starcoin(): u64 {
        DEFAULT_CHAINID_STARCOIN
    }

    public fun get_default_chain_id_ethereum(): u64 {
        DEFAULT_CHAINID_ETHEREUM
    }

}


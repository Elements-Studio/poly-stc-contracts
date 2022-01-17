address 0x18351d311d32201149a4df2a9fc2db8a {
module ZeroCopyTest {
    use 0x18351d311d32201149a4df2a9fc2db8a::Bytes;
    use 0x18351d311d32201149a4df2a9fc2db8a::ZeroCopySink;
    use 0x18351d311d32201149a4df2a9fc2db8a::ZeroCopySource;
    use 0x1::Debug::{Self};
    use 0x1::Vector;

    struct EthAccount has key, store, drop  {
        state_root: vector<u8>,
        height: u64,
        address: vector<u8>,
        balance: u128,
        nonce: u64,
        code_hash: vector<u8>,
        storage_hash: vector<u8>,
    }

    public fun init_eth_account(): EthAccount {
        EthAccount {
            state_root: x"fd725b0325c2bda54cf7e33e3b9f6bc9b7927beb7ba6a2ef5feef7d20b394168",
            height: 11146077,
            address: x"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            balance: 33908700,
            nonce: 17,
            code_hash: x"d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505",
            storage_hash: x"a9302463fd528ce8aca2d5ad58de0622f07e2107c12a780f67c624592bbcc13d",
        }
    }

    #[test]
    public fun test_zero_copy_u8() {
        let u:u8 = 210;
        let offset = 0;
        let buf = ZeroCopySink::write_u8(u);
        let (data, offset) = ZeroCopySource::next_u8(&buf, offset);

        Debug::print<u8>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<u8>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1001);
    }

    #[test]
    public fun test_zero_copy_u64() {
        let u:u64 = 11146077;
        let offset = 0;
        let buf = ZeroCopySink::write_u64(u);
        let (data, offset) = ZeroCopySource::next_u64(&buf, offset);

        Debug::print<u64>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<u64>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1002);
    }

    #[test]
    public fun test_zero_copy_u128() {
        let u:u128 = 33908700;
        let offset = 0;
        let buf = ZeroCopySink::write_u128(u);
        let (data, offset) = ZeroCopySource::next_u128(&buf, offset);

        Debug::print<u128>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<u128>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1003);
    }

    #[test]
    public fun test_zero_copy_bool() {
        let u:bool = true;
        let offset = 0;
        let buf = ZeroCopySink::write_bool(u);
        let (data, offset) = ZeroCopySource::next_bool(&buf, offset);

        Debug::print<bool>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<bool>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1004);
    }


    #[test]
    public fun test_zero_copy_byte() {
//        let u:vector<u8> = x"7f";
        let offset = 0;
        let buf = x"7f";
        let (data, offset) = ZeroCopySource::next_byte(&buf, offset);

        Debug::print<vector<u8>>(&buf);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(buf == data, 1005);
    }

    #[test]
    public fun test_zero_copy_var_bytes() {
        let u:vector<u8> = x"fd725b0325c2bda54cf7e33e3b9f6bc9b7927beb7ba6a2ef5feef7d20b394168";
        let offset = 0;
        let buf = ZeroCopySink::write_var_bytes(&u);
        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);

        Debug::print<vector<u8>>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1006);
    }

    #[test]
    public fun test_zero_copy_var_bytes_2() {
        let u:vector<u8> = x"fd725b0325c2bda54cf7e33e3b9f6bc9b7927beb7ba6a2ef5feef7d20b394168d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505a9302463fd528ce8aca2d5ad58de0622f07e2107c12a780f67c624592bbcc13da0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let offset = 0;
        let buf = ZeroCopySink::write_var_bytes(&u);
        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);

        Debug::print<vector<u8>>(&u);
        Debug::print<vector<u8>>(&buf);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(u == data, 1007);
    }


    public fun zero_copy_sink_combine(): vector<u8> {
        let eth_account = init_eth_account();
        let buf = Vector::empty();

        Debug::print<u64>(&110404);
        let data = ZeroCopySink::write_var_bytes(&eth_account.state_root);
        Debug::print<vector<u8>>(&eth_account.state_root);
        Debug::print<vector<u8>>(&data);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_u64(*&eth_account.height);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_var_bytes(&eth_account.address);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_u128(*&eth_account.balance);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_u64(*&eth_account.nonce);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_var_bytes(&eth_account.code_hash);
        buf = Bytes::concat(&buf, data);

        data = ZeroCopySink::write_var_bytes(&eth_account.storage_hash);
        buf = Bytes::concat(&buf, data);

        buf
    }

    #[test]
    public fun test_zero_copy_source_combine() {
        let eth_account = init_eth_account();
        let buf = zero_copy_sink_combine();

        let offset = 0;
        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.state_root, 1021);

        let (data, offset) = ZeroCopySource::next_u64(&buf, offset);
        Debug::print<u64>(&110333);
        Debug::print<u64>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.height, 1022);

        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.address, 1023);

        let (data, offset) = ZeroCopySource::next_u128(&buf, offset);
        Debug::print<u128>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.balance, 1024);

        let (data, offset) = ZeroCopySource::next_u64(&buf, offset);
        Debug::print<u64>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.nonce, 1025);

        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.code_hash, 1026);

        let (data, offset) = ZeroCopySource::next_var_bytes(&buf, offset);
        Debug::print<vector<u8>>(&data);
        Debug::print<u64>(&offset);
        assert(data == *&eth_account.storage_hash, 1027);
    }


}
}
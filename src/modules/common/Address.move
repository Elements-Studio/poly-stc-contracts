address 0xe52552637c5897a2d499fbf08216f73e {

module Address {
    // use 0x1::Vector;
    use 0x1::BCS;

    public fun bytify(_addr: address): vector<u8> {
        BCS::to_bytes<address>(&_addr)
    }

    public fun addressify(_addr_byte: vector<u8>): address {
        BCS::to_address(_addr_byte)
    }
}
}
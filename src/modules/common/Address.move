address 0xb6d69dd935edf7f2054acf12eb884df8 {

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
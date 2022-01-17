address 0x18351d311d32201149a4df2a9fc2db8a {

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
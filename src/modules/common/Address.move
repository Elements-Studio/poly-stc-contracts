address 0x2d81a0427d64ff61b11ede9085efa5ad {

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
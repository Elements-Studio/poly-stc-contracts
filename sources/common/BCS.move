module Bridge::BCS {
    use starcoin_std::from_bcs;
    use std::bcs;

    public fun to_bytes<MoveValue>(_addr: &MoveValue): vector<u8> {
        bcs::to_bytes<MoveValue>(_addr)
    }

    public fun to_address(_addr_byte: vector<u8>): address {
        from_bcs::from_bytes<address>(_addr_byte)
    }
}
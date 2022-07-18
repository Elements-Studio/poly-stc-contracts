address 0xe52552637c5897a2d499fbf08216f73e {
/// Hash util for SMT.
module SMTHash {
    use 0x1::Hash;
    const SIZE_ZERO_BYTES: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    public fun size(): u64 {
        32
    }

    public fun hash(data: &vector<u8>): vector<u8> {
        Hash::sha3_256(*data)
    }

    public fun size_zero_bytes(): vector<u8> {
        SIZE_ZERO_BYTES
    }
}
}
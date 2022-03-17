address 0x416b32009fe49fcab1d5f2ba0153838f {
/// Hash util for SMT.
module SMTHash {
    use 0x1::Hash;
    const SIZE_ZERO_BYTES: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    public fun size(): u64 {
        32
    }

    public fun sum(data: &vector<u8>): vector<u8> {
        Hash::sha3_256(*data)
    }

    public fun size_zero_bytes(): vector<u8> {
        SIZE_ZERO_BYTES
    }
}
}
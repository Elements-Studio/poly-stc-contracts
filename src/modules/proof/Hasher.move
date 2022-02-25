address 0x18351d311d32201149a4df2a9fc2db8a {
module Hasher {
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
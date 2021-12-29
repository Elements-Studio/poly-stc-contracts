address 0x2d81a0427d64ff61b11ede9085efa5ad {

module MerkleProofElementBits {

    use 0x1::BitOperators;
    use 0x1::Vector;
    use 0x1::Errors;

    const LENGTH: u64 = 32;
    const LENGTH_IN_BITS: u64 = 256;

    const ERROR_GET_HASH_BIT_INVALID_LENGTH: u64 = 101;
    const ERROR_GET_HASH_BIT_INVALID_BIT_LENGTH: u64 = 102;
    const ERROR_GET_HASH_BIT_COMMON_PREFIX_INVALID_LENGTH: u64 = 103;

    /// Input a hash bytes and output a vector that contains all bit
    public fun iter_bits(hash_bytes: &vector<u8>): vector<bool> {
        assert(Vector::length<u8>(hash_bytes) == LENGTH, Errors::invalid_state(ERROR_GET_HASH_BIT_INVALID_LENGTH));

        let i = 0;
        let result_vec = Vector::empty<bool>();
        while (i < LENGTH_IN_BITS) {
            Vector::push_back<bool>(&mut result_vec, get_bit(hash_bytes, i));
            i = i + 1;
        };
        assert(Vector::length<bool>(&result_vec) == LENGTH_IN_BITS, Errors::invalid_state(ERROR_GET_HASH_BIT_INVALID_BIT_LENGTH));
        result_vec
    }

    /// Returns the index-th bit in the bytes.
    public fun get_bit(hash_bytes: &vector<u8>, index: u64): bool {
        let pos = index / 8;
        let bit = ((7 - (index % 8)) as u8);
        let bit_byte = (*Vector::borrow<u8>(hash_bytes, pos) as u64);
        let rshift = BitOperators::rshift(bit_byte, bit);
        BitOperators::and(rshift, 1) != 0
    }

    /// Get common prefix length from 2 hash key
    public fun common_prefix_bits_len<Element: copy + drop>(key1: &vector<Element>,
                                                            key2: &vector<Element>): u64 {
        let keylen = Vector::length<Element>(key1);
        assert(keylen == Vector::length<Element>(key2), Errors::invalid_state(ERROR_GET_HASH_BIT_COMMON_PREFIX_INVALID_LENGTH));
        let idx = 0;
        while (idx < LENGTH_IN_BITS) {
            if (*Vector::borrow(key1, idx) != *Vector::borrow(key2, idx)) {
                break
            };
            idx = idx + 1;
        };
        idx
    }

    /// Default hash length
    public fun hash_length(): u64 {
        LENGTH
    }

    public fun hash_length_in_bits(): u64 {
        LENGTH_IN_BITS
    }
}
}
address 0x18351d311d32201149a4df2a9fc2db8a {
module SMTUtils {
    use 0x1::BitOperators;
    use 0x1::Vector;

    /// Get the bit at an offset from the most significant bit.
    fun get_bit_at_from_msb(data: &vector<u8>, position: u64): bool {
        let byte = (*Vector::borrow<u8>(data, position / 8) as u64);
        let bit = BitOperators::rshift(byte, ((7 - (position % 8)) as u8));
        BitOperators::and(bit, 1) != 0
    }

    fun count_common_prefix(data1: &vector<u8>, data2: &vector<u8>): u64 {
        let count = 0;
        let i = 0;
        while ( i < Vector::length(data1)*8) {
            if (get_bit_at_from_msb(data1, i) == get_bit_at_from_msb(data2, i)) {
                count = count+1;
            } else {
                break
            };
            i = i+1;
        };
        count
    }

    public fun bits_to_bool_vector_from_msb(data: &vector<u8>): vector<bool> {
        let i = 0;
        let vec = Vector::empty<bool>();
        while (i < Vector::length(data)) {
            Vector::push_back<bool>(&mut vec, get_bit_at_from_msb(data, i));
            i = i + 1;
        };
        vec
    }
}
}

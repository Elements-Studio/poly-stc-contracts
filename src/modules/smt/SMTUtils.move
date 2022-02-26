address 0x18351d311d32201149a4df2a9fc2db8a {
module SMTUtils {
    use 0x1::BitOperators;
    use 0x1::Vector;
    use 0x1::Errors;

    const ERROR_VECTORS_NOT_SAME_LENGTH: u64 = 103;
    const BIT_RIGHT: bool = true;
    const BIT_LEFT: bool = false;


    /// Get the bit at an offset from the most significant bit.
    public fun get_bit_at_from_msb(data: &vector<u8>, position: u64): bool {
        let byte = (*Vector::borrow<u8>(data, position / 8) as u64);
        let bit = BitOperators::rshift(byte, ((7 - (position % 8)) as u8));
        if (BitOperators::and(bit, 1) != 0) {
            BIT_RIGHT
        } else {
            BIT_LEFT
        }
    }

    public fun count_common_prefix(data1: &vector<u8>, data2: &vector<u8>): u64 {
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

    public fun count_vector_common_prefix<ElementT: copy + drop>(vec1: &vector<ElementT>,
                                                                 vec2: &vector<ElementT>): u64 {
        let vec_len = Vector::length<ElementT>(vec1);
        assert(vec_len == Vector::length<ElementT>(vec2), Errors::invalid_state(ERROR_VECTORS_NOT_SAME_LENGTH));
        let idx = 0;
        while (idx < vec_len) {
            if (*Vector::borrow(vec1, idx) != *Vector::borrow(vec2, idx)) {
                break
            };
            idx = idx + 1;
        };
        idx
    }

    public fun bits_to_bool_vector_from_msb(data: &vector<u8>): vector<bool> {
        let i = 0;
        let vec = Vector::empty<bool>();
        while (i < Vector::length(data)*8) {
            Vector::push_back<bool>(&mut vec, get_bit_at_from_msb(data, i));
            i = i + 1;
        };
        vec
    }

    public fun concat_u8_vectors(v1: &vector<u8>, v2: vector<u8>): vector<u8> {
        let data = *v1;
        Vector::append(&mut data, v2);
        data
    }

    public fun sub_u8_vector(vec: &vector<u8>, start: u64, end: u64): vector<u8> {
        let i = start;
        let result = Vector::empty<u8>();
        let data_len = Vector::length(vec);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end) {
            Vector::push_back(&mut result, *Vector::borrow(vec, i));
            i = i + 1;
        };
        result
    }

    public fun sub_vector<ElementT: copy>(vec: &vector<ElementT>, start: u64, end: u64): vector<ElementT> {
        let i = start;
        let result = Vector::empty<ElementT>();
        let data_len = Vector::length(vec);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end) {
            Vector::push_back(&mut result, *Vector::borrow(vec, i));
            i = i + 1;
        };
        result
    }

}
}

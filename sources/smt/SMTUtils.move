module Bridge::SMTUtils {
    use StarcoinFramework::BitOperators;
    use StarcoinFramework::Vector;
    use StarcoinFramework::Errors;

    spec module {
        pragma verify = true;
    }

    const ERROR_VECTORS_NOT_SAME_LENGTH: u64 = 103;
    const BIT_RIGHT: bool = true;
    const BIT_LEFT: bool = false;


    // Get the bit at an offset from the most significant bit.
    public fun get_bit_at_from_msb(data: &vector<u8>, position: u64): bool {
        let byte = (*Vector::borrow<u8>(data, position / 8) as u64);
        let bit = BitOperators::rshift(byte, ((7 - (position % 8)) as u8));
        if (BitOperators::and(bit, 1) != 0) {
            BIT_RIGHT
        } else {
            BIT_LEFT
        }
    }

    spec get_bit_at_from_msb {
        aborts_if len(data) == 0;
        aborts_if position / 8 >= len(data);
    }

    public fun count_common_prefix(data1: &vector<u8>, data2: &vector<u8>): u64 {
        let count = 0;
        let i = 0;
        while ({
            spec {
                invariant i <= len(data1)*8;
            };
            i < Vector::length(data1)*8
        }) {
            if (get_bit_at_from_msb(data1, i) == get_bit_at_from_msb(data2, i)) {
                count = count+1;
            } else {
                break
            };
            i = i+1;
        };
        count
    }

    spec count_common_prefix {
        pragma addition_overflow_unchecked;
    }

    public fun count_vector_common_prefix<ElementT: copy + drop>(vec1: &vector<ElementT>,
                                                                 vec2: &vector<ElementT>): u64 {
        let vec_len = Vector::length<ElementT>(vec1);
        assert!(vec_len == Vector::length<ElementT>(vec2), Errors::invalid_state(ERROR_VECTORS_NOT_SAME_LENGTH));
        let idx = 0;
        while ({
            spec {
                invariant idx <= len(vec1);
            };
            idx < vec_len
        }) {
            if (*Vector::borrow(vec1, idx) != *Vector::borrow(vec2, idx)) {
                break
            };
            idx = idx + 1;
        };
        idx
    }

    spec count_vector_common_prefix {
        pragma addition_overflow_unchecked;
        aborts_if len(vec1) != len(vec2);
    }

    public fun bits_to_bool_vector_from_msb(data: &vector<u8>): vector<bool> {
        let i = 0;
        let vec = Vector::empty<bool>();
        while ({
            spec {
                invariant i <= len(data)*8;
                invariant len(vec) == i;
            };
            i < Vector::length(data)*8
        }) {
            Vector::push_back<bool>(&mut vec, get_bit_at_from_msb(data, i));
            i = i + 1;
        };
        vec
    }

    spec bits_to_bool_vector_from_msb {
        pragma addition_overflow_unchecked;
        ensures len(result) == 8 * len(data);
    }

    public fun concat_u8_vectors(v1: &vector<u8>, v2: vector<u8>): vector<u8> {
        let data = *v1;
        Vector::append(&mut data, v2);
        data
    }

    spec concat_u8_vectors {
        ensures result == concat<u8>(v1, v2);
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
        while ({
            spec {
                invariant result == vec[start..i];
            };
            i < actual_end
        }) {
            Vector::push_back(&mut result, *Vector::borrow(vec, i));
            i = i + 1;
        };
        result
    }

    spec fun min(end: u64, data_len: u64 ): u64 {
        if (end < data_len) {
            end
        }else {
            data_len
        }
    }

    spec sub_u8_vector {
        pragma verify;
        pragma addition_overflow_unchecked;
        ensures result == vec[start..min(end,len(vec))];
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
        while ({
            spec {
                invariant result == vec[start..i];
            };
            i < actual_end
        }) {
            Vector::push_back(&mut result, *Vector::borrow(vec, i));
            i = i + 1;
        };
        result
    }

    spec sub_vector {
        pragma verify;
        pragma addition_overflow_unchecked;
        ensures result == vec[start..min(end,len(vec))];
    }
}
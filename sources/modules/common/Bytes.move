    address NamedAddr {
module Bytes {
    use StarcoinFramework::Vector;
    use StarcoinFramework::BitOperators;

    /// left shift n bits.
    public fun lshift_u128(x: u128, n: u8): u128 {
        (x << n)
    }

    /// right shift n bits.
    public fun rshift_u128(x: u128, n: u8): u128 {
        (x >> n)
    }

    public fun slice(data: &vector<u8>, start: u64, end: u64): vector<u8> {
        let i = start;
        let result = Vector::empty<u8>();
        let data_len = Vector::length(data);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end) {
            Vector::push_back(&mut result, *Vector::borrow(data, i));
            i = i + 1;
        };
        result
    }

    public fun slice_range_with_template<Element: copy>(data: &vector<Element>, start: u64, end: u64): vector<Element> {
        let i = start;
        let result = Vector::empty<Element>();
        let data_len = Vector::length(data);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end) {
            Vector::push_back(&mut result, *Vector::borrow(data, i));
            i = i + 1;
        };
        result
    }

    public fun concat(v1: &vector<u8>, v2: vector<u8>): vector<u8> {
        let data = *v1;
        Vector::append(&mut data, v2);
        data
    }

    public fun get_bit(data: &vector<u8>, index: u64): bool {
        let pos = index / 8;
        let bit = (7 - index % 8);
        (*Vector::borrow(data, pos) >> (bit as u8)) & 1u8 != 0
    }

    public fun bytes_to_u64(data: &vector<u8>): u64 {
        let number: u64 = 0;
        let i = 0;
        let len = Vector::length(data);
        while (i < len) {
            let slice = *Vector::borrow(data, i);
            let bit = (len - (i + 1) as u8);
            //BitOperators::lshift return only u64
            number = number + BitOperators::lshift((slice as u64), bit * 8);
            i = i + 1;
        };
        number
    }

    /// big endian cast
    public fun bytes_to_u128(data: &vector<u8>): u128 {
        let number: u128 = 0;
        let i = 0;
        let len = Vector::length(data);
        while (i < len) {
            let slice = *Vector::borrow(data, i);
            let bit = (len - (i + 1) as u8);
            number = number + lshift_u128((slice as u128), bit * 8);
            i = i + 1;
        };
        number
    }

    /// little endian cast
    public fun bytes_reverse_to_u128(data: &vector<u8>): u128 {
        let number: u128 = 0;
        let len = Vector::length(data);
        if (len > 0){
            let i = len - 1;
            loop {
                let slice = *Vector::borrow(data, i);
                let bit = (i as u8);
                number = number + lshift_u128((slice as u128), bit * 8);
                if( i == 0){
                    break
                };
                i = i - 1;
            };
        };
        number
    }

    public fun left_padding(data: &vector<u8>, total_len: u64): vector<u8>{
        let origin_len = Vector::length(data);
        if (origin_len < total_len){
            let padding_bytes = create_zero_bytes(total_len - origin_len);
            data = &concat(&padding_bytes, *data);
        };
        *data
    }

    public fun right_padding(data: &vector<u8>, total_len: u64): vector<u8>{
        let origin_len = Vector::length(data);
        if (origin_len < total_len){
            let padding_bytes = create_zero_bytes(total_len - origin_len);
            data = &concat(data, padding_bytes);
        };
        *data
    }

    public fun create_zero_bytes(len: u64): vector<u8> {
        let i = 0 ;
        let bytes = Vector::empty();
        while (i < len) {
            bytes = concat(&bytes, x"00");
            i = i + 1;
        };
        bytes
    }

}
}
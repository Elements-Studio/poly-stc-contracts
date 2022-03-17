address 0xb6d69dd935edf7f2054acf12eb884df8 {
module BytesTest {
    use 0xb6d69dd935edf7f2054acf12eb884df8::Bytes;
    use 0x1::Debug::{Self};
    use 0x1::Vector;
    use 0x1::BCS;

    public fun slice(data: &vector<u8>, start: u64, end: u64): vector<u8> {
        let i = start;
        let result = Vector::empty<u8>();
        let data_len = Vector::length(data);
        let actual_end = if (end < data_len) {
            end
        } else {
            data_len
        };
        while (i < actual_end){
            Vector::push_back(&mut result, *Vector::borrow(data, i));
            i = i + 1;
        };
        result
    }

    #[test]
    public fun test_bytes_to_u128() {
//        let hex:vector<u8> = x"98234aed82"; //653427142018
        let hex:vector<u8> = x"014e95f5a48100"; //8955205
        let number = Bytes::bytes_to_u128(&hex);
        Debug::print<u128>(&number);
//        assert(number == 653427142018, 1001);
        assert(number == 367880955003136, 1001);
    }

//    #[test, expected_failure(abort_code = 1)] //
    #[test, expected_failure]
    public fun test_cast_hex_u128_overflow() {
        let hex:vector<u8> = x"c4c8b2db715e9f7e1d3306b9f6860a389635dfb3943db13f1005544a50fbb2"; //
        let number = Bytes::bytes_to_u128(&hex);
        Debug::print<u128>(&number);
//        assert(number == 367880955003136, 1001);
    }

    #[test]
    public fun test_cast_hex_u128_bound() {
        let hex:vector<u8> = x"00"; //
        let number = Bytes::bytes_to_u128(&hex);
        Debug::print<u128>(&number);
    }

    #[test]
    public fun test_bytes_reverse_to_u128() {
        let hex:vector<u8> = x"014e95f5a48100"; //367880955003136
        let number = Bytes::bytes_to_u128(&hex);
        Debug::print(&hex);
        Vector::reverse(&mut hex);
        Debug::print(&hex);
        let reverse_number = Bytes::bytes_reverse_to_u128(&hex);
        Debug::print<u128>(&number);
        Debug::print<u128>(&reverse_number);
        assert(number == 367880955003136, 1001);
        assert(number == reverse_number, 1002);
    }

    #[test]
    public fun test_vector() {
        let hex:vector<u8> = x"014e95f5a48100"; //
        let hex1:vector<u8> = x"01"; //
        let hex2:vector<u8> = x"0166"; //
//        let len = Vector::length(&hex);
        Debug::print<u64>(&Vector::length(&hex));
        Debug::print<u64>(&Vector::length(&hex1));
        Debug::print<u64>(&Vector::length(&hex2));
        Debug::print<vector<u8>>(&hex);
        Debug::print<vector<u8>>(&slice(&hex, 1,12));
    }

    #[test]
    public fun test_bcs_cmp() {
        let hex1:vector<u8> = x"80"; //
        let hex2:vector<u8> = x"0305c9"; //
        let hex3:vector<u8> = x"0305c9"; //
        let data1 = BCS::to_bytes<u8>(&128u8);
        let data2 = BCS::to_bytes<u128>(&198089u128);
        let data3 = BCS::to_bytes<u64>(&198089u64);
        Debug::print<vector<u8>>(&hex1);
        Debug::print<vector<u8>>(&data1);
        Debug::print<vector<u8>>(&hex2);
        Debug::print<vector<u8>>(&data2);
        Debug::print<vector<u8>>(&hex3);
        Debug::print<vector<u8>>(&data3);
        assert(data1 == hex1, 1003);
        assert(data2 != copy hex2, 1004);
        assert(data3 != hex3, 1005);

        Debug::print<u128>(&(Bytes::bytes_to_u128(&hex2)));
    }

    #[test]
    public fun test_padding() {
        let hex:vector<u8> = x"01234f";
        let _hex_left:vector<u8> = x"000000000001234f";
        let _hex_right:vector<u8> = x"01234f0000000000";
        let left_padding_bytes = Bytes::left_padding(&hex, 8);
        let right_padding_bytes = Bytes::right_padding(&hex, 8);
        assert(_hex_left == copy left_padding_bytes, 1007);
        assert(_hex_right == copy right_padding_bytes, 1008);
        Debug::print<vector<u8>>(&left_padding_bytes);
        Debug::print<vector<u8>>(&right_padding_bytes);
    }

    #[test]
    public fun test_bytes_equal() {
        let hex:vector<u8> = x"01234f";
        let hex2:vector<u8> = Bytes::concat(&x"01", x"234f");
        assert(copy hex == copy hex2, 1009);
        assert(&hex ==  &hex2, 1011);
    }

    #[test]
    public fun test_bcs_address() {
        //let addr = x"344CFC3B8635F72F14200AAF2168D9F75DF86FD3000000000000000000000000";
        let addr1 = x"344CFC3B8635F72F14200AAF2168D9F7";
        let converted_addr = BCS::to_address(addr1);
        Debug::print(&converted_addr);
        assert(converted_addr != @0x01, 1001);
    }

    /// Using python convert decimal array to hex string
    /// ```
    /// ''.join(str(e) for e in [('%02X' % x) for x in [247, 27, 85, 239, 85, 206, 220, 145, 253, 0, 127, 122, 155, 163, 134, 236, 151, 143, 58, 168]])
    /// ```
    #[test]
    public fun test_bcs_equals1() {
        //let addr = x"344CFC3B8635F72F14200AAF2168D9F75DF86FD3000000000000000000000000";
        let bcs1 = x"F71B55EF55CEDC91FD007F7A9BA386EC978F3AA8";
        Debug::print(&bcs1);
    }


}
}
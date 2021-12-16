
address 0x2d81a0427d64ff61b11ede9085efa5ad {
/// Wrappers over decoding and deserialization operation from bytes into basic types in Move for PolyNetwork cross chain utility.
/// Decode into basic types in Move from bytes easily. It's designed to be used
/// for PolyNetwork cross chain application, and the decoding rules on Starcoin chain
/// and the encoding rule on other chains should be consistent, and . Here we
/// follow the underlying deserialization rule with implementation found here:
/// https://github.com/polynetwork/poly/blob/master/common/zero_copy_source.go
/// Using this library instead of the unchecked serialization method can help reduce
/// the risk of serious bugs and handfule, so it's recommended to use it.
/// Please note that risk can be minimized

module ZeroCopySource {
    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;
    use 0x1::Vector;
    use 0x1::Errors;

    const HEX_0XFD:vector<u8> = x"FD";
    const HEX_0XFFFF:vector<u8> = x"FFFF";
    const HEX_0XFFFFFFFF:vector<u8> = x"FFFFFFFF";
    const NUMBER_0XFD:u64 = 253;
    const NUMBER_0XFFFF:u64 = 65535;
    const NUMBER_0XFFFFFFFF:u64 = 4294967295;
    const U32_BYTES_LEN:u64 = 4;
    const U16_BYTES_LEN:u64 = 2;

    const ERR_NEXT_BYTE_OFFSET_EXCEED: u64 = 201;  //NextByte, offset exceeds maximum
    const ERR_NEXT_BOOl_OFFSET_EXCEED: u64 = 202;  //NextBool, offset exceeds maximum
    const ERR_NEXT_U8_OFFSET_EXCEED: u64 = 203;  //NextU8, offset exceeds maximum
    const ERR_NEXT_U16_OFFSET_EXCEED: u64 = 204;  //NextU16, offset exceeds maximum
    const ERR_NEXT_U32_OFFSET_EXCEED: u64 = 205;  //NextU32, offset exceeds maximum
    const ERR_NEXT_U64_OFFSET_EXCEED: u64 = 206;  //NextU64, offset exceeds maximum
    const ERR_NEXT_U128_OFFSET_EXCEED: u64 = 207;  //NextU128, offset exceeds maximum
    const ERR_NEXT_U256_OFFSET_EXCEED: u64 = 208;  //NextU256, offset exceeds maximum
    const ERR_NEXT_VAR_BYTES_OFFSET_EXCEED: u64 = 209;  //NextVarBytes, offset exceeds maximum
    const ERR_NEXT_BYTES_OFFSET_EXCEED: u64 = 210;  //NextBytes, offset exceeds maximum
    const ERR_NEXT_HASH_OFFSET_EXCEED: u64 = 211;  //NextHash, offset exceeds maximum

    const ERR_NEXT_U8_OUTSIDE_RANGE: u64 = 221;  //NextU8, value outside range
    const ERR_NEXT_U16_OUTSIDE_RANGE: u64 = 222;  //NextU16, value outside range
    const ERR_NEXT_U32_OUTSIDE_RANGE: u64 = 223;  //NextU32, value outside range
    const ERR_NEXT_U64_OUTSIDE_RANGE: u64 = 224;  //NextU64, value outside range


    ///  @notice              Read next byte as bool type starting at offset from data
    ///  @param data          Source bytes array
    ///  @param offset        The position from where we read the bool value
    ///  @return              The the read bool value and new offset
    public fun next_bool(data: &vector<u8>, offset: u64) : (bool, u64) {
        assert(((offset + 1) <= Vector::length(data)) && (offset < offset + 1 ), Errors::invalid_state(ERR_NEXT_BYTE_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 1);
        let v = Bytes::bytes_to_u64(&data_slice);
        if (v == 1){
            (true, offset + 1)
        } else if (v == 0){
            (false, offset + 1)
        } else {
            abort 215 //NextBool value error
        }
    }


    /// @notice              Read next byte starting at offset from data
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the byte value
    /// @return              The read byte value and new offset
    public fun next_byte(data: &vector<u8>, offset: u64) : (vector<u8>, u64) {
        assert((offset + 1 <= Vector::length(data)) && (offset < offset + 1 ), Errors::invalid_state(ERR_NEXT_BYTE_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 1);
        (data_slice, offset + 1)
    }


    /// @notice              Read next byte as u8 starting at offset from data
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the byte value
    /// @return              The read u8 value and new offset
    public fun next_u8(data: &vector<u8>, offset: u64) : (u8, u64) {
        assert((offset + 1 <= Vector::length(data)) && (offset < offset + 1 ), Errors::invalid_state(ERR_NEXT_U8_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 1);
        let v = Bytes::bytes_to_u64(&data_slice);
        ((v as u8), offset + 1)
    }


    /// @notice              Read next two bytes as u16 type starting from offset
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the u16 value
    /// @return              The read (u16 as u64) value and updated offset
    public fun next_u16(data: &vector<u8>, offset: u64) : (u64, u64) {
        assert((offset + 2 <= Vector::length(data)) && (offset < offset + 2 ), Errors::invalid_state(ERR_NEXT_U16_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 2);
        //little endian reserve to big endian
        let v = Bytes::bytes_reverse_to_u128(&data_slice);
        ((v as u64), offset + 2)
    }


    /// @notice              Read next four bytes as u32 type starting from offset
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the u32 value
    /// @return              The read (u32 as u64) value and updated offset
    public fun next_u32(data: &vector<u8>, offset: u64) : (u64, u64) {
        assert((offset + 4 <= Vector::length(data)) && (offset < offset + 4 ), Errors::invalid_state(ERR_NEXT_U32_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 4);
        //little endian reserve to big endian
        let v = Bytes::bytes_reverse_to_u128(&data_slice);
        ((v as u64), offset + 4)
    }


    /// @notice              Read next eight bytes as u64 type starting from offset
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the u64 value
    /// @return              The read u64 value and updated offset
    public fun next_u64(data: &vector<u8>, offset: u64) : (u64, u64) {
        assert((offset + 8 <= Vector::length(data)) && (offset < offset + 8 ), Errors::invalid_state(ERR_NEXT_U64_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 8);
        //little endian reserve to big endian
        let v = Bytes::bytes_reverse_to_u128(&data_slice);
        ((v as u64), offset + 8)
    }


    /// @notice              Read next eight bytes as u128 type starting from offset
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the u64 value
    /// @return              The read u128 value and updated offset
    public fun next_u128(data: &vector<u8>, offset: u64) : (u128, u64) {
        assert((offset + 16 <= Vector::length(data)) && (offset < offset + 16), Errors::invalid_state(ERR_NEXT_U128_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 16);
        //little endian reserve to big endian
        let v = Bytes::bytes_reverse_to_u128(&data_slice);
        (v, offset + 16)
    }


    /// @notice              Read next 32 bytes as u256 type starting from offset,
    ///                      there are limits considering the numerical limits in multi-chain
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the u256 value
    /// @return              The read u256 value and updated offset
    public fun next_u256(data: &vector<u8>, offset: u64) : (u128, u64) {
        assert((offset + 32 <= Vector::length(data)) && (offset < offset + 32 ), Errors::invalid_state(ERR_NEXT_U256_OFFSET_EXCEED));
        // TODO little endian encoding, when force transform may loss high 16-byte precision
        let data_slice = Bytes::slice(data, offset, offset + 16);
        //little endian reserve to big endian
//        Vector::reverse(&mut data_slice);
        let v = Bytes::bytes_reverse_to_u128(&data_slice);
        (v, offset + 32)
    }

    /// @notice              Read next 32 bytes starting from offset,
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the bytes value
    /// @return              The read bytes32 value and updated offset
    public fun next_hash(data: &vector<u8>, offset: u64) : (vector<u8>, u64) {
        assert((offset + 32 <= Vector::length(data)) && (offset < offset + 32), Errors::invalid_state(ERR_NEXT_HASH_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + 32);
        (data_slice, offset + 32)
    }


    /// @notice              Read next len bytes starting from offset,
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the bytes value
    /// @return              The read {len} bytes value and updated offset
    public fun next_bytes(data: &vector<u8>, offset: u64, len: u64) : (vector<u8>, u64) {
        assert((offset + len <= Vector::length(data)) && (offset < offset + len), Errors::invalid_state(ERR_NEXT_BYTES_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + len);
        (data_slice, offset + len)
    }


    /// @notice              Read next variable bytes starting from offset,
    ///                      the decoding rule coming from multi-chain
    /// @param data          Source bytes array
    /// @param offset        The position from where we read the bytes value
    /// @return              The read variable bytes array value and updated offset
    public fun next_var_bytes(data: &vector<u8>, offset: u64) : (vector<u8>, u64) {
        let (len, offset) = next_var_uint(data, offset);
        assert((offset + len <= Vector::length(data)) && (offset < offset + len), Errors::invalid_state(ERR_NEXT_VAR_BYTES_OFFSET_EXCEED));
        let data_slice = Bytes::slice(data, offset, offset + len);
        (data_slice, offset + len)
    }


    public fun next_var_uint(data: &vector<u8>, offset: u64) : (u64, u64) {
        let (byte, offset) = next_byte(data, offset);
        // var u16 encode
        if (copy byte == x"FD"){
            let (v, offset) = next_u16(data, offset);
            assert(v >= NUMBER_0XFD && v <= NUMBER_0XFFFF, ERR_NEXT_U16_OUTSIDE_RANGE);
            (v, offset)
        // var u32 encode
        } else if (copy byte == x"FE"){
            let (v, offset) = next_u32(data, offset);
            assert(v > NUMBER_0XFFFF && v <= NUMBER_0XFFFFFFFF, ERR_NEXT_U32_OUTSIDE_RANGE);
            (v, offset)
        // var u64 encode
        } else if (copy byte == x"FF"){
            let (v, offset) = next_u64(data, offset);
            assert(v > NUMBER_0XFFFFFFFF, ERR_NEXT_U64_OUTSIDE_RANGE);
            (v, offset)
        // var u8 encode
        } else {
            let v = Bytes::bytes_to_u64(&byte);
            assert(v < NUMBER_0XFD, ERR_NEXT_U8_OUTSIDE_RANGE);
            (v, offset)
        }
    }

}
}
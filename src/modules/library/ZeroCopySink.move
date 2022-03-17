address 0xb6d69dd935edf7f2054acf12eb884df8 {
/// Wrappers over encoding and serialization operation into bytes from basic types in Move for PolyNetwork cross chain utility.
/// Encode basic types in Move into bytes easily. It's designed to be used
/// for PolyNetwork cross chain application, and the encoding rules on Starcoin chain
/// and the decoding rules on other chains should be consistent. Here we
/// follow the underlying serialization rule with implementation found here:
/// https://github.com/polynetwork/poly/blob/master/common/zero_copy_sink.go
/// Using this library instead of the unchecked serialization method can help reduce
/// the risk of serious bugs and handfule, so it's recommended to use it.
/// Please note that risk can be minimized, yet not eliminated.

module ZeroCopySink {
    use 0xb6d69dd935edf7f2054acf12eb884df8::Bytes;
    use 0x1::Vector;
    use 0x1::BCS;

    const HEX_0XFD:vector<u8> = x"FD";
    const HEX_0XFFFF:vector<u8> = x"FFFF";
    const HEX_0XFFFFFFFF:vector<u8> = x"FFFFFFFF";
    const NUMBER_0XFD:u64 = 253;
    const NUMBER_0XFFFF:u64 = 65535;
    const NUMBER_0XFFFFFFFF:u64 = 4294967295;

    const U32_BYTES_LEN:u64 = 4;
    const U16_BYTES_LEN:u64 = 2;


   /// @notice          Convert bool value into bytes
   /// @param data      The bool value
   /// @return          Converted bytes array
    public fun write_bool(data: bool) : vector<u8> {
        let buf = Vector::empty<u8>();
        if (data) {
            Vector::append(&mut buf, x"01");
        } else {
            Vector::append(&mut buf, x"00");
        };
        buf
    }

//    public fun write_byte(data: vector<u8>) : vector<u8> {
//        let buf = Vector::empty<u8>();
//        Vector::append(&mut buf, data);
//        buff
//    }

   /// @notice          Convert u8 value into bytes
   /// @param data      The u8 value
   /// @return          Converted bytes array
    public fun write_u8(data: u8) : vector<u8> {
        let data_bytes = BCS::to_bytes<u8>(&data);
        data_bytes
    }


   /// @notice          Convert u16 value into bytes
   /// @param data      The u64 value
   /// @return          Converted bytes array
    public fun write_u16(data: u64) : vector<u8> {
        let buf = BCS::to_bytes<u64>(&data);
        Bytes::slice(&buf, 0, U16_BYTES_LEN)
    }


   /// @notice          Convert u32 value into bytes
   /// @param data        The u64 value
   /// @return          Converted bytes array
    public fun write_u32(data: u64) : vector<u8> {
        let buf = BCS::to_bytes<u64>(&data);
        Bytes::slice(&buf, 0, U32_BYTES_LEN)
    }


   /// @notice          Convert u64 value into bytes
   /// @param data      The u64 value
   /// @return          Converted bytes array
    public fun write_u64(data: u64) : vector<u8> {
        let buf = BCS::to_bytes<u64>(&data);
        buf
    }


   /// @notice          Convert limited u128 value into bytes
   /// @param data      The u128 value bsc::to_bytes()
   /// @return          Converted bytes array
    public fun write_u128(data: u128) : vector<u8> {
        let buf = BCS::to_bytes<u128>(&data);
        buf
    }


   /// @notice          Convert limited u256 value into bytes
   /// @param data      The u128 value bsc::to_bytes()
   /// @return          Converted bytes array
    public fun write_u256(data: vector<u8>) : vector<u8> {
//        let buf = BCS::to_bytes<u128>(&data);
        let little_endian_padding = x"00000000000000000000000000000000";
        Bytes::concat(&data, little_endian_padding)
    }


   /// @notice          Encode bytes format data into bytes
   /// @param data      The bytes array data
   /// @return          Encoded bytes array
    public fun write_var_bytes(data: &vector<u8>) : vector<u8> {
        let len = Vector::length(data);
        let var_uint_bytes = write_var_uint(len);
        Bytes::concat(&var_uint_bytes, *data)
    }


    public fun write_var_uint(data: u64) : vector<u8> {
//        let data_bytes = BCS::to_bytes<u64>(&data);
        // var u8 encode
        if (data < NUMBER_0XFD){
            write_u8((data as u8))
        // var u16 encode
        } else if (data <= NUMBER_0XFFFF) {
            let buf = write_u64(data);
            Bytes::concat(&x"FD", Bytes::slice(&buf, 0, U16_BYTES_LEN))
        // var u32 encode
        } else if (data <= NUMBER_0XFFFFFFFF) {
            let buf = write_u64(data);
            Bytes::concat(&x"FE", Bytes::slice(&buf, 0, U32_BYTES_LEN))
        // var u64 encode
        } else {
            Bytes::concat(&x"FF", write_u64(data))
        }
    }
}
}
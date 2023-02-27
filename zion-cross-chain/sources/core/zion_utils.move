module Bridge::zion_utils {

    use StarcoinFramework::Vector;
    use Bridge::Bytes;

    const EUNSUPPORT_GENERIC_TYPE: u64 = 1;
    const EINVALID_FROM_BYTES_TO_BOOL: u64 = 2;
    const EINVALID_FROM_BYTES_TO_U8: u64 = 3;
    const EINVALID_FROM_BYTES_TO_U64: u64 = 4;
    const EINVALID_FROM_BYTES_TO_U128: u64 = 5;

    public fun slice<Element: copy>(v: &vector<Element>, offset: u64, length: u64): vector<Element> {
        let res = Vector::empty<Element>();
        while ( length > 0 ) {
            length = length - 1;
            let t = *Vector::borrow<Element>(v, offset);
            Vector::push_back<Element>(&mut res, t);
            offset = offset + 1;
        };
        return res
    }

    public fun right_padding<Element: copy + drop>(v: &mut vector<Element>, cnt: u64, element: Element) {
        while (cnt > 0) {
            cnt = cnt - 1;
            Vector::push_back(v, copy element);
        };
    }

    public fun left_padding<Element: copy + drop>(v: &mut vector<Element>, cnt: u64, element: Element) {
        Vector::reverse(v);
        right_padding<Element>(v, cnt, copy element);
        Vector::reverse(v);
    }

    public fun to_bool(v: vector<u8>): bool {
        return Bytes::bytes_to_bool(&v)
    }

    public fun to_u8(v: vector<u8>): u8 {
        return Bytes::bytes_to_u8(&v)
    }

    //
    public fun to_u64(v: vector<u8>): u64 {
        return Bytes::bytes_to_u64(&v)
    }
    //
    public fun to_u128(v: vector<u8>): u128 {
        return Bytes::bytes_to_u128(&v)
    }

    // public fun to_address(v: vector<u8>): address {
    //     return BCS::to_address(v)
    // }
    //
    // public fun to_string(v: vector<u8>): vector<u8> {
    //     return from_bcs::to_string(v)
    // }
    // public fun from_bytes<T>(v: vector<u8>): T {
    //     let type = type_info::type_name<T>();
    //     if (type == string::utf8(b"bool")) {
    //         let res = from_bcs::to_bool(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else if (type == string::utf8(b"u8")) {
    //         let res = from_bcs::to_u8(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else if (type == string::utf8(b"u64")) {
    //         let res = from_bcs::to_u64(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else if (type == string::utf8(b"u128")) {
    //         let res = from_bcs::to_u128(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else if (type == string::utf8(b"address")) {
    //         let res = from_bcs::to_address(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else if (type == string::utf8(b"0x1::string::String")) {
    //         let res = from_bcs::to_string(v);
    //         return any::unpack<T>(any::pack(res))
    //     } else {
    //         abort EUNSUPPORT_GENERIC_TYPE
    //     }
    // }
}
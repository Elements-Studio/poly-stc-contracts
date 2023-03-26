module Bridge::zero_copy_source {

    use StarcoinFramework::Vector;
    use Bridge::zion_utils;

    public fun next_bool(bs: &vector<u8>, offset: u64): (bool, u64) {
        let res = *Vector::borrow<u8>(bs, offset);
        return (zion_utils::to_bool(vector<u8>[res]), offset + 1)
    }

    public fun next_byte(bs: &vector<u8>, offset: u64): (u8, u64) {
        let res = *Vector::borrow<u8>(bs, offset);
        return (res, offset + 1)
    }

    public fun next_u8(bs: &vector<u8>, offset: u64): (u8, u64) {
        let res = *Vector::borrow<u8>(bs, offset);
        return (res, offset + 1)
    }

    public fun next_u32(bs: &vector<u8>, offset: u64): (u32, u64) {
        let res = zion_utils::slice<u8>(bs, offset, 4);
        return (zion_utils::to_u32(res), offset + 4)
    }

    public fun next_u64(bs: &vector<u8>, offset: u64): (u64, u64) {
        let res = zion_utils::slice<u8>(bs, offset, 8);
        return (zion_utils::to_u64(res), offset + 8)
    }

    public fun next_u256(bs: &vector<u8>, offset: u64): (u256, u64) {
        let res = zion_utils::slice<u8>(bs, offset, 32);
        return (zion_utils::to_u256(res), offset + 32)
    }

    public fun next_hash(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        return (zion_utils::slice<u8>(bs, offset, 32), offset + 32)
    }

    public fun next_bytes20(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        return (zion_utils::slice<u8>(bs, offset, 20), offset + 20)
    }

    public fun next_var_bytes(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        let length: u64;
        (length, offset) = next_var_uint(bs, offset);
        return (zion_utils::slice<u8>(bs, offset, length), offset + length)
    }

    public fun next_var_uint(bs: &vector<u8>, offset: u64): (u64, u64) {
        let prefix = *Vector::borrow<u8>(bs, offset);
        if (prefix < 0xFD) {
            return ((prefix as u64), offset + 1)
        } else if (prefix == 0xFD) {
            let b_0 = (*Vector::borrow<u8>(bs, offset + 1) as u64);
            let b_1 = (*Vector::borrow<u8>(bs, offset + 2) as u64);
            let res = b_0 + (b_1 << 8);
            return (res, offset + 3)
        } else if (prefix == 0xFE) {
            let b_0 = (*Vector::borrow<u8>(bs, offset + 1) as u64);
            let b_1 = (*Vector::borrow<u8>(bs, offset + 2) as u64);
            let b_2 = (*Vector::borrow<u8>(bs, offset + 3) as u64);
            let b_3 = (*Vector::borrow<u8>(bs, offset + 4) as u64);
            let res = b_0 + (b_1 << 8) + (b_2 << 16) + (b_3 << 24);
            return (res, offset + 5)
        } else {
            return next_u64(bs, offset + 1)
        }
    }
}
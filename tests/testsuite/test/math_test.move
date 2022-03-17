//! account: alice, 10000000000000 0x1::STC::STC

//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::Math;
    use 0x1::Debug;
    use 0xb6d69dd935edf7f2054acf12eb884df8::SafeMath;

    // case : x*y/z overflow
    fun math_overflow(_: signer) {
        let precision: u8 = 18;
        let scaling_factor = Math::pow(10, (precision as u64));
        let x: u128 = 1000000000;
        let z: u128 = 50000;
        let y: u128 = 20000000 * scaling_factor;

        let amount_y_1 = SafeMath::safe_mul_div(x, z, y);
        let amount_y_2 = SafeMath::safe_mul_div(x, y, z);
        Debug::print<u128>(&amount_y_1);
        Debug::print<u128>(&amount_y_2);
        assert(amount_y_1 <= 0, 3003);
        assert(amount_y_2 > 0, 3004);
    }
}
// check: EXECUTED


//! new-transaction
//! sender: alice
address alice = {{alice}};
script {
    use 0x1::BCS;
    use 0x1::Debug;
//    use 0xb6d69dd935edf7f2054acf12eb884df8::Bytes;
    use 0x1::Vector;

    // case : x*y/z overflow
    fun bcs_test_u64(_: signer) {
        let x1 = BCS::to_bytes<u128>(&1);
        Vector::reverse(&mut x1);
        Debug::print(&x1);

        let x2 = BCS::to_bytes<u128>(&81238193281938219123913219999900099);
        Vector::reverse(&mut x2);
        Debug::print(&x2);
//        Debug::print(&BCS::to_bytes<u128>(&100000000));
//        Debug::print(&BCS::to_bytes<u128>(&2));
    }
}

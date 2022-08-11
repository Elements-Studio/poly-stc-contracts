//# init -n test --public-keys Bridge=0x8085e172ecf785692da465ba3339da46c4b43640c3f92a45db803690cc3c4a36

//# faucet --addr Bridge --amount 10000000000

//# run --signers Bridge
script {
    use StarcoinFramework::Math;
    use StarcoinFramework::Debug;
    use Bridge::SafeMath;

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
        assert!(amount_y_1 <= 0, 3003);
        assert!(amount_y_2 > 0, 3004);
    }
}
// check: EXECUTED


//# run --signers Bridge
script {
    use StarcoinFramework::BCS;
    use StarcoinFramework::Debug;
    use StarcoinFramework::Vector;

    // case : x*y/z overflow
    fun bcs_test_u64(_: signer) {
        let x1 = BCS::to_bytes<u128>(&1);
        Vector::reverse(&mut x1);
        Debug::print(&x1);

        let x2 = BCS::to_bytes<u128>(&81238193281938219123913219999900099);
        Vector::reverse(&mut x2);
        Debug::print(&x2);
    }
}

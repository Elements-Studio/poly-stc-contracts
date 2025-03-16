module Bridge::SafeMath {
    use StarcoinFramework::math128;
    use MoveStdlib::error as Errors;

    const EXP_SCALE_9:  u128 = 1000000000;// e9
    const EXP_SCALE_10: u128 = 10000000000;// e10
    const EXP_SCALE_18: u128 = 1000000000000000000;// e18
    const U64_MAX:      u64  = 18446744073709551615;  //length(U64_MAX)==20
    const U128_MAX:     u128 = 340282366920938463463374607431768211455;  //length(U128_MAX)==39

    const ERR_U128_OVERFLOW: u64 = 1001;
    const ERR_DIVIDE_BY_ZERO: u64 = 1002;
    //    const MUL_DIV_OVERFLOW_U128: u64 = 1003;

    // support 18-bit or larger precision token
    public fun safe_mul_div(x: u128, y: u128, z: u128): u128 {
        let r_u256 = mul_div_u256(x, y ,z);

        let u128_max = (U128_MAX as u256);
        if (r_u256 > u128_max) {
            abort Errors::invalid_argument(ERR_U128_OVERFLOW)
        };
        (r_u256 as u128)
    }

    public fun mul_div_u256(x: u128, y: u128, z: u128): u256 {
        if ( z == 0) {
            abort Errors::invalid_argument(ERR_DIVIDE_BY_ZERO)
        };

        if (x <= EXP_SCALE_18 && y <= EXP_SCALE_18) {
            return ((x * y / z) as u256);
        };

        let x_u256 = (x as u256);
        let y_u256 = (y as u256);
        let z_u256 = (z as u256);
        (x_u256 * y_u256) / z_u256
    }

    #[test]
    public fun test_safe_mul_div() {
        let x: u128 = 9446744073709551615;
        let y: u128 = 1009855555;
        let z: u128 = 3979;
        //        getcontext().prec = 64
        //        Decimal(9446744073709551615)*Decimal(1009855555)/Decimal(3979)
        //        Decimal('2397548876476230247541334.839')
        let _r_expected:u128 = 2397548876476230247541334;
        let r = Self::safe_mul_div(x, y, z);
        assert!(r == _r_expected, 3001);
    }

    #[test]
    #[expected_failure]
    public fun test_safe_mul_div_overflow() {
        let x: u128 = 240282366920938463463374607431768211455;
        let y: u128 = 1009855555;
        let z: u128 = 3979;

        let _r_expected:u128 = 9539846979498919717765120;
        let r = Self::safe_mul_div(x, y, z);
        assert!(r == _r_expected, 3002);
    }


    public fun mul_u256(x: u128, y: u128): u256 {
        (x as u256) * (y as u256)
    }

    // support 18-bit or larger precision token
    // base on native u256
    // babylonian method (https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method)
    public fun sqrt_u256(y: u256): u128 {
        let u128_max = (U128_MAX as u256);
        if (y <= u128_max) {
            let z = math128::sqrt((y as u128));
            (z as u128)
        } else {
            let z = copy y;
            let one_u256 = 1u256;
            let two_u256 = 2u256;
            let x = (copy y / copy two_u256) + one_u256;
            while (x < z) {
                z = copy x;
                x = ((copy y / copy x) + copy x) / copy two_u256;
            };
            (z as u128)
        }
    }

    #[test]
    public fun test_sqrt_u256() {
        let x: u128 = 90282366920938463463374607431768211455;
        let y: u128 = 1009855555;
        //        getcontext().prec = 64
        //        (Decimal(90282366920938463463374607431768211455)*Decimal(1009855555)).sqrt()
        //        Decimal('301947263199483152960157.5789842310747215103252658913180283305935')
        let _r_expected:u128 = 301947263199483152960157;
        let r = Self::sqrt_u256(Self::mul_u256(x, y));
        assert!(r == _r_expected, 3003);
    }

    #[test]
    public fun test_sqrt_u256_by_max_u128() {
        let _r_expected:u128 = 18446744073709551615;
        let r = Self::sqrt_u256((U128_MAX as u256));
        assert!(r == _r_expected, 3004);
    }

    public fun get_safe_u128(x: u256): u128 {
        let u128_max = (U128_MAX as u256);
        if (x > u128_max) {
            abort Errors::invalid_argument(ERR_U128_OVERFLOW)
        };
        (x as u128)
    }
}
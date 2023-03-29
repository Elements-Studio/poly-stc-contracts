module Bridge::zion_lock_proxy {
    use Bridge::SafeMath;
    use Bridge::SimpleMapWrapper;
    use Bridge::zero_copy_sink;
    use Bridge::zero_copy_source;
    use Bridge::zion_cross_chain_manager::{Self, License};
    use Bridge::zion_utils;

    use StarcoinFramework::Account;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Event;
    use StarcoinFramework::Option;
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Token;
    use StarcoinFramework::TypeInfo::{Self, TypeInfo};
    use StarcoinFramework::Vector;

    #[test_only] use StarcoinFramework::STC::STC;

    const DEPRECATED: u64 = 1;
    const ENOT_OWNER: u64 = 2;
    const ETREASURY_ALREADY_EXIST: u64 = 3;
    const ETREASURY_NOT_EXIST: u64 = 4;
    const ELICENSE_ALREADY_EXIST: u64 = 5;
    const ELICENSE_NOT_EXIST: u64 = 6;
    const ETARGET_PROXY_NOT_BIND: u64 = 7;
    const ETARGET_ASSET_NOT_BIND: u64 = 8;
    const EINVALID_COINTYPE: u64 = 9;
    const EINVALID_FROM_CONTRACT: u64 = 10;
    const EINVALID_TARGET_LICENSE_ID: u64 = 11;
    const EINVALID_METHOD: u64 = 12;
    const ELICENSE_STORE_ALREADY_EXIST: u64 = 13;
    const EINVALID_LICENSE_INFO: u64 = 14;
    const EINVALID_SIGNER: u64 = 15;
    const ELICENSE_STORE_NOT_EXIST: u64 = 16;
    const EALREADY_INIT: u64 = 17;


    struct LockProxyStore has key, store {
        proxy_map: SimpleMap<u64, vector<u8>>,
        asset_map: SimpleMap<TypeInfo, SimpleMap<u64, vector<u8>>>,
        paused: bool,
        owner: address,
        bind_proxy_event: Event::EventHandle<BindProxyEvent>,
        bind_asset_event: Event::EventHandle<BindAssetEvent>,
        lock_event: Event::EventHandle<LockEvent>,
        unlock_event: Event::EventHandle<UnlockEvent>
    }

    struct Treasury<phantom CoinType> has key, store {
        coin: Token::Token<CoinType>
    }

    struct LicenseStore<LicenseType: store> has key, store {
        license: Option::Option<LicenseType>
    }

    // events
    struct BindProxyEvent has store, drop {
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    }

    struct BindAssetEvent has store, drop {
        from_asset: TypeInfo,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_asset_decimals: u8,
    }

    struct UnlockEvent has store, drop {
        to_asset: TypeInfo,
        to_address: address,
        amount: u64,
        from_chain_amount: u128,
    }

    struct LockEvent has store, drop {
        from_asset: TypeInfo,
        from_address: address,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_address: vector<u8>,
        amount: u64,
        target_chain_amount: u128
    }


    // init
    public fun init(admin: &signer) {
        let admin_addr = Signer::address_of(admin);
        assert!(admin_addr == @Bridge, EINVALID_SIGNER);
        assert!(!exists<LockProxyStore>(admin_addr), EALREADY_INIT);

        move_to<LockProxyStore>(admin, LockProxyStore {
            proxy_map: SimpleMap::create<u64, vector<u8>>(),
            asset_map: SimpleMap::create<TypeInfo, SimpleMap<u64, vector<u8>>>(),
            paused: false,
            owner: Signer::address_of(admin),
            bind_proxy_event: Event::new_event_handle<BindProxyEvent>(admin),
            bind_asset_event: Event::new_event_handle<BindAssetEvent>(admin),
            lock_event: Event::new_event_handle<LockEvent>(admin),
            unlock_event: Event::new_event_handle<UnlockEvent>(admin),
        });

        create_license_store(admin);
    }

    // create license store
    public fun create_license_store<>(admin: &signer) {
        assert!(Signer::address_of(admin) == @Bridge, EINVALID_SIGNER);
        assert!(!exists<LicenseStore<License>>(@Bridge), ELICENSE_STORE_ALREADY_EXIST);

        move_to<LicenseStore<License>>(admin, LicenseStore<License> {
            license: Option::none<License>(),
        });
    }

    // getter function
    public fun getTargetProxy(to_chain_id: u64): vector<u8> acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@Bridge);
        if (SimpleMap::contains_key(&config_ref.proxy_map, &to_chain_id)) {
            return *SimpleMap::borrow(&config_ref.proxy_map, &to_chain_id)
        } else {
            abort ETARGET_PROXY_NOT_BIND
        }
    }

    public fun getToAsset<CoinType>(to_chain_id: u64): (vector<u8>, u8) acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@Bridge);
        let from_asset = TypeInfo::type_of<Token::Token<CoinType>>();

        if (SimpleMap::contains_key(&config_ref.asset_map, &from_asset)) {
            let sub_table = SimpleMap::borrow(&config_ref.asset_map, &from_asset);
            if (SimpleMap::contains_key(sub_table, &to_chain_id)) {
                let decimals_concat_to_asset = SimpleMap::borrow(sub_table, &to_chain_id);
                let decimals = *Vector::borrow(decimals_concat_to_asset, 0);
                let to_asset = zion_utils::slice(decimals_concat_to_asset, 1, Vector::length(decimals_concat_to_asset) - 1);
                return (to_asset, decimals)
            } else {
                abort ETARGET_ASSET_NOT_BIND
            }
        } else {
            abort ETARGET_ASSET_NOT_BIND
        }
    }

    public fun paused(): bool acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@Bridge);
        return config_ref.paused
    }

    public fun owner(): address acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@Bridge);
        return config_ref.owner
    }

    public fun getBalance<CoinType: store>(): u128 acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@Bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global<Treasury<CoinType>>(@Bridge);
        Token::value<CoinType>(&treasury_ref.coin)
    }


    // owner function
    fun onlyOwner(owner: &signer) acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@Bridge);
        assert!(Signer::address_of(owner) == config_ref.owner, ENOT_OWNER);
    }

    public /*entry*/ fun transferOwnerShip(owner: &signer, new_owner: address) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        config_ref.owner = new_owner;
    }

    public /*entry*/ fun pause(owner: &signer) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        config_ref.paused = true;
    }

    public /*entry*/ fun unpause(owner: &signer) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        config_ref.paused = false;
    }

    public /*entry*/ fun bindProxy(
        owner: &signer,
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    ) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        SimpleMapWrapper::upsert(&mut config_ref.proxy_map, to_chain_id, copy target_proxy_hash);

        Event::emit_event(
            &mut config_ref.bind_proxy_event,
            BindProxyEvent {
                to_chain_id,
                target_proxy_hash,
            },
        );
    }

    public /*entry*/ fun unbindProxy(owner: &signer, to_chain_id: u64) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        if (SimpleMap::contains_key(&config_ref.proxy_map, &to_chain_id)) {
            SimpleMap::remove(&mut config_ref.proxy_map, &to_chain_id);
        } else {
            abort ETARGET_PROXY_NOT_BIND
        };

        Event::emit_event(
            &mut config_ref.bind_proxy_event,
            BindProxyEvent {
                to_chain_id,
                target_proxy_hash: Vector::empty<u8>(),
            },
        );
    }

    public /*entry*/ fun bindAsset<CoinType>(
        owner: &signer,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_asset_decimals: u8
    ) acquires LockProxyStore {
        onlyOwner(owner);
        let from_asset = TypeInfo::type_of<Token::Token<CoinType>>();
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        let decimals_concat_to_asset = Vector::singleton(to_asset_decimals);
        Vector::append(&mut decimals_concat_to_asset, copy to_asset_hash);
        if (SimpleMap::contains_key(&config_ref.asset_map, &from_asset)) {
            SimpleMapWrapper::upsert(
                SimpleMap::borrow_mut(&mut config_ref.asset_map, &from_asset),
                to_chain_id,
                decimals_concat_to_asset
            );
        } else {
            let subTable = SimpleMap::create<u64, vector<u8>>();
            SimpleMap::add(&mut subTable, to_chain_id, decimals_concat_to_asset);
            SimpleMap::add(&mut config_ref.asset_map, copy from_asset, subTable);
        };

        Event::emit_event(
            &mut config_ref.bind_asset_event,
            BindAssetEvent {
                from_asset,
                to_chain_id,
                to_asset_hash,
                to_asset_decimals,
            },
        );
    }

    public /*entry*/ fun unbindAsset<CoinType>(owner: &signer, to_chain_id: u64) acquires LockProxyStore {
        onlyOwner(owner);
        let from_asset = TypeInfo::type_of<Token::Token<CoinType>>();
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        if (SimpleMap::contains_key(&config_ref.asset_map, &from_asset)) {
            let sub_table =
                SimpleMap::borrow_mut(&mut config_ref.asset_map, &from_asset);
            if (SimpleMap::contains_key(sub_table, &to_chain_id)) {
                SimpleMap::remove(sub_table, &to_chain_id);
            } else {
                abort ETARGET_ASSET_NOT_BIND
            };
        } else {
            abort ETARGET_ASSET_NOT_BIND
        };

        Event::emit_event(
            &mut config_ref.bind_asset_event,
            BindAssetEvent {
                from_asset,
                to_chain_id,
                to_asset_hash: Vector::empty<u8>(),
                to_asset_decimals: 0,
            },
        );
    }


    // treasury function
    public /*entry*/ fun initTreasury<CoinType: store>(admin: &signer) {
        assert!(Signer::address_of(admin) == @Bridge, EINVALID_SIGNER);
        assert!(!exists<Treasury<CoinType>>(@Bridge), ETREASURY_ALREADY_EXIST);
        move_to(admin, Treasury<CoinType> {
            coin: Token::zero<CoinType>()
        });
    }

    public fun is_treasury_initialzed<CoinType>(): bool {
        exists<Treasury<CoinType>>(@Bridge)
    }

    public fun is_admin(account: address): bool {
        account == @Bridge
    }

    public fun deposit<CoinType: store>(fund: Token::Token<CoinType>) acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@Bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global_mut<Treasury<CoinType>>(@Bridge);
        Token::deposit<CoinType>(&mut treasury_ref.coin, fund);
    }

    fun withdraw<CoinType: store>(amount: u64): Token::Token<CoinType> acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@Bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global_mut<Treasury<CoinType>>(@Bridge);
        return Token::withdraw<CoinType>(&mut treasury_ref.coin, (amount as u128))
    }


    // license function
    public fun receiveLicense<LicenseType: store>(license: LicenseType) acquires LicenseStore {
        assert!(exists<LicenseStore<LicenseType>>(@Bridge), ELICENSE_STORE_NOT_EXIST);
        let license_opt = &mut borrow_global_mut<LicenseStore<LicenseType>>(@Bridge).license;
        assert!(Option::is_none<LicenseType>(license_opt), ELICENSE_ALREADY_EXIST);
        Option::fill(license_opt, license);
    }

    public fun removeLicense<LicenseType: store>(admin: &signer): LicenseType acquires LicenseStore {
        assert!(Signer::address_of(admin) == @Bridge, EINVALID_SIGNER);
        assert!(exists<LicenseStore<LicenseType>>(@Bridge), ELICENSE_NOT_EXIST);
        let license_opt = &mut borrow_global_mut<LicenseStore<LicenseType>>(@Bridge).license;
        assert!(Option::is_some<LicenseType>(license_opt), ELICENSE_NOT_EXIST);
        Option::extract<LicenseType>(license_opt)
    }

    public fun getLicenseId(): vector<u8> acquires LicenseStore {
        assert!(exists<LicenseStore<License>>(@Bridge), ELICENSE_NOT_EXIST);
        let license_opt = &borrow_global<LicenseStore<License>>(@Bridge).license;
        assert!(Option::is_some<License>(license_opt), ELICENSE_NOT_EXIST);
        return zion_cross_chain_manager::getLicenseId(Option::borrow(license_opt))
    }

    // lock
    public fun lock<CoinType: store>(
        account: &signer,
        fund: Token::Token<CoinType>,
        toChainId: u64,
        toAddress: &vector<u8>
    ) acquires Treasury, LicenseStore, LockProxyStore {
        // lock fund
        let amount = (Token::value<CoinType>(&fund) as u64);
        deposit(fund);

        // borrow license
        assert!(exists<LicenseStore<License>>(@Bridge), ELICENSE_NOT_EXIST);
        let license_opt = &borrow_global<LicenseStore<License>>(@Bridge).license;
        assert!(Option::is_some<License>(license_opt), ELICENSE_NOT_EXIST);
        let license_ref = Option::borrow(license_opt);

        // get target proxy/asset
        let to_proxy = getTargetProxy(toChainId);
        let (to_asset, to_asset_decimals) = getToAsset<CoinType>(toChainId);

        // precision conversion
        let target_chain_amount = to_target_chain_amount<CoinType>(amount, to_asset_decimals);

        // pack args
        let tx_data = serializeTxArgs(&to_asset, toAddress, target_chain_amount);
        // cross chain
        zion_cross_chain_manager::crossChain(account, license_ref, toChainId, &to_proxy, &b"unlock", &tx_data);

        // emit Event 
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        Event::emit_event(
            &mut config_ref.lock_event,
            LockEvent {
                from_asset: TypeInfo::type_of<Token::Token<CoinType>>(),
                from_address: Signer::address_of(account),
                to_chain_id: toChainId,
                to_asset_hash: to_asset,
                to_address: *toAddress,
                amount,
                target_chain_amount: (target_chain_amount as u128),
            },
        );
    }


    // unlock
    public fun unlock<CoinType: store>(
        certificate: zion_cross_chain_manager::Certificate
    ) acquires Treasury, LicenseStore, LockProxyStore {
        // read certificate
        let (
            from_contract,
            from_chain_id,
            target_license_id,
            method,
            args
        ) = zion_cross_chain_manager::read_certificate(&certificate);

        // unpac args
        let (
            to_asset,
            to_address,
            from_chain_amount
        ) = deserializeTxArgs(&args);

        // precision conversion
        let (_, decimals) = getToAsset<CoinType>(from_chain_id);
        let amount = from_target_chain_amount<CoinType>((from_chain_amount as u128), decimals);

        // check
        assert!(BCS::to_bytes(&TypeInfo::type_of<Token::Token<CoinType>>()) == to_asset, EINVALID_COINTYPE);
        assert!(getTargetProxy(from_chain_id) == from_contract, EINVALID_FROM_CONTRACT);
        assert!(getLicenseId() == target_license_id, EINVALID_TARGET_LICENSE_ID);
        assert!(method == b"unlock", EINVALID_METHOD);

        // unlock fund
        let fund = withdraw<CoinType>(amount);
        Account::deposit(BCS::to_address(copy to_address), fund);

        // emit Event
        let config_ref = borrow_global_mut<LockProxyStore>(@Bridge);
        Event::emit_event(
            &mut config_ref.unlock_event,
            UnlockEvent {
                to_asset: TypeInfo::type_of<Token::Token<CoinType>>(),
                to_address: BCS::to_address(to_address),
                amount,
                from_chain_amount: (from_chain_amount as u128)
            },
        );
    }

    public /*entry*/ fun relay_unlock_tx<CoinType: store>(
        account: &signer,
        raw_header: vector<u8>,
        raw_seals: vector<u8>,
        account_proof: vector<u8>,
        storage_proof: vector<u8>,
        raw_cross_tx: vector<u8>
    ) acquires Treasury, LicenseStore, LockProxyStore {
        // borrow license
        assert!(exists<LicenseStore<License>>(@Bridge), ELICENSE_NOT_EXIST);
        let license_opt = &borrow_global<LicenseStore<License>>(@Bridge).license;
        assert!(Option::is_some<zion_cross_chain_manager::License>(license_opt), ELICENSE_NOT_EXIST);
        let license_ref = Option::borrow(license_opt);

        let certificate = zion_cross_chain_manager::verifyHeaderAndExecuteTx(
            account,
            license_ref,
            &raw_header,
            &raw_seals,
            &account_proof,
            &storage_proof,
            &raw_cross_tx
        );
        unlock<CoinType>(certificate);
    }

    // decimals conversion
    public fun to_target_chain_amount<CoinType: store>(amount: u64, target_decimals: u8): u256 {
        let source_decimals = Token::scaling_factor<CoinType>();
        (amount as u256) * (SafeMath::pow_10(target_decimals) as u256) / (source_decimals as u256)
    }

    public fun from_target_chain_amount<CoinType: store>(target_chain_amount: u128, target_decimals: u8): u64 {
        let source_decimals = Token::scaling_factor<CoinType>();
        (target_chain_amount * source_decimals / SafeMath::pow_10(target_decimals) as u64)
    }
    
    // codecs
    public fun serializeTxArgs(to_asset: &vector<u8>, to_address: &vector<u8>, amount: u256): vector<u8> {
        let buf = zero_copy_sink::write_var_bytes(to_asset);
        Vector::append(&mut buf, zero_copy_sink::write_var_bytes(to_address));
        Vector::append(&mut buf, zero_copy_sink::write_u256(amount));
        return buf
    }

    public fun deserializeTxArgs(raw_data: &vector<u8>): (vector<u8>, vector<u8>, u256) {
        let offset = (0 as u64);
        let to_asset: vector<u8>;
        let to_address: vector<u8>;
        let amount: u256;
        (to_asset, offset) = zero_copy_source::next_var_bytes(raw_data, offset);
        (to_address, offset) = zero_copy_source::next_var_bytes(raw_data, offset);
        (amount, _) = zero_copy_source::next_u256(raw_data, offset);
        return (to_asset, to_address, amount)
    }

    //#[test_only] use StarcoinFramework::Debug;
    #[test_only]
    fun test_init(admin: &signer) {
        assert!(Signer::address_of(admin) == @Bridge, EINVALID_SIGNER);

        move_to<LockProxyStore>(admin, LockProxyStore{
            proxy_map: SimpleMap::create<u64, vector<u8>>(),
            asset_map: SimpleMap::create<TypeInfo, SimpleMap<u64, vector<u8>>>(),
            paused: false,
            owner: Signer::address_of(admin),
            bind_proxy_event: Event::new_event_handle<BindProxyEvent>(admin),
            bind_asset_event: Event::new_event_handle<BindAssetEvent>(admin),
            lock_event: Event::new_event_handle<LockEvent>(admin),
            unlock_event: Event::new_event_handle<UnlockEvent>(admin),
        });

        move_to<LicenseStore<License>>(admin, LicenseStore<License>{
            license: Option::none<License>(),
        });
    }

    #[test_only] 
    fun test_setup(arg: &signer) {
        Account::create_account_with_address<STC>(@Bridge);
        test_init(arg);
    }

    #[test(arg = @Bridge)]
    fun pause_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        assert!(!paused(), 0);
        pause(&arg);
        assert!(paused(), 0);
        unpause(&arg);
        assert!(!paused(), 0);
    }

    #[test(arg = @Bridge, invalid_signer = @0x2), expected_failure]
    fun pause_failure_test(arg: signer, invalid_signer: signer) acquires LockProxyStore {
        test_setup(&arg);
        let addr = Signer::address_of(&invalid_signer);
        Account::create_account_with_address<STC>(addr);
        assert!(!paused(), 0);
        pause(&invalid_signer);
    }

    #[test]
    fun serializeTxArgs_test() {
        let asset = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        let addr = x"E1D7C7a4596B038CEd2A84bF65B8647271C53208";
        let amount = 13238898723897u256;
        let arg = serializeTxArgs(&asset, &addr, amount);
        let (asset_cp, addr_cp, amount_cp) = deserializeTxArgs(&arg);
        assert!(asset == asset_cp, 0);
        assert!(addr == addr_cp, 0);
        assert!(amount == amount_cp, 0);
    }

    #[test(arg = @Bridge), expected_failure(abort_code = ETARGET_ASSET_NOT_BIND)]
    fun bind_asset_nil_failure_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        getToAsset<STC>(10);
    }

    #[test(arg = @Bridge)]
    fun bind_asset_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetAsset = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        let targetAsset2 = x"13233e3c0e6b48010873b947bddc4721b1bdff9648";

        bindAsset<STC>(&arg, 10, targetAsset, 18);
        let (asset, decimals) = getToAsset<STC>(10);
        assert!((asset == targetAsset), 1001);
        assert!(decimals == 18, 1002);

        bindAsset<STC>(&arg, 10, targetAsset2, 9);
        (asset, decimals) = getToAsset<STC>(10);
        assert!((asset == targetAsset2), 1003);
        assert!((asset != targetAsset), 1004);
        assert!(decimals == 9, 1005);
    }

    #[test(arg = @Bridge), expected_failure(abort_code = ETARGET_ASSET_NOT_BIND)]
    fun unbind_asset_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetAsset = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        bindAsset<STC>(&arg, 10, targetAsset, 18);
        let (asset, decimals) = getToAsset<STC>(10);
        assert!((asset == targetAsset), 0);
        assert!(decimals == 18, 0);
        unbindAsset<STC>(&arg, 10);
        getToAsset<STC>(10);
    }

    #[test(arg = @Bridge, invalid_signer = @0x2), expected_failure]
    fun bind_asset_failure_test(arg: signer, invalid_signer: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetAsset = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        bindAsset<STC>(&invalid_signer, 10, targetAsset, 9);
    }

    #[test(arg = @Bridge), expected_failure(abort_code = ETARGET_PROXY_NOT_BIND)]
    fun bind_proxy_nil_failure_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        getTargetProxy(10);
    }

    #[test(arg = @Bridge)]
    fun bind_proxy_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetProxy = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        bindProxy(&arg, 10, targetProxy);
        assert!((getTargetProxy(10) == targetProxy), 0);
    }

    #[test(arg = @Bridge), expected_failure(abort_code = ETARGET_PROXY_NOT_BIND)]
    fun unbind_proxy_test(arg: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetProxy = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        bindProxy(&arg, 10, targetProxy);
        assert!((getTargetProxy(10) == targetProxy), 0);
        unbindProxy(&arg, 10);
        getTargetProxy(10);
    }

    #[test(arg = @Bridge, invalid_signer = @0x2), expected_failure]
    fun bind_proxy_failure_test(arg: signer, invalid_signer: signer) acquires LockProxyStore {
        test_setup(&arg);
        let targetProxy = x"03233e3c0e6b48010873b947bddc4721b1bdff9648";
        bindProxy(&invalid_signer, 10, targetProxy);
    }
}
module Bridge::zion_cross_chain_manager {
    use Bridge::ACL;
    use Bridge::SimpleMapWrapper;
    use Bridge::zion_cross_chain_utils;

    use StarcoinFramework::BCS;
    use StarcoinFramework::Event;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Signer;
    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    use StarcoinFramework::Vector;

    // Errors
    const EINVALID_SIGNER: u64 = 1;
    const EPAUSED: u64 = 2;
    const EVERIFY_HEADER_FAILED: u64 = 3;
    const EVERIFY_PROOF_FAILED: u64 = 4;
    const EALREADY_EXECUTED: u64 = 5;
    const ENOT_TARGET_CHAIN: u64 = 6;
    const EALREADY_HAS_ROLE: u64 = 7;
    const ENOT_HAS_ROLE: u64 = 8;
    const ENOT_ADMIN: u64 = 9;
    const ENOT_PAUSE_ROLE: u64 = 10;
    const ENOT_CA_ROLE: u64 = 11;
    const EBLACKLISTED_FROM: u64 = 13;
    const EBLACKLISTED_TO: u64 = 14;
    const EVERIFIER_NOT_RECEIVER: u64 = 15;
    const EALREADY_INITIALIZED: u64 = 16;
    const EINVLAID_BLOCK_HEIGHT: u64 = 17;
    const EEMPTY_VALIDATOR_SET: u64 = 18;

    const ZION_CROSS_CHAIN_MANAGER_ADDRESS: vector<u8> = x"e52552637c5897a2d499fbf08216f73e";

    // access control
    struct ACLStore has key, store {
        role_acls: SimpleMap::SimpleMap<u64, ACL::ACL>,
        license_black_list: SimpleMap::SimpleMap<vector<u8>, u8>
    }

    const ADMIN_ROLE: u64 = 1;
    const PAUSE_ROLE: u64 = 2;
    const CA_ROLE: u64 = 3;

    public fun hasRole(role: u64, account: address): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@Bridge);
        if (SimpleMap::contains_key(&acl_store_ref.role_acls, &role)) {
            let role_acl = SimpleMap::borrow(&acl_store_ref.role_acls, &role);
            return ACL::contains(role_acl, account)
        } else {
            return false
        }
    }

    public /*entry*/ fun grantRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, Signer::address_of(admin)), ENOT_ADMIN);
        assert!(!hasRole(role, account), EALREADY_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@Bridge);
        if (SimpleMap::contains_key(&acl_store_ref.role_acls, &role)) {
            let role_acl = SimpleMap::borrow_mut(&mut acl_store_ref.role_acls, &role);
            ACL::add(role_acl, account);
        } else {
            let role_acl = ACL::empty();
            ACL::add(&mut role_acl, account);
            SimpleMap::add(&mut acl_store_ref.role_acls, role, role_acl);
        }
    }

    public /*entry*/ fun revokeRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, Signer::address_of(admin)), ENOT_ADMIN);
        assert!(hasRole(role, account), ENOT_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@Bridge);
        let role_acl = SimpleMap::borrow_mut(&mut acl_store_ref.role_acls, &role);
        ACL::remove(role_acl, account);
    }

    // cross chain license
    struct License has key, store {
        account: address,
        module_name: vector<u8>,
    }

    public fun issueLicense(ca: &signer, account: address, module_name: vector<u8>): License acquires ACLStore {
        assert!(hasRole(CA_ROLE, Signer::address_of(ca)), ENOT_CA_ROLE);
        License {
            account,
            module_name,
        }
    }

    public fun destroyLicense(license: License) {
        let License { account: _, module_name: _ } = license;
    }

    public fun getLicenseId(license: &License): vector<u8> {
        let head = Vector::empty<u8>();
        let tail = Vector::empty<u8>();
        let k: u64 = 2;

        zion_cross_chain_utils::abi_encode_append_bytes(&mut head, &mut tail, BCS::to_bytes(&license.account), k);
        zion_cross_chain_utils::abi_encode_append_bytes(&mut head, &mut tail, *&license.module_name, k);

        Vector::append(&mut head, tail);
        head
    }

    public fun getLicenseInfo(license: &License): (address, vector<u8>) {
        (license.account, *&license.module_name)
    }


    // black list
    // access level: 0b000000xy , x means blackListed as fromContract , y means blackListed as toContract
    public fun isBlackListedFrom(license_id: &vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@Bridge);
        if (SimpleMap::contains_key(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *SimpleMap::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x02) != 0
        } else {
            return false
        }
    }

    public fun isBlackListedTo(license_id: &vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@Bridge);
        if (SimpleMap::contains_key(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *SimpleMap::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x01) != 0
        } else {
            return false
        }
    }

    public /*entry*/ fun setBlackList(ca: &signer, license_id: vector<u8>, access_level: u8) acquires ACLStore {
        assert!(hasRole(CA_ROLE, Signer::address_of(ca)), ENOT_CA_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@Bridge);
        let v_ref = SimpleMapWrapper::borrow_mut_with_default(
            &mut acl_store_ref.license_black_list,
            license_id,
            access_level
        );
        *v_ref = access_level;
    }


    // event 
    struct EventStore has key, store {
        init_genesis_block_event: Event::EventHandle<InitGenesisBlockEvent>,
        change_epoch_event: Event::EventHandle<ChangeEpochEvent>,
        cross_chain_event: Event::EventHandle<CrossChainEvent>,
        verify_header_and_execute_tx_event: Event::EventHandle<VerifyHeaderAndExecuteTxEvent>,
    }

    struct InitGenesisBlockEvent has store, drop {
        height: u64,
        raw_header: vector<u8>,
    }

    struct ChangeEpochEvent has store, drop {
        height: u64,
        raw_header: vector<u8>,
        old_validators: vector<vector<u8>>,
        new_validators: vector<vector<u8>>,
    }

    struct CrossChainEvent has store, drop {
        sender: address,
        tx_id: vector<u8>,
        proxy_or_asset_contract: vector<u8>,
        to_chain_id: u64,
        to_contract: vector<u8>,
        raw_data: vector<u8>,
    }

    struct VerifyHeaderAndExecuteTxEvent has store, drop {
        from_chain_id: u64,
        to_contract: vector<u8>,
        cross_chain_tx_hash: vector<u8>,
        from_chain_tx_hash: vector<u8>,
    }

    // data store
    struct CrossChainGlobalConfig has key {
        polyId: u64,
        paused: bool,
        curValidators: vector<vector<u8>>,
        curEpochStartHeight: u64,
        curEpochEndHeight: u64,
        aptosToPolyTxHashIndex: u128,
        aptosToPolyTxHashMap: SimpleMap<u128, vector<u8>>,
        fromChainTxExist: SimpleMap<u64, SimpleMap<vector<u8>, bool>>,
    }

    fun putPolyId(polyId: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.polyId = polyId;
    }

    public fun getPolyId(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return config_ref.polyId
    }

    fun putCurEpochStartHeight(height: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.curEpochStartHeight = height;
    }

    public fun getCurEpochStartHeight(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return config_ref.curEpochStartHeight
    }

    fun putCurEpochEndHeight(height: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.curEpochEndHeight = height;
    }

    public fun getCurEpochEndHeight(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return config_ref.curEpochEndHeight
    }

    fun putCurValidators(validators: &vector<vector<u8>>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.curValidators = *validators;
    }

    public fun getCurValidators(): vector<vector<u8>> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return *&config_ref.curValidators
    }

    fun markFromChainTxExist(fromChainId: u64, fromChainTx: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        if (SimpleMap::contains_key(&config_ref.fromChainTxExist, &fromChainId)) {
            SimpleMapWrapper::upsert(
                SimpleMap::borrow_mut(&mut config_ref.fromChainTxExist, &fromChainId),
                *fromChainTx,
                true
            );
            return
        } else {
            let subTable = SimpleMap::create<vector<u8>, bool>();
            SimpleMap::add(&mut subTable, *fromChainTx, true);
            SimpleMap::add(&mut config_ref.fromChainTxExist, fromChainId, subTable);
            return
        }
    }

    public fun checkIfFromChainTxExist(
        fromChainId: u64,
        fromChainTx: &vector<u8>
    ): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        if (SimpleMap::contains_key(&config_ref.fromChainTxExist, &fromChainId)) {
            if (SimpleMap::contains_key(SimpleMap::borrow(&config_ref.fromChainTxExist, &fromChainId), fromChainTx)) {
                return *SimpleMap::borrow(SimpleMap::borrow(&config_ref.fromChainTxExist, &fromChainId), fromChainTx)
            };
        };
        return false
    }

    public fun getAptosTxHashIndex(): u128 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return config_ref.aptosToPolyTxHashIndex
    }

    fun putAptosTxHash(hash: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        let index = config_ref.aptosToPolyTxHashIndex;
        SimpleMapWrapper::upsert(&mut config_ref.aptosToPolyTxHashMap, index, *hash);
        config_ref.aptosToPolyTxHashIndex = index + 1;
    }

    public fun getAptosTxHash(aptosHashIndex: u128): vector<u8> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return *SimpleMap::borrow(&config_ref.aptosToPolyTxHashMap, &aptosHashIndex)
    }


    // pause/unpause
    public fun paused(): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@Bridge);
        return config_ref.paused
    }

    public fun pause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, Signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.paused = true;
    }

    public fun unpause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, Signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@Bridge);
        config_ref.paused = false;
    }


    // initialize
    public /*entry*/ fun init(account: &signer, raw_header: vector<u8>, polyId: u64) acquires EventStore {
        assert!(Signer::address_of(account) == @Bridge, EINVALID_SIGNER);
        assert!(!exists<CrossChainGlobalConfig>(@Bridge), EALREADY_INITIALIZED);

        // init access control lists
        let acls = SimpleMap::create<u64, ACL::ACL>();
        let admin_acl = ACL::empty();
        let pause_acl = ACL::empty();
        let ca_acl = ACL::empty();
        ACL::add(&mut admin_acl, @Bridge);
        ACL::add(&mut pause_acl, @Bridge);
        ACL::add(&mut ca_acl, @Bridge);
        SimpleMap::add(&mut acls, ADMIN_ROLE, admin_acl);
        SimpleMap::add(&mut acls, PAUSE_ROLE, pause_acl);
        SimpleMap::add(&mut acls, CA_ROLE, ca_acl);
        move_to<ACLStore>(account, ACLStore {
            role_acls: acls,
            license_black_list: SimpleMap::create<vector<u8>, u8>()
        });

        // decode header
        let (_, height) = zion_cross_chain_utils::decode_header(&raw_header);
        let (epoch_end_height, validators) = zion_cross_chain_utils::decode_extra(&raw_header);

        // init global config
        let config = CrossChainGlobalConfig {
            polyId,
            paused: false,
            curValidators: validators,
            curEpochStartHeight: height + 1,
            curEpochEndHeight: epoch_end_height,
            aptosToPolyTxHashIndex: 0,
            aptosToPolyTxHashMap: SimpleMap::create<u128, vector<u8>>(),
            fromChainTxExist: SimpleMap::create<u64, SimpleMap<vector<u8>, bool>>()
        };
        move_to<CrossChainGlobalConfig>(account, config);

        // init event store
        move_to<EventStore>(account, EventStore {
            init_genesis_block_event: Event::new_event_handle<InitGenesisBlockEvent>(account),
            change_epoch_event: Event::new_event_handle<ChangeEpochEvent>(account),
            cross_chain_event: Event::new_event_handle<CrossChainEvent>(account),
            verify_header_and_execute_tx_event: Event::new_event_handle<VerifyHeaderAndExecuteTxEvent>(account),
        });

        let event_store = borrow_global_mut<EventStore>(@Bridge);
        Event::emit_event(
            &mut event_store.init_genesis_block_event,
            InitGenesisBlockEvent {
                height,
                raw_header,
            },
        );
    }


    // set poly id
    public /*entry*/ fun setPolyId(account: &signer, polyId: u64) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(ADMIN_ROLE, Signer::address_of(account)), ENOT_ADMIN);
        putPolyId(polyId);
    }


    // change book keeper
    public /*entry*/ fun change_epoch(
        _account: &signer,
        raw_header: vector<u8>,
        raw_seals: vector<u8>
    ) acquires CrossChainGlobalConfig, EventStore {
        // decode
        let (_, height) = zion_cross_chain_utils::decode_header(&raw_header);
        let (epoch_end_height, new_validators) = zion_cross_chain_utils::decode_extra(&raw_header);
        let header_hash = zion_cross_chain_utils::get_header_hash(*&raw_header);
        let old_validators = getCurValidators();

        // check
        assert!(height >= getCurEpochStartHeight(), EINVLAID_BLOCK_HEIGHT);
        assert!(Vector::length<vector<u8>>(&new_validators) != 0, EEMPTY_VALIDATOR_SET);
        assert!(
            zion_cross_chain_utils::verify_header(&header_hash, &raw_seals, &old_validators),
            EVERIFY_HEADER_FAILED
        );

        // put
        putCurValidators(&new_validators);
        putCurEpochStartHeight(height + 1);
        putCurEpochEndHeight(epoch_end_height);

        let event_store = borrow_global_mut<EventStore>(@Bridge);
        Event::emit_event(
            &mut event_store.change_epoch_event,
            ChangeEpochEvent {
                height,
                raw_header: *&raw_header,
                old_validators,
                new_validators,
            },
        );
    }

    // cross chain
    public fun crossChain(
        account: &signer,
        license: &License,
        toChainId: u64,
        toContract: &vector<u8>,
        method: &vector<u8>,
        txData: &vector<u8>
    ) acquires CrossChainGlobalConfig, ACLStore, EventStore {
        assert!(!paused(), EPAUSED);

        // check license
        let msg_sender = getLicenseId(license);
        assert!(!isBlackListedFrom(&msg_sender), EBLACKLISTED_FROM);

        // pack args
        let tx_hash_index = getAptosTxHashIndex();
        let param_tx_hash = BCS::to_bytes(&tx_hash_index);
        Vector::reverse(&mut param_tx_hash);

        let cross_chain_id = b"StarcoinCrossChainManager";
        Vector::append(&mut cross_chain_id, *&param_tx_hash);
        cross_chain_id = Hash::sha3_256(cross_chain_id);

        let raw_param = zion_cross_chain_utils::encode_tx_param(
            *&param_tx_hash,
            cross_chain_id,
            *&msg_sender,
            toChainId,
            *toContract,
            *method,
            *txData,
        );

        // mark
        putAptosTxHash(&Hash::sha3_256(*&raw_param));

        // emit event
        let event_store = borrow_global_mut<EventStore>(@Bridge);
        Event::emit_event(
            &mut event_store.cross_chain_event,
            CrossChainEvent {
                sender: Signer::address_of(account),
                tx_id: param_tx_hash,
                proxy_or_asset_contract: msg_sender,
                to_chain_id: toChainId,
                to_contract: *toContract,
                raw_data: raw_param,
            },
        );
    }


    // certificate
    struct Certificate has drop {
        from_contract: vector<u8>,
        from_chain_id: u64,
        target_license_id: vector<u8>,
        method: vector<u8>,
        args: vector<u8>
    }

    public fun read_certificate(certificate: &Certificate): (
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>)
    {
        return (
            *&certificate.from_contract,
            certificate.from_chain_id,
            *&certificate.target_license_id,
            *&certificate.method,
            *&certificate.args
        )
    }

    // verify header and execute tx
    public fun verifyHeaderAndExecuteTx(
        _account: &signer,
        license: &License,
        raw_header: &vector<u8>,
        raw_seals: &vector<u8>,
        account_proof: &vector<u8>,
        storage_proof: &vector<u8>,
        raw_cross_tx: &vector<u8>
    ): Certificate acquires CrossChainGlobalConfig, ACLStore, EventStore {
        assert!(!paused(), EPAUSED);

        // decode
        let (
            zion_tx_hash,
            from_chain_id,
            source_tx_hash,
            cross_chain_id,
            from_contract,
            to_chain_id,
            to_contract,
            method,
            args
        ) = zion_cross_chain_utils::decode_cross_tx(
            raw_cross_tx
        );
        let (root, height) = zion_cross_chain_utils::decode_header(raw_header);
        let header_hash = zion_cross_chain_utils::get_header_hash(*raw_header);
        let validators = getCurValidators();
        let cur_epoch_start_height = getCurEpochStartHeight();
        let cur_epoch_end_height = getCurEpochEndHeight();

        // verify block height
        assert!(height >= cur_epoch_start_height, EINVLAID_BLOCK_HEIGHT);
        assert!(height <= cur_epoch_end_height, EINVLAID_BLOCK_HEIGHT);

        // verify header
        assert!(zion_cross_chain_utils::verify_header(&header_hash, raw_seals, &validators), EVERIFY_HEADER_FAILED);

        // verify proof
        let storage_index = zion_cross_chain_utils::get_cross_tx_storage_slot(copy zion_tx_hash, to_chain_id);
        let storage_value = zion_cross_chain_utils::verify_account_proof(
            account_proof,
            &root,
            &ZION_CROSS_CHAIN_MANAGER_ADDRESS,
            storage_proof,
            &storage_index
        );
        assert!(storage_value == Hash::sha3_256(*raw_cross_tx), EVERIFY_PROOF_FAILED);

        // double-spending check/mark
        assert!(!checkIfFromChainTxExist(from_chain_id, &cross_chain_id), EALREADY_EXECUTED);
        markFromChainTxExist(from_chain_id, &cross_chain_id);

        // check to chain id
        assert!(to_chain_id == getPolyId(), ENOT_TARGET_CHAIN);

        // check verifier
        let msg_sender = getLicenseId(license);
        assert!(msg_sender == copy to_contract, EVERIFIER_NOT_RECEIVER);

        // check black list
        assert!(!isBlackListedTo(&to_contract), EBLACKLISTED_TO);

        // emit event
        let event_store = borrow_global_mut<EventStore>(@Bridge);
        Event::emit_event(
            &mut event_store.verify_header_and_execute_tx_event,
            VerifyHeaderAndExecuteTxEvent {
                from_chain_id,
                to_contract: copy to_contract,
                cross_chain_tx_hash: zion_tx_hash,
                from_chain_tx_hash: source_tx_hash,
            },
        );

        // return a certificate to prove the execution is certified
        return Certificate {
            from_contract,
            from_chain_id,
            target_license_id: to_contract,
            method,
            args,
        }
    }
}
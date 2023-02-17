module poly::cross_chain_manager {
    use std::vector;
    use std::signer;
    use std::bcs;
    use std::acl::{ACL, Self};
    use aptos_std::table::{Table, Self};
    use aptos_std::event;
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::account;

    use poly::cross_chain_utils;


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

    const ZION_CROSS_CHAIN_MANAGER_ADDRESS: vector<u8> = x"0000000000000000000000000000000000001003";


    // access control
    struct ACLStore has key, store {
        role_acls: Table<u64, ACL>,
        license_black_list: Table<vector<u8>, u8>
    }

    const ADMIN_ROLE: u64 = 1;
    const PAUSE_ROLE: u64 = 2;
    const CA_ROLE: u64 = 3;

    public fun hasRole(role: u64, account: address): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.role_acls, role)) {
            let role_acl = table::borrow(&acl_store_ref.role_acls, role);
            return acl::contains(role_acl, account)
        } else {
            return false
        }
    }

    public entry fun grantRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, signer::address_of(admin)), ENOT_ADMIN);
        assert!(!hasRole(role, account), EALREADY_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.role_acls, role)) {
            let role_acl = table::borrow_mut(&mut acl_store_ref.role_acls, role);
            acl::add(role_acl, account);
        } else {
            let role_acl = acl::empty();
            acl::add(&mut role_acl, account);
            table::add(&mut acl_store_ref.role_acls, role, role_acl);
        }
    }

    public entry fun revokeRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, signer::address_of(admin)), ENOT_ADMIN);
        assert!(hasRole(role, account), ENOT_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        let role_acl = table::borrow_mut(&mut acl_store_ref.role_acls, role);
        acl::remove(role_acl, account);
    }


    // cross chain license
    struct License has key, store {
        account: address,
        module_name: vector<u8>,
    }

    public fun issueLicense(ca: &signer, account: address, module_name: vector<u8>): License acquires ACLStore {
        assert!(hasRole(CA_ROLE, signer::address_of(ca)), ENOT_CA_ROLE);
        License{
            account: account,
            module_name: module_name,
        }
    }

    public fun destroyLicense(license: License) {
        let License{ account: _, module_name: _ } = license;
    }

    public fun getLicenseId(license: &License): vector<u8> {
        let head = vector::empty<u8>();
        let tail = vector::empty<u8>();
        let k: u64 = 2;

        cross_chain_utils::abi_encode_append_bytes(&mut head, &mut tail, bcs::to_bytes(&license.account), k);
        cross_chain_utils::abi_encode_append_bytes(&mut head, &mut tail, license.module_name, k);

        vector::append(&mut head, tail);
        head
    }

    public fun getLicenseInfo(license: &License): (address, vector<u8>) {
        (license.account, license.module_name)
    }


    // black list
    // access level: 0b000000xy , x means blackListed as fromContract , y means blackListed as toContract
    public fun isBlackListedFrom(license_id: vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *table::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x02) != 0
        } else {
            return false
        }
    }

    public fun isBlackListedTo(license_id: vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *table::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x01) != 0
        } else {
            return false
        }
    }

    public entry fun setBlackList(ca: &signer, license_id: vector<u8>, access_level: u8) acquires ACLStore {
        assert!(hasRole(CA_ROLE, signer::address_of(ca)), ENOT_CA_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        let v_ref = table::borrow_mut_with_default(&mut acl_store_ref.license_black_list, license_id, access_level);
        *v_ref = access_level;
    }
 

    // event 
    struct EventStore has key, store {
        init_genesis_block_event: event::EventHandle<InitGenesisBlockEvent>,
        change_epoch_event: event::EventHandle<ChangeEpochEvent>,
        cross_chain_event: event::EventHandle<CrossChainEvent>,
        verify_header_and_execute_tx_event: event::EventHandle<VerifyHeaderAndExecuteTxEvent>,
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
        aptosToPolyTxHashMap: Table<u128, vector<u8>>,
        fromChainTxExist: Table<u64, Table<vector<u8>, bool>>,
    }

    fun putPolyId(polyId: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.polyId = polyId;
    }

    public fun getPolyId(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.polyId
    }

    fun putCurEpochStartHeight(height: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.curEpochStartHeight = height;
    }

    public fun getCurEpochStartHeight(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.curEpochStartHeight
    }

    fun putCurEpochEndHeight(height: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.curEpochEndHeight = height;
    }

    public fun getCurEpochEndHeight(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.curEpochEndHeight
    }

    fun putCurValidators(validators: &vector<vector<u8>>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.curValidators = *validators;
    }

    public fun getCurValidators(): vector<vector<u8>> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.curValidators
    }

    fun markFromChainTxExist(fromChainId: u64, fromChainTx: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        if (table::contains(&config_ref.fromChainTxExist, fromChainId)) {
            table::upsert(table::borrow_mut(&mut config_ref.fromChainTxExist, fromChainId), *fromChainTx, true);
            return
        } else {
            let subTable = table::new<vector<u8>, bool>();
            table::add(&mut subTable, *fromChainTx, true);
            table::add(&mut config_ref.fromChainTxExist, fromChainId, subTable);
            return
        }
    }

    public fun checkIfFromChainTxExist(fromChainId: u64, fromChainTx: &vector<u8>): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        if (table::contains(&config_ref.fromChainTxExist, fromChainId)) {
            if (table::contains(table::borrow(&config_ref.fromChainTxExist, fromChainId), *fromChainTx)) {
                return *table::borrow(table::borrow(&config_ref.fromChainTxExist, fromChainId), *fromChainTx)
            };
        };
        return false
    }

    public fun getAptosTxHashIndex(): u128 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.aptosToPolyTxHashIndex
    }

    fun putAptosTxHash(hash: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        let index = config_ref.aptosToPolyTxHashIndex;
        table::upsert(&mut config_ref.aptosToPolyTxHashMap, index, *hash);
        config_ref.aptosToPolyTxHashIndex = index + 1;
    }

    public fun getAptosTxHash(aptosHashIndex: u128): vector<u8> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return *table::borrow(&config_ref.aptosToPolyTxHashMap, aptosHashIndex)
    }


    // pause/unpause
    public fun paused(): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.paused
    }

    public fun pause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.paused = true;
    }

    public fun unpause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.paused = false;
    }


    // initialize
    public entry fun init(account: &signer, raw_header: vector<u8>, polyId: u64) acquires EventStore {
        assert!(signer::address_of(account) == @poly, EINVALID_SIGNER);
        assert!(!exists<CrossChainGlobalConfig>(@poly), EALREADY_INITIALIZED);
        
        // init access control lists
        let acls = table::new<u64, ACL>();
        let admin_acl = acl::empty();
        let pause_acl = acl::empty();
        let ca_acl = acl::empty();
        acl::add(&mut admin_acl, @poly);
        acl::add(&mut pause_acl, @poly);
        acl::add(&mut ca_acl, @poly);
        table::add(&mut acls, ADMIN_ROLE, admin_acl);
        table::add(&mut acls, PAUSE_ROLE, pause_acl);
        table::add(&mut acls, CA_ROLE, ca_acl);
        move_to<ACLStore>(account, ACLStore{ 
            role_acls: acls, 
            license_black_list: table::new<vector<u8>, u8>() 
        });

        // decode header
        let (_,height) = cross_chain_utils::decode_header(&raw_header);
        let (epoch_end_height, validators) = cross_chain_utils::decode_extra(&raw_header);

        // init global config
        let config = CrossChainGlobalConfig{
            polyId,
            paused: false,
            curValidators: validators,
            curEpochStartHeight: height+1,
            curEpochEndHeight: epoch_end_height,
            aptosToPolyTxHashIndex: 0,
            aptosToPolyTxHashMap: table::new<u128, vector<u8>>(),
            fromChainTxExist: table::new<u64, Table<vector<u8>, bool>>()
        };
        move_to<CrossChainGlobalConfig>(account, config);

        // init event store
        move_to<EventStore>(account, EventStore{
            init_genesis_block_event: account::new_event_handle<InitGenesisBlockEvent>(account),
            change_epoch_event: account::new_event_handle<ChangeEpochEvent>(account),
            cross_chain_event: account::new_event_handle<CrossChainEvent>(account),
            verify_header_and_execute_tx_event: account::new_event_handle<VerifyHeaderAndExecuteTxEvent>(account),
        });

        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.init_genesis_block_event,
            InitGenesisBlockEvent{
                height,
                raw_header,
            },
        );
    }

    
    // set poly id
    public entry fun setPolyId(account: &signer, polyId: u64) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(ADMIN_ROLE, signer::address_of(account)), ENOT_ADMIN);
        putPolyId(polyId);
    }


    // change book keeper
    public entry fun change_epoch(_account: &signer, raw_header: vector<u8>, raw_seals: vector<u8>) acquires CrossChainGlobalConfig, EventStore {
        // decode
        let (_,height) = cross_chain_utils::decode_header(&raw_header);
        let (epoch_end_height, new_validators) = cross_chain_utils::decode_extra(&raw_header);
        let header_hash = cross_chain_utils::get_header_hash(raw_header);
        let old_validators = getCurValidators();

        // check
        assert!(height>=getCurEpochStartHeight(), EINVLAID_BLOCK_HEIGHT);
        assert!(vector::length<vector<u8>>(&new_validators)!=0, EEMPTY_VALIDATOR_SET);
        assert!(cross_chain_utils::verify_header(&header_hash, &raw_seals, &old_validators), EVERIFY_HEADER_FAILED);

        // put
        putCurValidators(&new_validators);
        putCurEpochStartHeight(height+1);
        putCurEpochEndHeight(epoch_end_height);

        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.change_epoch_event,
            ChangeEpochEvent{
                height,
                raw_header,
                old_validators,
                new_validators,
            },
        );
    }

    
    // cross chain
    public fun crossChain(account: &signer, license: &License, toChainId: u64, toContract: &vector<u8>, method: &vector<u8>, txData: &vector<u8>) acquires CrossChainGlobalConfig, ACLStore, EventStore {
        assert!(!paused(), EPAUSED);

        // check license
        let msg_sender = getLicenseId(license);
        assert!(!isBlackListedFrom(msg_sender), EBLACKLISTED_FROM);

        // pack args
        let tx_hash_index = getAptosTxHashIndex();
        let param_tx_hash = bcs::to_bytes(&tx_hash_index);
        vector::reverse(&mut param_tx_hash);

        let cross_chain_id = b"AptosCrossChainManager";
        vector::append(&mut cross_chain_id, param_tx_hash);
        cross_chain_id = keccak256(cross_chain_id);

        let raw_param = cross_chain_utils::encode_tx_param(
            param_tx_hash,
            cross_chain_id,
            msg_sender,
            toChainId,
            *toContract,
            *method,
            *txData,
        );

        // mark
        putAptosTxHash(&keccak256(raw_param));

        // emit event
        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.cross_chain_event,
            CrossChainEvent{
                sender: signer::address_of(account),
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
            certificate.from_contract,
            certificate.from_chain_id,
            certificate.target_license_id,
            certificate.method,
            certificate.args
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
        let (zion_tx_hash, from_chain_id, source_tx_hash, cross_chain_id, from_contract, to_chain_id, to_contract, method, args) = cross_chain_utils::decode_cross_tx(raw_cross_tx);
        let (root, height) = cross_chain_utils::decode_header(raw_header);
        let header_hash = cross_chain_utils::get_header_hash(*raw_header);
        let validators = getCurValidators();
        let cur_epoch_start_height = getCurEpochStartHeight();
        let cur_epoch_end_height = getCurEpochEndHeight();

        // verify block height
        assert!(height>=cur_epoch_start_height, EINVLAID_BLOCK_HEIGHT);
        assert!(height<=cur_epoch_end_height, EINVLAID_BLOCK_HEIGHT);

        // verify header
        assert!(cross_chain_utils::verify_header(&header_hash, raw_seals, &validators), EVERIFY_HEADER_FAILED);

        // verify proof
        let storage_index = cross_chain_utils::get_cross_tx_storage_slot(zion_tx_hash, to_chain_id);
        let storage_value = cross_chain_utils::verify_account_proof(account_proof, &root, &ZION_CROSS_CHAIN_MANAGER_ADDRESS, storage_proof, &storage_index);
        assert!(storage_value==keccak256(*raw_cross_tx), EVERIFY_PROOF_FAILED);

        // double-spending check/mark
        assert!(!checkIfFromChainTxExist(from_chain_id, &cross_chain_id), EALREADY_EXECUTED);
        markFromChainTxExist(from_chain_id, &cross_chain_id);

        // check to chain id
        assert!(to_chain_id == getPolyId(), ENOT_TARGET_CHAIN);

        // check verifier
        let msg_sender = getLicenseId(license);
        assert!(msg_sender == to_contract, EVERIFIER_NOT_RECEIVER);

        // check black list
        assert!(!isBlackListedTo(to_contract), EBLACKLISTED_TO);

        // emit event
        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.verify_header_and_execute_tx_event,
            VerifyHeaderAndExecuteTxEvent{
                from_chain_id,
                to_contract,
                cross_chain_tx_hash: zion_tx_hash,
                from_chain_tx_hash: source_tx_hash,
            },
        );

        // return a certificate to prove the execution is certified
        return Certificate{
            from_contract,
            from_chain_id,
            target_license_id: to_contract,
            method,
            args,
        }
    }
}
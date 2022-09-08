module Bridge::CrossChainManager {
    use StarcoinFramework::Vector;
    use StarcoinFramework::Event;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Signer;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Hash;

    use Bridge::Address;
    use Bridge::CrossChainData;
    use Bridge::CrossChainLibrary;
    use Bridge::CrossChainGlobal;
    use Bridge::ZeroCopySink;
    use Bridge::Bytes;
    use Bridge::CrossChainProcessCombinator;

    const PROXY_HASH_STARCOIN: vector<u8> = b"0xe52552637c5897a2d499fbf08216f73e::CrossChainScript";

    const ERR_DECREPTED: u64 = 1;

    const ERR_CONTRACT_INITIALIZE_REPEATE: u64 = 101;
    const ERR_NEXT_BOOK_KEEPER_ILLEGAL: u64 = 102;
    const ERR_NEXT_BOOK_KEEPER_EMPTY: u64 = 103;
    const ERR_INVALID_HEADER_HEIGHT: u64 = 104;
    const ERR_FAILDE_VERIFY_HEADER_PROOF: u64 = 105;
    const ERR_NOT_AIMING_TARGET_NETWORK: u64 = 106;
    const ERR_TRANSACTION_EXECUTE_REPEATE: u64 = 107;
    const ERR_FAILED_VERIFY_SIGNATURE: u64 = 108;
    const ERR_FAILED_VEIRFY_POLY_CHAIN_CUR_EPOCH_HEADER_SIGNATURE: u64 = 109;
    const ERR_EXECUTE_TX_FAILED: u64 = 110;
    const ERR_UNSUPPORT_CHAIN_TYPE: u64 = 111;

    struct EventStore has key, store {
        init_genesis_block_event: Event::EventHandle<InitGenesisBlockEvent>,
        change_book_keeper_event: Event::EventHandle<ChangeBookKeeperEvent>,
        cross_chain_event: Event::EventHandle<CrossChainEvent>,
        verify_header_and_execute_tx_event: Event::EventHandle<VerifyHeaderAndExecuteTxEvent>,
    }

    struct InitGenesisBlockEvent has store, drop {
        height: u128,
        raw_header: vector<u8>
    }

    struct ChangeBookKeeperEvent has store, drop {
        height: u128,
        raw_header: vector<u8>
    }

    struct CrossChainEvent has store, drop {
        sender: vector<u8>,
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

    /* @notice              sync Poly chain genesis block header to smart contrat
    *  @dev                 this function can only be called once, nextbookkeeper of rawHeader can't be empty
    *  @param rawHeader     Poly chain genesis block raw header or raw Header including switching consensus peers info
    *  @return              true or false
    */
    public fun init_genesis_block(signer: &signer,
                                  raw_header: &vector<u8>,
                                  pub_key_list: &vector<u8>) acquires EventStore {
        // // Load Ethereum cross chain data contract
        // IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);

        // // Make sure the contract has not been initialized before
        // require(eccd.getCurEpochConPubKeyBytes().length == 0, "EthCrossChainData contract has already been initialized!");

        // // Parse header and convit the public keys into nextBookKeeper and compare it with header.nextBookKeeper to verify the validity of signature
        // ECCUtils.Header memory header = ECCUtils.deserialize_header(rawHeader);
        // (bytes20 nextBookKeeper, address[] memory keepers) = ECCUtils.verifyPubkey(pubKeyList);
        // require(header.nextBookkeeper == nextBookKeeper, "NextBookers illegal");

        // // Record current epoch start height and public keys (by storing them in address format)
        // require(eccd.putCurEpochStartHeight(header.height), "Save Poly chain current epoch start height to Data contract failed!");
        // require(eccd.putCurEpochConPubKeyBytes(ECCUtils.serializeKeepers(keepers)), "Save Poly chain current epoch book keepers to Data contract failed!");

        // // Fire the event
        // emit InitGenesisBlockEvent(header.height, rawHeader);
        // return true;

        CrossChainGlobal::require_genesis_account(Signer::address_of(signer));

        move_to(signer, EventStore {
            init_genesis_block_event: Event::new_event_handle<InitGenesisBlockEvent>(signer),
            change_book_keeper_event: Event::new_event_handle<ChangeBookKeeperEvent>(signer),
            cross_chain_event: Event::new_event_handle<CrossChainEvent>(signer),
            verify_header_and_execute_tx_event: Event::new_event_handle<VerifyHeaderAndExecuteTxEvent>(signer),
        });

        let pub_key_bytes = CrossChainData::get_cur_epoch_con_pubkey_bytes();
        assert!(Vector::is_empty<u8>(&pub_key_bytes), Errors::invalid_state(ERR_CONTRACT_INITIALIZE_REPEATE));

        let (
            _,
            _,
            _,
            header_height,
            _,
            _,
            _,
            _,
            _,
            _,
            header_next_bookkeeper
        ) = CrossChainLibrary::deserialize_header(raw_header);
        let (next_book_keeper, keepers) = CrossChainLibrary::verify_pubkey(pub_key_list);
        assert!(header_next_bookkeeper == next_book_keeper, Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_ILLEGAL));

        CrossChainData::put_cur_epoch_start_height(header_height);

        let keep_serialized_byte = CrossChainLibrary::serialize_keepers(&keepers);
        CrossChainData::put_cur_epoch_con_pubkey_bytes(keep_serialized_byte);

        let event_store = borrow_global_mut<EventStore>(CrossChainGlobal::genesis_account());
        Event::emit_event(
            &mut event_store.init_genesis_block_event,
            InitGenesisBlockEvent {
                height: (header_height as u128),
                raw_header: *raw_header,
            },
        );
    }


    /* @notice              change Poly chain consensus book keeper
    *  @param rawHeader     Poly chain change book keeper block raw header
    *  @param pubKeyList    Poly chain consensus nodes public key list
    *  @param sigList       Poly chain consensus nodes signature list
    *  @return              true or false
    */
    public fun change_book_keeper(signer: &signer,
                                  raw_header: &vector<u8>,
                                  pub_key_list: &vector<u8>,
                                  sig_list: &vector<u8>) acquires EventStore {
        // // Load Ethereum cross chain data contract
        // ECCUtils.Header memory header = ECCUtils.deserialize_header(rawHeader);
        // IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);

        // // Make sure rawHeader.height is higher than recorded current epoch start height
        // uint64 curEpochStartHeight = eccd.getCurEpochStartHeight();
        // require(header.height > curEpochStartHeight, "The height of header is lower than current epoch start height!");

        // // Ensure the rawHeader is the key header including info of switching consensus peers by containing non-empty nextBookKeeper field
        // require(header.nextBookkeeper != bytes20(0), "The nextBookKeeper of header is empty");

        // // Verify signature of rawHeader comes from pubKeyList
        // address[] memory polyChainBKs = ECCUtils.deserializeKeepers(eccd.getCurEpochConPubKeyBytes());
        // uint n = polyChainBKs.length;
        // require(ECCUtils.verifySig(rawHeader, sigList, polyChainBKs, n - (n - 1) / 3), "Verify signature failed!");

        // // Convert pubKeyList into ethereum address format and make sure the compound address from the converted ethereum addresses
        // // equals passed in header.nextBooker
        // (bytes20 nextBookKeeper, address[] memory keepers) = ECCUtils.verifyPubkey(pubKeyList);
        // require(header.nextBookkeeper == nextBookKeeper, "NextBookers illegal");

        // // update current epoch start height of Poly chain and current epoch consensus peers book keepers addresses
        // require(eccd.putCurEpochStartHeight(header.height), "Save MC LatestHeight to Data contract failed!");
        // require(eccd.putCurEpochConPubKeyBytes(ECCUtils.serializeKeepers(keepers)), "Save Poly chain book keepers bytes to Data contract failed!");

        // // Fire the change book keeper event
        // emit ChangeBookKeeperEvent(header.height, rawHeader);
        // return true;

        CrossChainGlobal::require_admin_account(Signer::address_of(signer));

        let (
            _,
            _,
            _,
            header_height,
            _,
            _,
            _,
            _,
            _,
            _,
            header_next_bookkeeper
        ) = CrossChainLibrary::deserialize_header(raw_header);

        let cur_epoch_start_height = CrossChainData::get_cur_epoch_start_height();

        // Make sure rawHeader.height is higher than recorded current epoch start height
        assert!(header_height > cur_epoch_start_height, Errors::invalid_state(ERR_INVALID_HEADER_HEIGHT));
        assert!(!Vector::is_empty<u8>(&header_next_bookkeeper), Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_EMPTY));

        // Verify signature of rawHeader comes from pubKeyList
        let pub_key_bytes = CrossChainData::get_cur_epoch_con_pubkey_bytes();
        let poly_chain_bks = CrossChainLibrary::deserialize_keepers(&pub_key_bytes);
        let n = Vector::length<vector<u8>>(&poly_chain_bks);
        assert!(CrossChainLibrary::verify_sig(
            raw_header, sig_list, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
            Errors::invalid_state(ERR_FAILED_VERIFY_SIGNATURE));

        // Convert pubKeyList into ethereum address format and make sure the compound address from the converted ethereum addresses
        // equals passed in header.nextBooker
        let (next_book_keeper, keepers) = CrossChainLibrary::verify_pubkey(pub_key_list);
        assert!(header_next_bookkeeper == next_book_keeper, Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_ILLEGAL));

        // update current epoch start height of Poly chain and current epoch consensus peers book keepers addresses
        CrossChainData::put_cur_epoch_start_height(header_height);
        let serialized_keepers = CrossChainLibrary::serialize_keepers(&keepers);
        CrossChainData::put_cur_epoch_con_pubkey_bytes(serialized_keepers);

        // Fire the change book keeper event
        let event_store = borrow_global_mut<EventStore>(CrossChainGlobal::genesis_account());
        Event::emit_event(
            &mut event_store.change_book_keeper_event,
            ChangeBookKeeperEvent {
                height: (header_height as u128),
                raw_header: *raw_header,
            },
        );
    }


    /* @notice              ERC20 token cross chain to other blockchain.
    *                       this function push tx event to blockchain
    *  @param toChainId     Target chain id
    *  @param toContract    Target smart contract address in target block chain
    *  @param txData        Transaction data for target chain, include to_address, amount
    *  @return              true or false
    */
    public fun cross_chain_with_param_pack(signer: &signer,
                                           lock_parameters: CrossChainProcessCombinator::LockToChainParamPack)
    acquires EventStore {
        // // Load Ethereum cross chain data contract
        // IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);

        // // To help differentiate two txs, the ethTxHashIndex is increasing automatically
        // uint256 txHashIndex = eccd.get_eth_tx_hash_index();

        // // Convert the uint256 into bytes
        // bytes memory paramTxHash = Utils.uint256ToBytes(txHashIndex);

        // // Construct the makeTxParam, and put the hash info storage, to help provide proof of tx existence
        // bytes memory rawParam = abi.encodePacked(ZeroCopySink.WriteVarBytes(paramTxHash),
        //     ZeroCopySink.WriteVarBytes(abi.encodePacked(sha256(abi.encodePacked(address(this), paramTxHash)))),
        //     ZeroCopySink.WriteVarBytes(Utils.addressToBytes(msg.sender)),
        //     ZeroCopySink.WriteUint64(toChainId),
        //     ZeroCopySink.WriteVarBytes(toContract),
        //     ZeroCopySink.WriteVarBytes(method),
        //     ZeroCopySink.WriteVarBytes(txData)
        // );

        // // Must save it in the storage to be included in the proof to be verified.
        // require(eccd.put_eth_tx_hash(keccak256(rawParam)), "Save ethTxHash by index to Data contract failed!");

        // // Fire the cross chain event denoting there is a cross chain request from Ethereum network to other public chains through Poly chain network
        // emit CrossChainEvent(tx.origin, paramTxHash, msg.sender, toChainId, toContract, rawParam);
        // return true;

        let (
            to_chain_id,
            to_contract,
            method,
            tx_data
        ) = CrossChainProcessCombinator::unpack_lock_to_chain_parameters(lock_parameters);

        // Check global freezing switch has closed
        CrossChainGlobal::require_not_freezing();

        let account = Signer::address_of(signer);
        let raw_param = Vector::empty<u8>();

        // Tx hash index
        let param_tx_hash = BCS::to_bytes(&CrossChainData::get_eth_tx_hash_index());

        // Reverse little edian to big edian
        Vector::reverse(&mut param_tx_hash);

        // --------- serialize MakeTxParam start ---------
        // Golang version:
        // type MakeTxParam struct {
        // 	TxHash              []byte
        // 	CrossChainID        []byte
        // 	FromContractAddress []byte
        // 	ToChainID           uint64
        // 	ToContractAddress   []byte
        // 	Method              string
        // 	Args                []byte
        // }
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&param_tx_hash));
        // hash genesis_addr and tx_hash to CrossChainID! 
        // Solidity code:
        // Contract address: ZeroCopySink.WriteVarBytes(abi.encodePacked(sha256(abi.encodePacked(address(this), paramTxHash))))
        let genesis_addr_byte = Address::bytify(CrossChainGlobal::genesis_account());
        let cross_chain_id =
            Hash::sha3_256(Bytes::concat(&genesis_addr_byte, *&param_tx_hash));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&cross_chain_id));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&PROXY_HASH_STARCOIN));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_u64(to_chain_id));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&to_contract));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&method));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&tx_data));
        // --------- serialize MakeTxParam end ---------

        // Must save it in the storage to be included in the proof to be verified.
        CrossChainData::put_eth_tx_hash(Hash::keccak_256(*&raw_param));
        let event_store = borrow_global_mut<EventStore>(CrossChainGlobal::genesis_account());

        Event::emit_event(
            &mut event_store.cross_chain_event,
            CrossChainEvent {
                sender: Address::bytify(account),
                tx_id: param_tx_hash,
                proxy_or_asset_contract: PROXY_HASH_STARCOIN,
                to_chain_id,
                to_contract,
                raw_data: raw_param,
            },
        );
    }

    /* verifyHeaderAndExecuteTx
    * @notice              Verify Poly chain header and proof, execute the cross chain tx from Poly chain to Ethereum
    *  @param proof         Poly chain tx merkle proof
    *  @param rawHeader     The header containing crossStateRoot to verify the above tx merkle proof
    *  @param headerProof   The header merkle proof used to verify rawHeader
    *  @param curRawHeader  Any header in current epoch consensus of Poly chain
    *  @param headerSig     The coverted signature veriable for solidity derived from Poly chain consensus nodes' signature
    *                       used to verify the validity of curRawHeader
    *  @return              true or false
    */
    public fun verify_header_with_param_pack(proof: &vector<u8>,
                                             raw_header: &vector<u8>,
                                             header_proof: &vector<u8>,
                                             cur_raw_header: &vector<u8>,
                                             header_sig: &vector<u8>)
    : CrossChainProcessCombinator::HeaderVerifyedParamPack acquires EventStore {
        // Load ehereum cross chain data contract
        let (
            _,
            _,
            _,
            header_height,
            _,
            _,
            _,
            header_cross_states_root,
            _,
            _,
            _
        ) = CrossChainLibrary::deserialize_header(raw_header);

        // Get stored consensus public key bytes of current poly chain epoch and
        // deserialize Poly chain consensus public key bytes to address[]
        let pub_key_bytes = CrossChainData::get_cur_epoch_con_pubkey_bytes();
        let poly_chain_bks = CrossChainLibrary::deserialize_keepers(&pub_key_bytes);
        let cur_epoch_start_height = CrossChainData::get_cur_epoch_start_height();

        let n = Vector::length<vector<u8>>(&poly_chain_bks);
        if (header_height >= cur_epoch_start_height) {
            // It's enough to verify rawHeader signature
            assert!(CrossChainLibrary::verify_sig(raw_header, header_sig, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
                Errors::invalid_state(ERR_FAILED_VERIFY_SIGNATURE));
        } else {
            // We need to verify the signature of curHeader
            assert!(CrossChainLibrary::verify_sig(cur_raw_header, header_sig, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
                Errors::invalid_state(ERR_FAILED_VEIRFY_POLY_CHAIN_CUR_EPOCH_HEADER_SIGNATURE));
            // Then use curHeader.StateRoot and headerProof to verify rawHeader.CrossStateRoot
            let (_, _, _, _, _, _, _, _, block_root, _, _) = CrossChainLibrary::deserialize_header(cur_raw_header);
            let prove_value = CrossChainLibrary::merkle_prove(header_proof, &block_root);
            assert!(CrossChainLibrary::get_header_hash(raw_header) == prove_value,
                Errors::invalid_state(ERR_FAILDE_VERIFY_HEADER_PROOF));
        };

        // Through rawHeader.CrossStateRoot, the toMerkleValue or cross chain msg can be verified and parsed from proof
        let to_merkle_value_bs = CrossChainLibrary::merkle_prove(proof, &header_cross_states_root);

        // Parse the toMerkleValue struct and make sure the tx has not been processed, then mark this tx as processed
        let (
            cross_chain_tx_hash,
            from_chain_id,
            source_chain_tx_hash,
            _,
            from_contract,
            to_chain_id,
            to_contract,
            method,
            args
        ) = CrossChainLibrary::deserialize_merkle_value(&to_merkle_value_bs);

        // Check if from chain transaction is exists
        //        let check_ret =
        //            check_and_mark_transaction_exists<CrossChainType::Starcoin>(
        //                from_chain_id,
        //                &cross_chain_tx_hash,
        //                merkle_proof_root,
        //                merkle_proof_leaf,
        //                merkle_proof_siblings) ||
        //            check_and_mark_transaction_exists<CrossChainType::Ethereum>(
        //                from_chain_id,
        //                &cross_chain_tx_hash,
        //                merkle_proof_root,
        //                merkle_proof_leaf,
        //                merkle_proof_siblings);
        //        assert!(check_ret, Errors::invalid_state(ERR_UNSUPPORT_CHAIN_TYPE));
        // Ethereum ChainId is 2, we need to check the transaction is for Ethereum network
        // assert!(to_chain_id == 2, Errors::invalid_state(ERR_NOT_AIMING_ETHEREUM_NETWORK));

        // TODO: check this part to make sure we commit the next line when doing local net UT test
        //        assert!(execute_cross_chain_tx(
        //            &to_contract,
        //            &method,
        //            &args,
        //            &from_contract,
        //            from_chain_id), Errors::invalid_state(ERR_EXECUTE_TX_FAILED));

        assert!(to_chain_id == CrossChainGlobal::get_chain_id<CrossChainGlobal::STARCOIN_CHAIN>(),
            Errors::invalid_state(ERR_NOT_AIMING_TARGET_NETWORK));

        // Fire the cross chain event denoting the executation of cross chain tx is successful,
        // and this tx is coming from other public chains to current Ethereum network
        let event_store = borrow_global_mut<EventStore>(CrossChainGlobal::genesis_account());
        Event::emit_event(
            &mut event_store.verify_header_and_execute_tx_event,
            VerifyHeaderAndExecuteTxEvent {
                from_chain_id,
                to_contract,
                cross_chain_tx_hash: *&cross_chain_tx_hash,
                from_chain_tx_hash: source_chain_tx_hash,
            },
        );

        //(
        // method,
        // args,
        // from_chain_id,
        // from_contract,
        // CrossChainGlobal::generate_execution_cap(&cross_chain_tx_hash, false),
        // cross_chain_tx_hash,
        //)
        CrossChainProcessCombinator::pack_header_verified_param(method, args, from_chain_id, from_contract, cross_chain_tx_hash)
    }

    // Process undefine execution after verify success.
    public fun undefine_execution(cap: CrossChainGlobal::ExecutionCapability) {
        CrossChainGlobal::destroy_execution_cap(cap);
    }

    // // Check and marking transaction exists
    // public fun check_and_mark_transaction_exists(chain_id: u64,
    //                                              tx_hash: &vector<u8>,
    //                                              merkle_proof_root: &vector<u8>,
    //                                              merkle_proof_leaf: &vector<u8>,
    //                                              merkle_proof_siblings: &vector<vector<u8>>
    // ): CrossChainProofCap::MerkleProofCertificate {
    //     let proof_path_hash = CrossChainSMTProofs::generate_leaf_path(chain_id, tx_hash);
    //
    //     assert!(
    //         CrossChainData::check_chain_tx_not_exists(
    //             &proof_path_hash,
    //             merkle_proof_root,
    //             merkle_proof_leaf,
    //             merkle_proof_siblings),
    //         Errors::invalid_state(ERR_TRANSACTION_EXECUTE_REPEATE));
    //
    //     CrossChainData::mark_from_chain_tx_exists(
    //         &proof_path_hash,
    //         merkle_proof_leaf,
    //         merkle_proof_siblings);
    //
    //     CrossChainProofCap::create_proof_certificate(chain_id, tx_hash, merkle_proof_root, merkle_proof_leaf)
    // }

    public fun cross_chain(_signer: &signer,
                           _to_chain_id: u64,
                           _to_contract: &vector<u8>,
                           _method: &vector<u8>,
                           _tx_data: &vector<u8>,
                           _cap: CrossChainGlobal::ExecutionCapability) {
        abort Errors::invalid_state(ERR_DECREPTED)
    }

    public fun verify_header(_proof: &vector<u8>,
                             _raw_header: &vector<u8>,
                             _header_proof: &vector<u8>,
                             _cur_raw_header: &vector<u8>,
                             _header_sig: &vector<u8>) {
        abort Errors::invalid_state(ERR_DECREPTED)
    }
}

#[test_only]
module Bridge::CrossChainManagerTest {
    use StarcoinFramework::Debug;
    use Bridge::CrossChainLibrary;

    #[test]
    fun testParseUnlockParams1() {
        let proof = x"fd330120f0e4a04a083412175621308d8f08f282e0622d01240e9140f01c82a050ded3e51f0000000000000010000000000000000000000000000000002012cf1c7bb1fe4e4554595f4fec271f038199e43d6f7488d71ce06cf5572db18734307865353235353236333763353839376132643439396662663038323136663733653a3a43726f7373436861696e5363726970741f0000000000000034307865353235353236333763353839376132643439396662663038323136663733653a3a43726f7373436861696e53637269707406756e6c6f636b5e2c307830303030303030303030303030303030303030303030303030303030303030313a3a5354433a3a5354431007fa08a855753f0ff7292fdcbe8712160065cd1d00000000000000000000000000000000000000000000000000000000";
        let raw_header = x"00000000000000000000000094dbf9a18209be1aea35dc2eeacac442ce37afe1f0a471d6733ec473a82f857c820a317e777ca6074d65459022b362bf4aa2b28e8b09f2218bc59d4ab1378ed3e48040cadb9de17c286f59bd2036301897b685e4ebb5232fd15104f85b50d5c577375c8410a9c2d88ac26888e5a39c7febed1bb96181cb40161b34c328992b2dfd509f628e913501936f061a1314a8bbfd13017b226c6561646572223a342c227672665f76616c7565223a22424d733836683851774b7535655a4a394c43756a7075596a4d4f78326e463352366748695165444c347279367932305a4d5866323047707a70616e2b397a4a6376614c53376e71643945304b6b65396c657569486b67303d222c227672665f70726f6f66223a226f6d566b337a32304a51637675564653623145624b45547641507969494f77476b736963576e5075686b474878435a78336c303764506437326555377a576b44576658777450536153596776467a31394f34316d70773d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a32303238303030302c226e65775f636861696e5f636f6e666967223a6e756c6c7d0000000000000000000000000000000000000000";
        let (
            _,
            _,
            _,
            _header_height,
            _,
            _,
            _,
            header_cross_states_root,
            _,
            _,
            _
        ) = CrossChainLibrary::deserialize_header(&raw_header);

        // Through rawHeader.CrossStateRoot, the toMerkleValue or cross chain msg can be verified and parsed from proof
        let to_merkle_value_bs = CrossChainLibrary::merkle_prove(&proof, &header_cross_states_root);

        // Parse the toMerkleValue struct and make sure the tx has not been processed, then mark this tx as processed
        let (
            _cross_chain_tx_hash,
            _from_chain_id,
            _source_chain_tx_hash,
            _,
            _from_contract,
            _to_chain_id,
            _to_contract,
            _method,
            args
        ) = CrossChainLibrary::deserialize_merkle_value(&to_merkle_value_bs);
        Debug::print(&_cross_chain_tx_hash);
        Debug::print(&_from_chain_id);
        Debug::print(&_source_chain_tx_hash);
        Debug::print(&_from_contract);
        Debug::print(&_to_chain_id);
        Debug::print(&_to_contract);
        Debug::print(&_method);
        Debug::print(&args);
        let (
            to_asset_hash,
            to_address,
            amount,
        ) = CrossChainLibrary::deserialize_tx_args(args);
        Debug::print(&to_asset_hash);
        Debug::print(&to_address);
        Debug::print(&amount);
    }
}
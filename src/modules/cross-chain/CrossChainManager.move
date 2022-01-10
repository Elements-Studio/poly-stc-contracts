address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainManager {
    use 0x1::Vector;
    use 0x1::Event;
    use 0x1::Errors;
    use 0x1::Signer;
    use 0x1::BCS;
    use 0x1::Hash;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::Address;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainData;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainLibrary;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::ZeroCopySink;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::MerkleProofHelper;

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

    struct ChainInfo has key, store {
        current_chain_id: u64,
    }

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
                                  current_chain_id: u64,
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

        move_to(signer, ChainInfo {
            current_chain_id,
        });

        move_to(signer, EventStore {
            init_genesis_block_event: Event::new_event_handle<InitGenesisBlockEvent>(signer),
            change_book_keeper_event: Event::new_event_handle<ChangeBookKeeperEvent>(signer),
            cross_chain_event: Event::new_event_handle<CrossChainEvent>(signer),
            verify_header_and_execute_tx_event: Event::new_event_handle<VerifyHeaderAndExecuteTxEvent>(signer),
        });

        let pub_key_bytes = CrossChainData::get_cur_epoch_con_pubkey_bytes();
        assert(Vector::is_empty<u8>(&pub_key_bytes), Errors::invalid_state(ERR_CONTRACT_INITIALIZE_REPEATE));

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
        assert(header_next_bookkeeper == next_book_keeper, Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_ILLEGAL));

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

        CrossChainGlobal::require_genesis_account(Signer::address_of(signer));

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
        assert(header_height > cur_epoch_start_height, Errors::invalid_state(ERR_INVALID_HEADER_HEIGHT));
        assert(!Vector::is_empty<u8>(&header_next_bookkeeper), Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_EMPTY));

        // Verify signature of rawHeader comes from pubKeyList
         let pub_key_bytes = CrossChainData::get_cur_epoch_con_pubkey_bytes();
         let poly_chain_bks = CrossChainLibrary::deserialize_keepers(&pub_key_bytes);
         let n = Vector::length<vector<u8>>(&poly_chain_bks);
         assert(CrossChainLibrary::verify_sig(
             raw_header, sig_list, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
             Errors::invalid_state(ERR_FAILED_VERIFY_SIGNATURE));

        // Convert pubKeyList into ethereum address format and make sure the compound address from the converted ethereum addresses
        // equals passed in header.nextBooker
        let (next_book_keeper, keepers) = CrossChainLibrary::verify_pubkey(pub_key_list);
        assert(header_next_bookkeeper == next_book_keeper, Errors::invalid_state(ERR_NEXT_BOOK_KEEPER_ILLEGAL));

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
    public fun cross_chain(signer: &signer,
                           to_chain_id: u64,
                           to_contract: &vector<u8>,
                           method: &vector<u8>,
                           tx_data: &vector<u8>,
                           cap: CrossChainGlobal::ExecutionCapability) acquires EventStore {
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

        // Capability handle
        CrossChainGlobal::verify_execution_cap(&cap, tx_data);
        CrossChainGlobal::destroy_execution_cap(cap);

        let account = Signer::address_of(signer);
        CrossChainGlobal::require_genesis_account(account);

        let raw_param = Vector::empty<u8>();

        // Tx hash index
        let param_tx_hash = BCS::to_bytes(&CrossChainData::get_eth_tx_hash_index());

        // Reverse little edian to big edian
        Vector::reverse(&mut param_tx_hash);

        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&param_tx_hash));

        // Contract address: ZeroCopySink.WriteVarBytes(abi.encodePacked(sha256(abi.encodePacked(address(this), paramTxHash))))
        let genesis_addr_byte = Address::bytify(CrossChainGlobal::genesis_account());
        let contract_addr_serialize =
            Hash::sha3_256(Bytes::concat(&genesis_addr_byte, *&param_tx_hash));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&contract_addr_serialize));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(&Address::bytify(account)));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_u64(to_chain_id));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(to_contract));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(method));
        raw_param = Bytes::concat(&raw_param, ZeroCopySink::write_var_bytes(tx_data));

        // Must save it in the storage to be included in the proof to be verified.
        CrossChainData::put_eth_tx_hash(Hash::keccak_256(*&raw_param));
        let event_store = borrow_global_mut<EventStore>(CrossChainGlobal::genesis_account());

        Event::emit_event(
            &mut event_store.cross_chain_event,
            CrossChainEvent {
                sender: Address::bytify(account),
                tx_id: param_tx_hash,
                proxy_or_asset_contract: b"0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager",//Address::bytify(CrossChainGlobal::genesis_account()),
                to_chain_id,
                to_contract: *to_contract,
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
    public fun verify_header(proof: &vector<u8>,
                             raw_header: &vector<u8>,
                             header_proof: &vector<u8>,
                             cur_raw_header: &vector<u8>,
                             header_sig: &vector<u8>)
    : (
        vector<u8>, // method
        vector<u8>, // args
        u64, // chain id
        vector<u8>, // from_contract
        CrossChainGlobal::ExecutionCapability,
        vector<u8>, // tx hash
    ) acquires EventStore, ChainInfo {

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
            assert(CrossChainLibrary::verify_sig(raw_header, header_sig, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
                Errors::invalid_state(ERR_FAILED_VERIFY_SIGNATURE));
        } else {
            // We need to verify the signature of curHeader
            assert(CrossChainLibrary::verify_sig(cur_raw_header, header_sig, &poly_chain_bks, ((n - (n - 1) / 3) as u64)),
                Errors::invalid_state(ERR_FAILED_VEIRFY_POLY_CHAIN_CUR_EPOCH_HEADER_SIGNATURE));
            // Then use curHeader.StateRoot and headerProof to verify rawHeader.CrossStateRoot
            let (_, _, _, _, _, _, _, _, block_root, _, _) = CrossChainLibrary::deserialize_header(cur_raw_header);
            let prove_value = CrossChainLibrary::merkle_prove(header_proof, &block_root);
            assert(CrossChainLibrary::get_header_hash(raw_header) == prove_value,
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
//        assert(check_ret, Errors::invalid_state(ERR_UNSUPPORT_CHAIN_TYPE));
        // Ethereum ChainId is 2, we need to check the transaction is for Ethereum network
        // assert(to_chain_id == 2, Errors::invalid_state(ERR_NOT_AIMING_ETHEREUM_NETWORK));

        // TODO: check this part to make sure we commit the next line when doing local net UT test
        //        assert(execute_cross_chain_tx(
        //            &to_contract,
        //            &method,
        //            &args,
        //            &from_contract,
        //            from_chain_id), Errors::invalid_state(ERR_EXECUTE_TX_FAILED));


        let genesis_account = CrossChainGlobal::genesis_account();
        let chain_info = borrow_global<ChainInfo>(genesis_account);
        assert(to_chain_id == chain_info.current_chain_id, Errors::invalid_state(ERR_NOT_AIMING_TARGET_NETWORK));

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

        (
            method,
            args,
            from_chain_id,
            from_contract,
            CrossChainGlobal::generate_execution_cap(&cross_chain_tx_hash, false),
            cross_chain_tx_hash,
        )
    }

    /// Process undefine execution after verify success.
    public fun undefine_execution(cap: CrossChainGlobal::ExecutionCapability) {
        CrossChainGlobal::destroy_execution_cap(cap);
    }

    /// Check and marking transaction exists
    public fun check_and_mark_transaction_exists(chain_id: u64,
                                                 tx_hash: &vector<u8>,
                                                 merkle_proof_root: &vector<u8>,
                                                 merkle_proof_leaf: &vector<u8>,
                                                 merkle_proof_siblings: &vector<vector<u8>>,
                                                 cap: &mut CrossChainGlobal::ExecutionCapability
    ) {
        let proof_path_hash = MerkleProofHelper::gen_proof_path(chain_id, tx_hash);

        assert(
            CrossChainData::check_chain_tx_not_exists(
                &proof_path_hash,
                merkle_proof_root,
                merkle_proof_leaf,
                merkle_proof_siblings),
            Errors::invalid_state(ERR_TRANSACTION_EXECUTE_REPEATE));

        CrossChainData::mark_from_chain_tx_exists(
            &proof_path_hash,
            merkle_proof_leaf,
            merkle_proof_siblings);

        CrossChainGlobal::tx_hash_has_proof(cap);
    }

}
}
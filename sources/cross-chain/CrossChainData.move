module Bridge::CrossChainData {

    use Bridge::CrossChainGlobal;
    use Bridge::CrossChainSMTProofs;
    use Bridge::SMTProofs;
    use Bridge::SMTUtils;
    use Bridge::SMTreeHasher;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Signer;
    use StarcoinFramework::Vector;

    const LEAF_DATA_VALUE_HASH_START_INDEX: u64 = 33;
    const LEAF_DATA_LEN: u64 = 65;

    const ERR_INITIALIZED_REPEATE: u64 = 101;
    const ERR_PROOF_HASH_INVALID: u64 = 102;
    const ERR_PROOF_ROOT_HASH_INVALID: u64 = 103;
    const ERR_NON_MEMBERSHIP_LEAF_DATA_INVALID: u64 = 104;

    struct Consensus has key, store {
        //  When Poly chain switches the consensus epoch book keepers, the consensus peers public keys of Poly chain should be 
        //  changed into no-compressed version so that solidity smart contract can convert it to address type and 
        //  verify the signature derived from Poly chain account signature.
        //  ConKeepersPkBytes means Consensus book Keepers Public Key Bytes
        con_keepers_pk_bytes: vector<u8>,

        // CurEpochStartHeight means Current Epoch Start Height of Poly chain block
        cur_epoch_start_height: u64,

        // This index records the current Map length
        eth_to_poly_tx_hash_index: u128,

        /*
         Ethereum cross chain tx hash indexed by the automatically increased index.
         This map exists for the reason that Poly chain can verify the existence of 
         cross chain request tx coming from Ethereum
        */
        eth_to_poly_tx_hash: vector<vector<u8>>
    }

    // SMT hash root key
    struct SparseMerkleTreeRoot has key, store {
        hash: vector<u8>
    }

    // This function called from cross chain data
    public fun init_genesis(signer: &signer) {
        let account = Signer::address_of(signer);
        CrossChainGlobal::require_genesis_account(account);

        // repeate check
        assert!(!exists<Consensus>(account), Errors::invalid_state(ERR_INITIALIZED_REPEATE));

        move_to(signer, Consensus {
            con_keepers_pk_bytes: Vector::empty<u8>(),
            cur_epoch_start_height: 0,
            eth_to_poly_tx_hash_index: 0,
            eth_to_poly_tx_hash: Vector::empty<vector<u8>>()
        });

        // Repeate check
        assert!(!exists<SparseMerkleTreeRoot>(Signer::address_of(signer)),
            Errors::invalid_state(ERR_INITIALIZED_REPEATE));
        move_to(signer, SparseMerkleTreeRoot {
            hash: *&SMTreeHasher::placeholder()
        });
    }

    public fun put_cur_epoch_con_pubkey_bytes(bytes: vector<u8>) acquires Consensus {
        let consesus = borrow_global_mut<Consensus>(CrossChainGlobal::genesis_account());
        consesus.con_keepers_pk_bytes = bytes;
    }

    public fun get_cur_epoch_con_pubkey_bytes(): vector<u8> acquires Consensus {
        let consesus = borrow_global<Consensus>(CrossChainGlobal::genesis_account());
        //CrosschainUtils::duplicate_vector<u8>(&consesus.conKeepersPkBytes)
        *&consesus.con_keepers_pk_bytes
    }

    public fun put_cur_epoch_start_height(curEpochStartHeight: u64) acquires Consensus {
        let consesus = borrow_global_mut<Consensus>(CrossChainGlobal::genesis_account());
        consesus.cur_epoch_start_height = curEpochStartHeight;
    }

    public fun get_cur_epoch_start_height(): u64 acquires Consensus {
        let consesus = borrow_global_mut<Consensus>(CrossChainGlobal::genesis_account());
        consesus.cur_epoch_start_height
    }

    // Get current recorded index of cross chain txs requesting from Ethereum to other public chains
    // in order to help cross chain manager contract differenciate two cross chain tx requests
    public fun get_eth_tx_hash_index(): u128 acquires Consensus {
        let consesus = borrow_global_mut<Consensus>(CrossChainGlobal::genesis_account());
        consesus.eth_to_poly_tx_hash_index
    }

    // Store Ethereum cross chain tx hash, increase the index record by 1
    public fun put_eth_tx_hash(eth_tx_hash: vector<u8>) acquires Consensus {
        let consesus = borrow_global_mut<Consensus>(CrossChainGlobal::genesis_account());
        consesus.eth_to_poly_tx_hash_index = consesus.eth_to_poly_tx_hash_index + 1;
        Vector::push_back<vector<u8>>(&mut consesus.eth_to_poly_tx_hash, eth_tx_hash);
    }

    // Get Ethereum cross chain tx hash indexed by ethTxHashIndex
    public fun get_eth_tx_hash(eth_tx_hash_index: u64): vector<u8> acquires Consensus {
        let consesus = borrow_global<Consensus>(CrossChainGlobal::genesis_account());
        let eth_to_poly_hash = Vector::borrow<vector<u8>>(&consesus.eth_to_poly_tx_hash, eth_tx_hash_index);
        *eth_to_poly_hash
    }


    // Query merkle root hash from data
    public fun get_merkle_root_hash(): vector<u8> acquires SparseMerkleTreeRoot {
        let smt = borrow_global<SparseMerkleTreeRoot>(CrossChainGlobal::genesis_account());
        *&smt.hash
    }

    // Mark from chain tx fromChainTx as exist or processed
    public fun mark_from_chain_tx_exists(
        input_hash: &vector<u8>,
        proof_leaf: &vector<u8>,
        proof_siblings: &vector<vector<u8>>)
    acquires SparseMerkleTreeRoot {
        let smt_root = borrow_global_mut<SparseMerkleTreeRoot>(CrossChainGlobal::genesis_account());
        smt_root.hash = SMTProofs::compute_root_hash_new_leaf_included(input_hash,
            &CrossChainSMTProofs::leaf_default_value_hash(),
            proof_leaf,
            proof_siblings);
    }

    // Check if from chain tx fromChainTx has been processed before
    public fun check_chain_tx_not_exists(
        input_hash: &vector<u8>,
        proof_root: &vector<u8>,
        proof_leaf: &vector<u8>,
        proof_siblings: &vector<vector<u8>>
    ): bool acquires SparseMerkleTreeRoot {
        let smt_root = borrow_global_mut<SparseMerkleTreeRoot>(CrossChainGlobal::genesis_account());
        assert!(*&smt_root.hash == *proof_root, Errors::invalid_state(ERR_PROOF_ROOT_HASH_INVALID));
        assert!(*proof_leaf == x""
                || SMTUtils::sub_u8_vector(proof_leaf, LEAF_DATA_VALUE_HASH_START_INDEX, LEAF_DATA_LEN) == CrossChainSMTProofs::leaf_default_value_hash(),
            Errors::invalid_argument(ERR_NON_MEMBERSHIP_LEAF_DATA_INVALID));
        SMTProofs::verify_non_membership_proof_by_leaf_path(&smt_root.hash, proof_leaf, proof_siblings, input_hash)
    }

//    #[test]
//    fun test_check_chain_tx_not_exists() {
//        let _path = x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3";
//        let _root_hash = x"e12e95cee66ba3866b02ac8da4fe70252954773bdc6a9ba9df479d848668e360";
//        let proof_leaf = x"0089bd5770d361dfa0c06a8c1cf4d89ef194456ab5cf8fc55a9f6744aff0bfef812767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7";
//        let siblings = Vector::empty<vector<u8>>();
//        Vector::push_back(&mut siblings, x"67fca48cb86777e28bdb0d29cea95266d83338b9248ac3ebe7ca04b7c054c1d3");
//        Vector::push_back(&mut siblings, x"f7cab8f8c82042e3831a4bc4be6313e76a5e613e8551ef2b693de568bb2384c9");
//        Vector::push_back(&mut siblings, x"0000000000000000000000000000000000000000000000000000000000000000");
//        Vector::push_back(&mut siblings, x"5f8eead34f151a5f2d28b4c382004748648b78e2acbee0c3943d67af41791bd1");
//        _ = siblings;
//        assert!(*&proof_leaf == x""
//                || SMTUtils::sub_u8_vector(&proof_leaf, LEAF_DATA_VALUE_HASH_START_INDEX, LEAF_DATA_LEN) == CrossChainSMTProofs::leaf_default_value_hash(),
//            Errors::invalid_argument(ERR_NON_MEMBERSHIP_LEAF_DATA_INVALID));
//    }
}
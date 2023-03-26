module Bridge::zion_cross_chain_utils {

    use Bridge::zion_utils;
    use StarcoinFramework::BCS;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Option;
    use StarcoinFramework::Secp256k1;
    use StarcoinFramework::Vector;

    #[test_only] use StarcoinFramework::Debug;

    struct Extra has copy, drop {
        epoch_end_height: u64,
        validators: vector<vector<u8>>,
    }

    struct Header has copy, drop {
        root: vector<u8>,
        number: u128,
    }

    struct ToMerkleValue has copy, drop {
        txHash: vector<u8>,
        fromChainID: u64,
        makeTxParam: TxParam
    }

    struct TxParam has copy, drop {
        txHash: vector<u8>,
        crossChainId: vector<u8>,
        fromContract: vector<u8>,
        toChainId: u64,
        toContract: vector<u8>,
        method: vector<u8>,
        args: vector<u8>
    }

    const ZION_SEAL_RLP_LEN: u64 = 67;
    // rlpPrefix: 2 , r: 32 , s:32 , v:1
    const ZION_PEER_RLP_LEN: u64 = 93;
    // rlpPrefix: 2 , pk_rlp: 70 , address_rlp: 21
    const ZION_ADDRESS_RLP_LEN: u64 = 21;
    // rlpPrefix: 1 , address: 20
    const ZION_ADDRESS_LEN: u64 = 20;
    const EVM_SLOT_LENGTH: u64 = 32;
    const ZION_SEAL_LEN: u64 = 65;
    const APTOS_SIG_LEN: u64 = 64;

    const RLP_SPLIT_EINVALID_DATA_LENGTH: u64 = 1;
    const RLP_U128_EINVALID_DATA_LENGTH: u64 = 2;
    const RLP_U64_EINVALID_DATA_LENGTH: u64 = 3;
    const RLP_ZION_ADDRESS_EINVALID_DATA_LENGTH: u64 = 4;
    const RLP_BYTES32_EINVALID_DATA_LENGTH: u64 = 5;
    const DECODE_HEADER_EINVALID_EXTRA_VALIDATOR_SET: u64 = 6;
    const ECRECOVER_EINVALID_SIGNATURE: u64 = 7;
    const VERIFY_PROOF_EUNEQUAL_NODE_HASH: u64 = 8;
    const VERIFY_PROOF_EINVALID_KEY: u64 = 9;
    const RLP_U256_EINVALID_DATA_LENGTH: u64 = 10;

    /*
            
        __  __ ____ _____   ____  ____   ___   ___  _____ 
        |  \/  |  _ \_   _| |  _ \|  _ \ / _ \ / _ \|  ___|
        | |\/| | |_) || |   | |_) | |_) | | | | | | | |_   
        | |  | |  __/ | |   |  __/|  _ <| |_| | |_| |  _|  
        |_|  |_|_|    |_|   |_|   |_| \_\\___/ \___/|_|    
                                                    
    */
    public fun verify_account_proof(
        account_proof: &vector<u8>,
        header_root: &vector<u8>,
        account_addr: &vector<u8>,
        storage_proof: &vector<u8>,
        storage_index: &vector<u8>,
    ): vector<u8> {
        let account_key = Hash::keccak_256(*account_addr);
        let account = verify_mpt_proof(account_proof, &account_key, header_root);

        (account, _) = rlp_split(&account, 0);
        let (_, offset) = rlp_split(&account, 0); // nonce
        (_, offset) = rlp_split(&account, offset); // balance
        let (storage_root, _) = rlp_split(&account, offset);

        let storage_key = Hash::keccak_256(*storage_index);
        let (value, _) = rlp_split(&verify_mpt_proof(storage_proof, &storage_key, &storage_root), 0);
        value
    }

    public fun verify_mpt_proof(proof_rlp: &vector<u8>, key_bytes: &vector<u8>, root: &vector<u8>): vector<u8> {
        let key_hex = key_bytes_to_hex(key_bytes);
        let (proof, _) = rlp_split(proof_rlp, 0);
        let offset = 0;
        let size = Vector::length(&proof);
        let value = *root;
        while (offset < size) {
            let node;
            assert!(check_node_hash(&proof, offset, &value), VERIFY_PROOF_EUNEQUAL_NODE_HASH);
            (node, offset) = rlp_split(&proof, offset);
            let (size_tmp, offset_tmp) = rlp_read_kind(&node, 0);
            (size_tmp, offset_tmp) = rlp_read_kind(&node, size_tmp + offset_tmp);
            offset_tmp = offset_tmp + size_tmp;
            if (offset_tmp == Vector::length<u8>(&node)) {
                // shortNode
                let (key_element, _offset) = rlp_split(&node, 0);
                let sub_key = key_compact_to_hex(&key_element);
                assert!(compare_and_slice_key(&mut key_hex, &sub_key), VERIFY_PROOF_EINVALID_KEY);
                (value, _) = rlp_split(&node, _offset);
            } else {
                // fullNode
                let index = Vector::remove(&mut key_hex, 0);
                let _offset = 0;
                let i = 0;
                while (i < index) {
                    i = i + 1;
                    (size_tmp, offset_tmp) = rlp_read_kind(&node, _offset);
                    _offset = offset_tmp + size_tmp;
                };
                (value, _) = rlp_split(&node, _offset);
            };
            if (Vector::length(&key_hex) == 0) break;
        };
        assert!(Vector::length(&key_hex) == 0, VERIFY_PROOF_EINVALID_KEY);
        value
    }

    public fun check_node_hash(raw: &vector<u8>, offset: u64, hash: &vector<u8>): bool {
        let (size, offset_) = rlp_read_kind(raw, offset);
        let full_size = size + offset_ - offset;
        let node = zion_utils::slice(raw, offset, full_size);
        if (full_size < 32) {
            node == *hash
        } else {
            Hash::keccak_256(node) == *hash
        }
    }

    public fun compare_and_slice_key(key: &mut vector<u8>, element: &vector<u8>): bool {
        let element_len = Vector::length(element);
        let key_len = Vector::length(key);
        if (key_len < element_len) return false;
        if (zion_utils::slice(key, 0, element_len) == *element) {
            *key = zion_utils::slice(key, element_len, key_len - element_len);
            true
        } else {
            false
        }
    }

    public fun get_cross_tx_storage_slot(zion_tx_hash: vector<u8>, to_chain_id: u64): vector<u8> {
        // []byte("request") = 72657175657374
        let key = x"72657175657374";
        Vector::append(&mut key, BCS::to_bytes<u64>(&to_chain_id));
        Vector::append(&mut key, zion_tx_hash);
        Hash::keccak_256(key)
    }

    public fun key_bytes_to_hex(key_bytes: &vector<u8>): vector<u8> {
        let len = Vector::length(key_bytes);
        let key_hex = Vector::empty<u8>();
        let index = 0;
        while (index < len) {
            let b = *Vector::borrow(key_bytes, index);
            Vector::push_back(&mut key_hex, b >> 4);
            Vector::push_back(&mut key_hex, b & 0x0f);
            index = index + 1;
        };
        Vector::push_back(&mut key_hex, 0x10);
        key_hex
    }

    public fun key_compact_to_hex(key_compact: &vector<u8>): vector<u8> {
        let kc0 = *Vector::borrow(key_compact, 0);
        let t = kc0 >> 4;
        let has_term = (t == 2 || t == 3);
        let is_odd = (t == 1 || t == 3);
        let key_hex = Vector::empty<u8>();
        if (is_odd) Vector::push_back(&mut key_hex, kc0 & 0x0f);
        let compact_len = Vector::length(key_compact);
        let i = 0;
        while (i < compact_len - 1) {
            i = i + 1;
            let kci = *Vector::borrow(key_compact, i);
            Vector::push_back(&mut key_hex, kci >> 4);
            Vector::push_back(&mut key_hex, kci & 0x0f);
        };
        if (has_term) Vector::push_back(&mut key_hex, 0x10);
        key_hex
    }

    public fun hex_to_compact(key_hex: &vector<u8>): vector<u8> {
        let hex_len = Vector::length(key_hex);
        if (hex_len == 0) return x"00";
        let t: u8 = 0;
        let is_odd = hex_len % 2;
        let compact_len = hex_len / 2 + 1;
        if (*Vector::borrow(key_hex, hex_len - 1) == 0x10) {
            t = t + 2;
            is_odd = 1 - is_odd;
            compact_len = (hex_len + 1) / 2;
        };
        t = t + (is_odd as u8);
        let key_compact = Vector::empty<u8>();
        let prefix = (t << 4) + if (is_odd == 1) *Vector::borrow(key_hex, 0) else 0x00;
        Vector::push_back(&mut key_compact, prefix);
        let i = 0;
        while (i < compact_len - 1) {
            let left = *Vector::borrow(key_hex, 2 * i + is_odd);
            let right = *Vector::borrow(key_hex, 2 * i + is_odd + 1);
            Vector::push_back(&mut key_compact, (left << 4) + right);
            i = i + 1;
        };
        key_compact
    }

    /*

        _   _ _____    _    ____  _____ ____   __     _______ ____  ___ _____ ___ ____    _  _____ ___ ___  _   _ 
        | | | | ____|  / \  |  _ \| ____|  _ \  \ \   / / ____|  _ \|_ _|  ___|_ _/ ___|  / \|_   _|_ _/ _ \| \ | |
        | |_| |  _|   / _ \ | | | |  _| | |_) |  \ \ / /|  _| | |_) || || |_   | | |     / _ \ | |  | | | | |  \| |
        |  _  | |___ / ___ \| |_| | |___|  _ <    \ V / | |___|  _ < | ||  _|  | | |___ / ___ \| |  | | |_| | |\  |
        |_| |_|_____/_/   \_\____/|_____|_| \_\    \_/  |_____|_| \_\___|_|   |___\____/_/   \_\_| |___\___/|_| \_|
                                                                                                                    
    */
    public fun verify_header(
        header_hash: &vector<u8>,
        raw_seals: &vector<u8>,
        validators: &vector<vector<u8>>,
    ): bool {
        let seals;
        let signers = Vector::empty<vector<u8>>();
        (seals, _) = rlp_split(raw_seals, 0);
        let seal_cnt = Vector::length<u8>(&seals) / ZION_SEAL_RLP_LEN;
        let index = seal_cnt;
        let offset = 0;
        while (index > 0) {
            index = index - 1;
            let seal;
            (seal, offset) = rlp_split(&seals, offset);
            Vector::push_back(&mut signers, verify_seal(header_hash, &seal));
        };
        has_enough_signer(validators, &signers)
    }

    public fun has_enough_signer(
        validators: &vector<vector<u8>>,
        signers: &vector<vector<u8>>,
    ): bool {
        let m = Vector::length(validators) * 2 / 3 + 1;
        let v_copy = *validators;
        let valid_signer_cnt = 0;
        let index = Vector::length(signers);
        while (index > 0) {
            index = index - 1;
            let s = Vector::borrow(signers, index);
            let (exist, v_index) = Vector::index_of(&v_copy, s);
            if (!exist) continue;
            Vector::remove<vector<u8>>(&mut v_copy, v_index);
            valid_signer_cnt = valid_signer_cnt + 1;
        };
        valid_signer_cnt >= m
    }

    public fun verify_seal(
        msg_hash: &vector<u8>,
        seal: &vector<u8>,
    ): vector<u8> {
        let sig_bytes = zion_utils::slice(seal, 0, APTOS_SIG_LEN);
        let recovery_id = *Vector::borrow<u8>(seal, APTOS_SIG_LEN);
        ecrecover(msg_hash, &sig_bytes, recovery_id)
    }

    public fun ecrecover(
        msg_hash: &vector<u8>,
        sig_bytes: &vector<u8>,
        recovery_id: u8,
    ): vector<u8> {
        let sig = Secp256k1::ecdsa_signature_from_bytes(*sig_bytes);
        let signer_opt = Secp256k1::ecdsa_recover(*msg_hash, recovery_id, &sig);
        assert!(Option::is_some(&signer_opt), ECRECOVER_EINVALID_SIGNATURE);
        ecdsa_public_key_to_zion_address(&Option::destroy_some<Secp256k1::ECDSARawPublicKey>(signer_opt))
    }
    //
    public fun ecdsa_public_key_to_zion_address(pk: &Secp256k1::ECDSARawPublicKey): vector<u8> {
        let pk_bytes = Secp256k1::ecdsa_raw_public_key_to_bytes(pk);
        let pk_hash = Hash::keccak_256(pk_bytes);
        zion_utils::slice(&pk_hash, Vector::length<u8>(&pk_hash) - ZION_ADDRESS_LEN, ZION_ADDRESS_LEN)
    }

    public fun get_header_hash(raw_header: vector<u8>): vector<u8> {
        Hash::keccak_256(raw_header)
    }

    /*

        ____ ___  ____  _____ ____ ____  
        / ___/ _ \|  _ \| ____/ ___/ ___| 
        | |  | | | | | | |  _|| |   \___ \ 
        | |__| |_| | |_| | |__| |___ ___) |
        \____\___/|____/|_____\____|____/ 
                                            
    */

    // return (root, number)
    public fun decode_header(
        raw_header: &vector<u8>,
    ): (vector<u8>, u64) {
        let root;
        let number;
        let size;
        let offset = 0;
        (_, offset) = rlp_read_kind(raw_header, offset);
        (root, _) = rlp_get_next_bytes(raw_header, offset + 87); // position of Root
        (size, offset) = rlp_read_kind(raw_header, offset + 445); // position of Difficulty
        (number, _) = rlp_get_next_u256(raw_header, offset + size); // position of Number
        (root, (number as u64))
    }

    // return (epoch_end_height, validators)
    public fun decode_extra(
        raw_header: &vector<u8>,
    ): (u64, vector<vector<u8>>) {
        let epoch_end_height;
        let validator_bytes;
        let validators = Vector::empty<vector<u8>>();
        let size;
        let offset = 0;
        (_, offset) = rlp_read_kind(raw_header, offset);
        (size, offset) = rlp_read_kind(raw_header, offset + 445); // position of Difficulty
        (size, offset) = rlp_read_kind(raw_header, offset + size); // position of Number
        (size, offset) = rlp_read_kind(raw_header, offset + size); // position of GasLimit
        (size, offset) = rlp_read_kind(raw_header, offset + size); // position of GasUsed
        (size, offset) = rlp_read_kind(raw_header, offset + size); // position of Time
        (_,offset) = rlp_read_kind(raw_header, offset + size); // position of Extra(with digest)
        (_,offset) = rlp_read_kind(raw_header, offset + 0x20); // position of Extra(without digest) , a bytes32 digest is appended before extra
        (size, offset) = rlp_read_kind(raw_header, offset); // position of Extra.EpochStartHeight
        (epoch_end_height, offset) = rlp_get_next_u64(raw_header, offset + size); // position of Extra.EpochEndHeight
        (validator_bytes, _) = rlp_get_next_bytes(raw_header, offset);
        size = Vector::length<u8>(&validator_bytes);
        assert!(size % ZION_ADDRESS_RLP_LEN == 0, DECODE_HEADER_EINVALID_EXTRA_VALIDATOR_SET);
        let len = size / ZION_ADDRESS_RLP_LEN;
        let index = 0;
        while (index < len) {
            let validator_addr;
            (validator_addr, _) = rlp_get_next_zion_address(&validator_bytes, index * ZION_ADDRESS_RLP_LEN);
            Vector::push_back(&mut validators, validator_addr);
            index = index + 1;
        };
        (epoch_end_height, validators)
    }

    public fun decode_cross_tx(
        raw_tx: &vector<u8>,
    ): (
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
    ) {
        let txHash: vector<u8>;
        let fromChainID: u64;
        let txParam_txHash: vector<u8>;
        let txParam_crossChainId: vector<u8>;
        let txParam_fromContract: vector<u8>;
        let txParam_toChainId: u64;
        let txParam_toContract: vector<u8>;
        let txParam_method: vector<u8>;
        let txParam_args: vector<u8>;
        let offset: u64 = 0;

        (_, offset) = rlp_read_kind(raw_tx, offset);
        (txHash, offset) = rlp_get_next_bytes(raw_tx, offset);
        (fromChainID, offset) = rlp_get_next_u64(raw_tx, offset);
        (_, offset) = rlp_read_kind(raw_tx, offset);
        (txParam_txHash, offset) = rlp_get_next_bytes(raw_tx, offset);
        (txParam_crossChainId, offset) = rlp_get_next_bytes(raw_tx, offset);
        (txParam_fromContract, offset) = rlp_get_next_bytes(raw_tx, offset);
        (txParam_toChainId, offset) = rlp_get_next_u64(raw_tx, offset);
        (txParam_toContract, offset) = rlp_get_next_bytes(raw_tx, offset);
        (txParam_method, offset) = rlp_get_next_bytes(raw_tx, offset);
        (txParam_args, _) = rlp_get_next_bytes(raw_tx, offset);

        (
            txHash,
            fromChainID,
            txParam_txHash,
            txParam_crossChainId,
            txParam_fromContract,
            txParam_toChainId,
            txParam_toContract,
            txParam_method,
            txParam_args,
        )
    }

    // evm.abi.encode 
    public fun encode_tx_param(
        tx_hash: vector<u8>,
        cross_chain_id: vector<u8>,
        from_contract: vector<u8>,
        to_chain_id: u64,
        to_contract: vector<u8>,
        method: vector<u8>,
        args: vector<u8>,
    ): vector<u8> {
        let head = Vector::empty<u8>();
        let tail = Vector::empty<u8>();
        let k: u64 = 7;

        abi_encode_append_bytes(&mut head, &mut tail, tx_hash, k);
        abi_encode_append_bytes(&mut head, &mut tail, cross_chain_id, k);
        abi_encode_append_bytes(&mut head, &mut tail, from_contract, k);
        abi_encode_append_u64(&mut head, &mut tail, to_chain_id, k);
        abi_encode_append_bytes(&mut head, &mut tail, to_contract, k);
        abi_encode_append_bytes(&mut head, &mut tail, method, k);
        abi_encode_append_bytes(&mut head, &mut tail, args, k);

        Vector::append(&mut head, tail);
        head
    }

    // k is the number of all values to encode
    public fun abi_encode_append_bytes(
        head: &mut vector<u8>,
        tail: &mut vector<u8>,
        value: vector<u8>,
        k: u64,
    ) {
        // head
        let pos = k * EVM_SLOT_LENGTH + Vector::length(tail);
        Vector::append(head, u64_to_evm_format_bytes32(pos));

        // tail
        let value_len = Vector::length(&value);
        let padding_zeros = ((value_len + EVM_SLOT_LENGTH - 1) / EVM_SLOT_LENGTH) * EVM_SLOT_LENGTH - value_len;
        let padded_value = value;
        zion_utils::right_padding<u8>(&mut padded_value, padding_zeros, 0);
        let enc_value = u64_to_evm_format_bytes32(value_len);
        Vector::append(&mut enc_value, padded_value);
        Vector::append(tail, enc_value);
    }   

    public fun abi_encode_append_u64(
        head: &mut vector<u8>,
        _tail: &mut vector<u8>,
        value: u64,
        _k: u64,
    ) {
        Vector::append(head, u64_to_evm_format_bytes32(value));
    }

    public fun u64_to_evm_format_bytes32(
        value: u64,
    ): vector<u8> {
        let value_bytes = BCS::to_bytes(&value);
        let value_len = Vector::length(&value_bytes);
        zion_utils::right_padding<u8>(&mut value_bytes, EVM_SLOT_LENGTH - value_len, 0);
        Vector::reverse(&mut value_bytes);
        value_bytes
    }

    /*

        ____  _     ____  
        |  _ \| |   |  _ \ 
        | |_) | |   | |_) |
        |  _ <| |___|  __/ 
        |_| \_\_____|_|    
                    
    */

    // return (value, offset_)
    public fun rlp_get_next_bytes(
        raw: &vector<u8>,
        offset: u64,
    ): (vector<u8>, u64) {
        rlp_split(raw, offset)
    }

    // return (value, offset_)
    public fun rlp_get_next_bytes32(
        raw: &vector<u8>,
        offset: u64,
    ): (vector<u8>, u64) {
        let (size, offset) = rlp_read_kind(raw, offset);
        assert!(size == 32, RLP_BYTES32_EINVALID_DATA_LENGTH);
        (zion_utils::slice(raw, offset, size), offset + size)
    }

    // return (value, offset_)
    public fun rlp_get_next_zion_address(
        raw: &vector<u8>,
        offset: u64,
    ): (vector<u8>, u64) {
        let size;
        (size, offset) = rlp_read_kind(raw, offset);
        assert!(size == ZION_ADDRESS_LEN, RLP_ZION_ADDRESS_EINVALID_DATA_LENGTH);
        (zion_utils::slice(raw, offset, size), offset + size)
    }

    // return (value, offset_)
    public fun rlp_get_next_u64(
        raw: &vector<u8>,
        offset: u64,
    ): (u64, u64) {
        let size;
        let val;
        (size, offset) = rlp_read_kind(raw, offset);
        assert!(size <= 8, RLP_U64_EINVALID_DATA_LENGTH);
        (val, offset) = rlp_read_uint(raw, offset, size);
        ((val as u64), offset)
    }

    // return (value, offset_)
    public fun rlp_get_next_u128(
        raw: &vector<u8>,
        offset: u64,
    ): (u128, u64) {
        let size;
        (size, offset) = rlp_read_kind(raw, offset);
        assert!(size<=16, RLP_U128_EINVALID_DATA_LENGTH);
        let (val, offset) = rlp_read_uint(raw, offset, size);
        ((val as u128), offset)
    }

    // return (value, offset_)
    public fun rlp_get_next_u256(
        raw: &vector<u8>,
        offset: u64,
    ): (u256, u64) {
        let size;
        (size, offset) = rlp_read_kind(raw, offset);
        assert!(size <= 32, RLP_U256_EINVALID_DATA_LENGTH);
        rlp_read_uint(raw, offset, size)
    }

    // return (value, offset_)
    public fun rlp_split(
        raw: &vector<u8>,
        offset: u64,
    ): (vector<u8>, u64) {
        let size;
        (size, offset) = rlp_read_kind(raw, offset);
        (zion_utils::slice(raw, offset, size), offset + size)
    }

    // return (size, offset_)
    public fun rlp_read_kind(
        raw: &vector<u8>,
        offset: u64,
    ): (u64, u64) {
        let k = *Vector::borrow(raw, offset);
        if (k < 0x80) {
            (1, offset)
        } else if (k < 0xb8) {
            ((k - 0x80 as u64), offset + 1)
        } else if (k < 0xc0) {
            let val;
            (val, offset) = rlp_read_uint(raw, offset + 1, (k - 0xb7 as u64));
            ((val as u64), offset)
        } else if (k < 0xf8) {
            ((k - 0xc0 as u64), offset + 1)
        } else {
            let val;
            (val, offset) = rlp_read_uint(raw, offset + 1, (k - 0xf7 as u64));
            ((val as u64), offset)
        }
    }

    // return (value, offset_)
    public fun rlp_read_uint(
        raw: &vector<u8>,
        offset: u64,
        len: u64,
    ): (u256, u64) {
        if (len == 0) return (0, offset);
        let index = len - 1;
        let first_byte = *Vector::borrow(raw, offset+index);
        let val = (first_byte as u256);
        let pow = 1;
        while (index > 0) {
            index = index - 1;
            pow = pow * 0x100;
            let b = *Vector::borrow(raw, offset+index);
            if (b == 0) continue;
            val = val + (b as u256) * pow
        };
        (val, offset + len)
    }


    #[test]
    fun test_encode_tx_param() {
        Debug::print(&encode_tx_param(
            b"123456",
            b"111",
            b"111",
            318,
            b"111",
            b"111",
            b"111"
        ))
    }

    #[test]
    fun verify_account_proof_test() {
        let account_proof = x"b90e34f90211a0b741140d3a6318a3379ff67e3bb89fa9780c8aaf0fdabea6198098d792391597a0c4e5a99e315464eaf6392a999144d19f59173753996cf0981e5c148e04fc5d32a0d718273ac08000412a49c02767fff67d6d4d4c108a67082bc75dfa12174fdac0a038d3b6c562304b4e4ee6a7027783276473e734062c067aa9236aea3836e2a4e9a0c6354069b8d0fe2c1ee604a1248b51a90bacce4ac2f21225e07dc63d83fbc5ffa00a242aca34573f747041cf861bb7d41e5b194098183d0d192915e6f43eede54da0f9ea1862eb571abc0af92222417cd83d36c211da4daffa662614ab28d4499deea0907015eea2c82954a0a0bc757f9b54a7fddd2120cc0a1998a68a428052bcc259a03b451915a431e8c0d6c99dc2de4aec8792117eb7f6d7c58eedab5cfd7a33758ca0cb99a9d235236d18334c73714d695776e07368b7d5087c92be48a80ca7780b00a05d8b69b388bcba32e45754df01bda1c4183dd35507a94e2de2bfa0fa927ed790a01ea856df980fe0ad10de0805c075b7f042dced1c0ad518a1210e4e1b80ee109ba0de4c4a786ee86b865a25083400768a7c580a899c489397439b0002a8361a27eea05c72828ffbee3efaf3744d94aadaefb45fa713642c0310e9505bf2e85fb0ce4ea02f47fc136056fc81ab1ae50ea46184641b03e157129314d78d086b59903dfbb1a0f3126aa208eee8ff04ea98e78a0ecf10443685d546f4a91907fbfda662fe8dc380f90211a09103f4a1135b9f75fd25f1ddb7a556dc2c92c3bd809292fad290ed44c51ec9cea028215cc63bb8b282f90b2bae5a26de6ed0828601a1b19def64bff139f11b48a7a05a4672c87f8d864f2f7487bb844ac8fc48f60178787d91c0093b0a0f0a91ab4ba072cd65ce9ea7a398532319b9dc8de24a68e1fb204cf093bd16a9f4c81d4dd0eda0e4d0321d625b06ae6614224a55ff2d359df21ac8528d43d8bae57813f3c512d0a065ddf9a52b8d2bcaa136e2ed26c308ffb332572c9ff9915a2018f1b07a342fa8a043dc357d9a6d033d905316c499808b0c0d0d4b37fa355f504074312d921730a4a09cf5ee09061b795c036c6f22eb2a0ca69e2178058d6207876700039f027949f2a098329197f44a04470159940c9e11df711a58e8816412ab02cdedc2475115e31fa098aff63fd11ccfa9b5f06377972e66e238aad9e083d3f787c9a825ba473e2350a079192192dbe405ef459915a95b7511e6802e80bf57f4a4d664e840310ec61a48a0c487bc8e5fb7562bb943e2f81d148844e7be196df731c33a768bc009c7914d99a0045d014772a883d3d56ee282eff7936bce6d3240092f11a7efb866bf2406d6b9a0d7c2d37368aa37470bab73b697da24bcdf769f8ef1056f7e3928019b43bfe051a054a55cdef313d9b1cf11e19de0c13c77dbf89f1692fa714a2e944e01dcbb0e07a0e9d532c6e53056ecb6580fc9b3cbf75726b0be1909f25320ba4a2eea4cbcafc680f90211a0f8716ee393c51dddd03dbb0df4d2efa45c8513233f7d42dfa71669ce05faaba5a01318320ee4a0dcdfd38621d887fb601a6ff7b4abeafe313bec24e6a07f925417a016895a43fc6599bcfb06c1169d3e5270663482b3a3b7277754f883e1490a7a26a0ae0c4621c60f4be3884845ca4758bb4d6124a272e4c8259416bf5879d95e63eca032f8ced44550c817aed3e1503440ec7a9cef6f7e0cfb43056fb34a4ef531e971a0b86bed75d646921d8b1854e484a7630073d6a291b1e17205d4899e9efccfca77a0a6d2d71554e85f86804efa0442769c11918ee84d3a9a985004c6eee5085c06b7a0f63088a2c97cf5074a694478874cee1a08e34f1cbb2f35854535a15aa3cc1bffa0c81e76ff2013966e71fb13a69055e0d7902c4b1ffe16f4b631f84149ff6d63a7a0e1efae81604bca3a97993542e94fc3bb1515285bf6b0611c27e719f22e24c1c0a050ae095a2dbb29ef45819c896c9e76b925bae9d8aed3d25bcd0396844f695512a03e7d8c2f7e7b47a2dc32a2d2eca44776407e8dfa1b47f2af29a58a4da37e9e8da0a5faab169bf76c36892fae1aa9b1d0b0d751c00e27f5f62bb0aa7535b643922aa0add12c7750f5489f8eafad74404e3271e460b9700824668599772276e82e37b0a03f3a068b40ed8694709e3a09a15293fc57efc7584894bfa9e2673d600c2d3927a0488f598b0d87617c288382e3165b1d905b457c0d714ce87c8ef29a17ffda4cf080f90211a03791718f24ec0d075d271c2a747469f86e4ec80dbd02abde23a000247f0fd60ca00ffff60b659758ba241c4b6b6172c98a77313ddaa3cba1f90cfecbad43b40d95a0669057ff7dfe0570c0574fa12b63669f3a1f301f6d3d66086d7b45afa6464a9fa0c676aa4205537893fb89bcb1843de2bfca789155ec79136c0d83a3c935747f27a0c74fd524eea3c8c27e7f321e8667fdda138fa95beed00829ce70680183c4def2a0e2656dfa1de703af58e027cc73b6e6c0cc4108334b4960cde0453b83803f3e80a00aa05181348042d171583e7e5995f1d4ec8826d73792909a9effe9af72f69123a0106636d7b70674e206c31c14a2a25acf62bebc9e1d80c8488df1363c1e38813fa0d0176a180120a15dccfd4f0303c9606df8eb43618ec3c9b867746faf03eea31ea0f4e46fccc0219acf1c3c77a7d9ad48de815cdeaeba250c60d57ec491fc5cfe52a06d836a64bcd12166dae91d28fa4a7697f963d6a058e364c6773733d58b9272faa0798c6db0eeda2f013592434c5bfa9ddd421d929d764899bfed5178ac3f9190c5a03cc0bb14dc4d16846dbd840189aa93828602e194e87302ee854ef0ae409e8772a07fee766c12d118209c1762047d4d59dc00e210ac0777828ac4830bbf667fbd11a011b715b76f357e822649aa64b1248c2555a9745c1094966d3cdb07e4c91e88b9a02a4caa5cc29911dd3a651260e35afa493a8262548a2a2c23499da6d004dc3ba080f90211a00fcb2b8e33d8534225f2658b37c7c77ee53f30adcac18923c44c3218ae715842a01b48f71fa960f75f14228c0d83b9c230a3b8d719cc8dbbe7586ec61c9716641ba0c322d340c50ba4d1d8cfbd7b0069dca36ca653d87bbadf0dfdebca93eb2148f6a0f2f74a5fa1dda9960bf858b5f5ebd2aef491070f6f16a06ca608291d3895803fa098062c1354c0b90834b0979ee49fba0df675d9af6cf03e4512610296797bc377a00d89a8a8551ad2f21abcc5a5f0ecd6eb7bfa69dcb3aa5edcf506c8648340b3d2a088855a465d789237a4b54afecf7d4a3ab39c4656ffba364fef2dd3e0e8391612a00a4deaf50f402651d43b6213f625011a3466de8214f58d803e9ecfb9c6d32f31a021eb5e5135d77ac459f32aa99843ac50cdab749fd0e733ff478bc51dcdb5638da098aa811c9c145224069e24d558efda6f7c64e1d886394c6fe8892fae95a3922ba005d95fe792634d32ead3406168c7d2c0ded050e47c652cd6f2fb473e29ab0f79a04653b9e5a5fffa6e8c92d9cc3fa7fe42239942db03833aa9e4f210571399d174a01b14d6732668376797dec7a1da1b84d2b59d611324adc902660a92d12d3d4722a0c614db8a884fd513a2367447182e028e0dbaf9b5611acc1b7dbe12a3beebd987a0e328066c1167c02968dc8eab0ce4a4acfacc1b73b37e37f44204ece1ad07a2a9a0e4be8aa9a188a76453218513eccda6c2fe4ad61b1cd43970d64a1e92c8b63c9680f90211a0ee940971034a948744d99fbc58addd15a579e2d85a4f65fcb805f0eeed67bf4fa038ed332850bf07d19e022fb5d949d4fa17863c27788525eb5a4c6ced2568efb6a0e970b422efc8c39b8ed1b6ed57f163027eff6ce3b35277528264299ee25990e7a0be241ddd1c79f5f34fe4e059773d084d6fa4f30939a9b0ce3acdee3c03f97a22a09e814449c24dad2bf119541863cebd094f803666e7dd499fa76d9afd3a1af29ea021c860a5f7a50b183ef2cf2b1cfa7ff4457fc0e0ac5ebce5e826a44a02471f8da0f144e39fb40ae9528759fb524d64274ccffc044339cc56751f9335942d47b6c5a0f5f1ea3b4c496fcf2c86cf622e90083787d3b159304936d858dd7454302abf66a0b124f85d96b311bbc255135e0bec0d3ac4437da0003edaeaf3cdff05038144efa0d17bb8aa7775a9ed5746c47504a123f194cdee2d4a7c48cc36272120061588f6a0eb75ebdd6fde798d6e8e4b0eac8ae24b46e70a7bf6a94b6c9f34d38cfaf2a4bca0274e9ebb63919d9491b5cdeea4810b1eb7e4bf30eaf8f2be3c832638c06ec0c2a067df00968f1926dc7e5b26079156e3c496d61b9bb601fed5bbbce627c651d790a0ecf18162af98abd61084233499216ae327f78655bc49d36463238bfad8dd9cb2a0c898d513f8446f4dc600d16dfb5ae11e219fc22b2fabb136d3f9e244ab9fcc40a05dc97cd537c68b8f8083c82cbbc2812ff47dd211fed57526e4649a743a4f1e3480f90151a0f0193db74be08058606b46ebb78cc3911465de28ed81fd59466e24bbb73cd2e880a02833bf6404301c0d0c52eef381415ffdbc3badc79747c3e44395dbbc151e706180a0152e0e6aed172abc678ab7ae41870b45dfdf8ed0329c30b28c8eb3cfb99b7b8a8080a074a07e62ec8601cb080a74b071acc9cc23ee134079137c7c4955b7603fd916c3a08185c4940af6b500466b727eaaa1607a7f60fb947c75d52d08bbd68e5898f11ba057c58a71ea1b2d4cd8db94c73fee1a0d402e2a88f149f2ac0577a65ce043763b80a001dd15f3e3e3ad962529522fec84b2fb9285a1933b471cce2446148488025857a00fa778a067f12adcf5d967ba4b75055a0c76801028127451bf3047c693344abb80a05f8715aacb30c8680edd6f5776e119902cc4747dac42a485c9d79fe0181a6125a00e8c1fdf2da7e992a26589d2f8efa93eb70a27dd5b1eb985541b1c7a8d6842f580f8669d3837e47e9d97fea44bf893a771a304a3232304719598eff3743ca7ae4bb846f8440180a06b58bbd6d52464ecf91852537153b98ae5d05872cd57ef8777e3a158c7158bf0a0614777117c0a31bb33af852628e78b108a6e6e6b3bb9e938deaaee7e2b033adb";
        let header_root = x"b2d2e3feec4af059219e8afdbabfcf4df54aa2a0374bb0206abc4685c60879dc";
        let account_addr = x"cf2afe102057ba5c16f899271045a0a37fcb10f2";
        let storage_proof = x"b907b5f90211a07ed39b0406d98b1bd4ac969de62251c28166aef8f69e29b63696e872ac189487a0ac5f460011f98632c2a89a230d74496a0f24238ec31b81b976d4e13003c72d6aa0a8fdd52d18c3f32422d855da308c2952d8c3e62d32c7485181002f65ab8b57afa085cbdc3a0cba369c10c95e410f47252771eae14302875332613fa2272185d7b0a0bbb7b4b8517476dbd93814a4261eed6f9c97ca10cd0013cf21a9bffe69f03bdda02b7e730e92a8a17afc75ce75c92392f14f3afa32043e5b657c5591f93e008efaa06031d69caf4b044c76bfb7a5d5858f6379ca738604e6fef330a3b7fc934c6dfaa039a81cf4ec43adc442aeb8d39d0bfb8aea825717d6ec84edaef8a3171b355a6fa0397bc9286b2e7f5a11345fbc1e53723b51574327f4f579c00f271c7cf170c282a040d05c1bac2e6704974b0220b40c98063474954c785440d839079600577e6823a0b0e04d24a63cb027e5fd79eced2cbc22ff9de4e06d5a35ba334962bc651a3c5ca0c1cc67cabe19054542e3868189a139d914a682c079fe24e74ed36d1e6a47b898a0052e33c422e91910ce324727b67906b3ae99c6d743a006864cd27b1db94bc079a0e30908e2fdbf74787f9f314166d71375297e65f616b50241259b2552a454f109a04e8a0da0f4d104807c9179eac1593444c6faa383217e72be55632f3b4a8f82d6a0abcdf9e280b03116a508f9e884d020db4fa6f8c6f99a9876c505e96bb2b1c1ee80f90211a0e8a177164a0903af248c1ce6e407aa3757c2b6e938365119d72680966834944fa0a711179d5280d7807b586b6c6c00a57862d94a74a70622184fe359e6a09fe72fa07f3c6e247a4299cd7363cc1f4c17a095fd3faf2a1e354cbf9181cbb8d89fc369a07e1aead1e3fc3fe359c7d171930b78ec54be8c46f6c14efc279f251725913f0fa0109cead3dc197d9277fb5e2ee00ffcd12f7041371ac2eb0327922b10d4e26b16a0ed93a1e844d80ba5a171225d21389aae47ec2f3716f8b4e3b2e1a133504043e8a090fd100b80e8158b315854543af17087f8857e54184db7bc3d9de77fda32a0bda0851eee7ce719e6a015ec9c875508ac9905c4a2eccda37316446956afcf4e23baa0d2a294eeae765264513ccca891aa919d34c69b3111b835f63c8737d352668009a019285dbf4f245f329403d24543ad83274ecc3284d4c57cc3a88b3ce1ea1ac11ca0d4629a9597ed272e17b235ad29c7da794ee32760ba098bdd7d14b6e810f24368a09c336ad8430de2df7f43ec60444a4ed070ad13922ddab175d86f91addd963297a0a868e36c2bb51e60dd302a18bd778ee75b322b970a08a3649134a8a10e1aba81a07b1a01c6802541dd28d535ae227ac6c98f0ef33f145adf82a4b96852ec6f3f73a0dcc13ebca88dbd8a0c55faeed20caccb28d62a502cf0db77b485784c57c3bf80a0a87e59e39a094f2913274ab52a8de1cf792927ac7d5fee29cdf562e245d0dc2e80f90211a01757917e9224d8e39d6c944a96ced33c52745a1c06314a6ae5c1ef0028ae02b9a0eba8b1fb250c33e15be6403379c85a3f474632f94551e21d2021b835ef1cf16da0971be97201d6089d0284e9ce1390dbb801ea7f7e949d8d27a24c129f152563c1a0a19c1d33affc5b418fd755923e54e9120e474f6b0d2a349cba84b90a0f66ddd4a08a5b25f5767d0654bc9f7ad9bf5bdc498d23e01b768dd2f0ad8932da48614c12a0d9b92383870f2d89401c36ff30cfd1a534c36d15798aae97eb04b9c430694672a0db39ea934e865b4258aa27a1d15d88c8a708b788245f62ea40382c5955a4c011a0c30b5709545fd2f8ba396bc05d72c7f8d5b307707b36971687e6337585576b4aa05c195afb8eceff2cb8956a4c9fd5627f84a5a3f29b75bfca08cf0ab4426f1820a052e65038019b745358c010b86d25da81f8f328e5972821d5a7626c868348a0e3a06d990082b50c7e9ecc641184adafb135659c66e9cb29a423932f511578cb7126a0761b5db9f8e3a19c119684b48a869ac32abd1288905666224112996815d8b499a087be60024fb57677ffc530ce6e9ffe48b1c4a5656466a7a986a6ef0ba4fd44b6a01ebeaf5225b5edc45237db4838fdcf8fbd9f282e3286ef5b1bd54e8d1a3ce027a00f76986377197ea90ee95620eac59eae4d454c9620f6bca769bc90a5984b244ea0c34a527eec08998e829b2df246b503c28551b6f65ca6a0aa3b4350cb17200f8c80f90151a0744d00ff280e769c2daf908c1e8a4b5e5ea9a653295deb0d07160d83eac7435aa010ef6734ed120f8f8ee079d2bf6db2a234d731e7d08c2f31e4738abc0d8443568080a01755a82d129503f82ff0a92265bb8d056a81456a346b788522aad848a99e000580a0ea8e41e2016c801b99b2bf7333bc5f27283388df703546c69d69057b21b085a8a04cf623a5154bdf4f33ccdfc4d4ab38b8165adb1592c425d49cb877244a2fa68280a084d71f99e326177e070f1618a05fb1bb9e3257cc9ea9c2e9cdc367943f41c4dda0a40b555d93923c9fd96e0ad671c722335b0812cd3e451d95b76e2dce5e38cd6580a080a3d9222507178bb567c5e1041070f041661bf60179e5595b044b10cb88fb8580a0334e35ff43871b958ff4b604161c6da0288f61a12316ed4f0a377d3fc06df37aa02081102b6f79d26a1ca5984a8abd89cf434be02ca2f2c4862494dc34dde73fe880e49f2087fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace838277d7";
        let storage_index = x"0000000000000000000000000000000000000000000000000000000000000002";
        let storage_value = x"77d7";

        assert!(verify_account_proof(&account_proof, &header_root, &account_addr, &storage_proof, &storage_index) == storage_value, 0);
    }

    #[test, expected_failure]
    fun verify_account_proof_fail_wrong_headerRoot_test() {
        let account_proof = x"b90e34f90211a0b741140d3a6318a3379ff67e3bb89fa9780c8aaf0fdabea6198098d792391597a0c4e5a99e315464eaf6392a999144d19f59173753996cf0981e5c148e04fc5d32a0d718273ac08000412a49c02767fff67d6d4d4c108a67082bc75dfa12174fdac0a038d3b6c562304b4e4ee6a7027783276473e734062c067aa9236aea3836e2a4e9a0c6354069b8d0fe2c1ee604a1248b51a90bacce4ac2f21225e07dc63d83fbc5ffa00a242aca34573f747041cf861bb7d41e5b194098183d0d192915e6f43eede54da0f9ea1862eb571abc0af92222417cd83d36c211da4daffa662614ab28d4499deea0907015eea2c82954a0a0bc757f9b54a7fddd2120cc0a1998a68a428052bcc259a03b451915a431e8c0d6c99dc2de4aec8792117eb7f6d7c58eedab5cfd7a33758ca0cb99a9d235236d18334c73714d695776e07368b7d5087c92be48a80ca7780b00a05d8b69b388bcba32e45754df01bda1c4183dd35507a94e2de2bfa0fa927ed790a01ea856df980fe0ad10de0805c075b7f042dced1c0ad518a1210e4e1b80ee109ba0de4c4a786ee86b865a25083400768a7c580a899c489397439b0002a8361a27eea05c72828ffbee3efaf3744d94aadaefb45fa713642c0310e9505bf2e85fb0ce4ea02f47fc136056fc81ab1ae50ea46184641b03e157129314d78d086b59903dfbb1a0f3126aa208eee8ff04ea98e78a0ecf10443685d546f4a91907fbfda662fe8dc380f90211a09103f4a1135b9f75fd25f1ddb7a556dc2c92c3bd809292fad290ed44c51ec9cea028215cc63bb8b282f90b2bae5a26de6ed0828601a1b19def64bff139f11b48a7a05a4672c87f8d864f2f7487bb844ac8fc48f60178787d91c0093b0a0f0a91ab4ba072cd65ce9ea7a398532319b9dc8de24a68e1fb204cf093bd16a9f4c81d4dd0eda0e4d0321d625b06ae6614224a55ff2d359df21ac8528d43d8bae57813f3c512d0a065ddf9a52b8d2bcaa136e2ed26c308ffb332572c9ff9915a2018f1b07a342fa8a043dc357d9a6d033d905316c499808b0c0d0d4b37fa355f504074312d921730a4a09cf5ee09061b795c036c6f22eb2a0ca69e2178058d6207876700039f027949f2a098329197f44a04470159940c9e11df711a58e8816412ab02cdedc2475115e31fa098aff63fd11ccfa9b5f06377972e66e238aad9e083d3f787c9a825ba473e2350a079192192dbe405ef459915a95b7511e6802e80bf57f4a4d664e840310ec61a48a0c487bc8e5fb7562bb943e2f81d148844e7be196df731c33a768bc009c7914d99a0045d014772a883d3d56ee282eff7936bce6d3240092f11a7efb866bf2406d6b9a0d7c2d37368aa37470bab73b697da24bcdf769f8ef1056f7e3928019b43bfe051a054a55cdef313d9b1cf11e19de0c13c77dbf89f1692fa714a2e944e01dcbb0e07a0e9d532c6e53056ecb6580fc9b3cbf75726b0be1909f25320ba4a2eea4cbcafc680f90211a0f8716ee393c51dddd03dbb0df4d2efa45c8513233f7d42dfa71669ce05faaba5a01318320ee4a0dcdfd38621d887fb601a6ff7b4abeafe313bec24e6a07f925417a016895a43fc6599bcfb06c1169d3e5270663482b3a3b7277754f883e1490a7a26a0ae0c4621c60f4be3884845ca4758bb4d6124a272e4c8259416bf5879d95e63eca032f8ced44550c817aed3e1503440ec7a9cef6f7e0cfb43056fb34a4ef531e971a0b86bed75d646921d8b1854e484a7630073d6a291b1e17205d4899e9efccfca77a0a6d2d71554e85f86804efa0442769c11918ee84d3a9a985004c6eee5085c06b7a0f63088a2c97cf5074a694478874cee1a08e34f1cbb2f35854535a15aa3cc1bffa0c81e76ff2013966e71fb13a69055e0d7902c4b1ffe16f4b631f84149ff6d63a7a0e1efae81604bca3a97993542e94fc3bb1515285bf6b0611c27e719f22e24c1c0a050ae095a2dbb29ef45819c896c9e76b925bae9d8aed3d25bcd0396844f695512a03e7d8c2f7e7b47a2dc32a2d2eca44776407e8dfa1b47f2af29a58a4da37e9e8da0a5faab169bf76c36892fae1aa9b1d0b0d751c00e27f5f62bb0aa7535b643922aa0add12c7750f5489f8eafad74404e3271e460b9700824668599772276e82e37b0a03f3a068b40ed8694709e3a09a15293fc57efc7584894bfa9e2673d600c2d3927a0488f598b0d87617c288382e3165b1d905b457c0d714ce87c8ef29a17ffda4cf080f90211a03791718f24ec0d075d271c2a747469f86e4ec80dbd02abde23a000247f0fd60ca00ffff60b659758ba241c4b6b6172c98a77313ddaa3cba1f90cfecbad43b40d95a0669057ff7dfe0570c0574fa12b63669f3a1f301f6d3d66086d7b45afa6464a9fa0c676aa4205537893fb89bcb1843de2bfca789155ec79136c0d83a3c935747f27a0c74fd524eea3c8c27e7f321e8667fdda138fa95beed00829ce70680183c4def2a0e2656dfa1de703af58e027cc73b6e6c0cc4108334b4960cde0453b83803f3e80a00aa05181348042d171583e7e5995f1d4ec8826d73792909a9effe9af72f69123a0106636d7b70674e206c31c14a2a25acf62bebc9e1d80c8488df1363c1e38813fa0d0176a180120a15dccfd4f0303c9606df8eb43618ec3c9b867746faf03eea31ea0f4e46fccc0219acf1c3c77a7d9ad48de815cdeaeba250c60d57ec491fc5cfe52a06d836a64bcd12166dae91d28fa4a7697f963d6a058e364c6773733d58b9272faa0798c6db0eeda2f013592434c5bfa9ddd421d929d764899bfed5178ac3f9190c5a03cc0bb14dc4d16846dbd840189aa93828602e194e87302ee854ef0ae409e8772a07fee766c12d118209c1762047d4d59dc00e210ac0777828ac4830bbf667fbd11a011b715b76f357e822649aa64b1248c2555a9745c1094966d3cdb07e4c91e88b9a02a4caa5cc29911dd3a651260e35afa493a8262548a2a2c23499da6d004dc3ba080f90211a00fcb2b8e33d8534225f2658b37c7c77ee53f30adcac18923c44c3218ae715842a01b48f71fa960f75f14228c0d83b9c230a3b8d719cc8dbbe7586ec61c9716641ba0c322d340c50ba4d1d8cfbd7b0069dca36ca653d87bbadf0dfdebca93eb2148f6a0f2f74a5fa1dda9960bf858b5f5ebd2aef491070f6f16a06ca608291d3895803fa098062c1354c0b90834b0979ee49fba0df675d9af6cf03e4512610296797bc377a00d89a8a8551ad2f21abcc5a5f0ecd6eb7bfa69dcb3aa5edcf506c8648340b3d2a088855a465d789237a4b54afecf7d4a3ab39c4656ffba364fef2dd3e0e8391612a00a4deaf50f402651d43b6213f625011a3466de8214f58d803e9ecfb9c6d32f31a021eb5e5135d77ac459f32aa99843ac50cdab749fd0e733ff478bc51dcdb5638da098aa811c9c145224069e24d558efda6f7c64e1d886394c6fe8892fae95a3922ba005d95fe792634d32ead3406168c7d2c0ded050e47c652cd6f2fb473e29ab0f79a04653b9e5a5fffa6e8c92d9cc3fa7fe42239942db03833aa9e4f210571399d174a01b14d6732668376797dec7a1da1b84d2b59d611324adc902660a92d12d3d4722a0c614db8a884fd513a2367447182e028e0dbaf9b5611acc1b7dbe12a3beebd987a0e328066c1167c02968dc8eab0ce4a4acfacc1b73b37e37f44204ece1ad07a2a9a0e4be8aa9a188a76453218513eccda6c2fe4ad61b1cd43970d64a1e92c8b63c9680f90211a0ee940971034a948744d99fbc58addd15a579e2d85a4f65fcb805f0eeed67bf4fa038ed332850bf07d19e022fb5d949d4fa17863c27788525eb5a4c6ced2568efb6a0e970b422efc8c39b8ed1b6ed57f163027eff6ce3b35277528264299ee25990e7a0be241ddd1c79f5f34fe4e059773d084d6fa4f30939a9b0ce3acdee3c03f97a22a09e814449c24dad2bf119541863cebd094f803666e7dd499fa76d9afd3a1af29ea021c860a5f7a50b183ef2cf2b1cfa7ff4457fc0e0ac5ebce5e826a44a02471f8da0f144e39fb40ae9528759fb524d64274ccffc044339cc56751f9335942d47b6c5a0f5f1ea3b4c496fcf2c86cf622e90083787d3b159304936d858dd7454302abf66a0b124f85d96b311bbc255135e0bec0d3ac4437da0003edaeaf3cdff05038144efa0d17bb8aa7775a9ed5746c47504a123f194cdee2d4a7c48cc36272120061588f6a0eb75ebdd6fde798d6e8e4b0eac8ae24b46e70a7bf6a94b6c9f34d38cfaf2a4bca0274e9ebb63919d9491b5cdeea4810b1eb7e4bf30eaf8f2be3c832638c06ec0c2a067df00968f1926dc7e5b26079156e3c496d61b9bb601fed5bbbce627c651d790a0ecf18162af98abd61084233499216ae327f78655bc49d36463238bfad8dd9cb2a0c898d513f8446f4dc600d16dfb5ae11e219fc22b2fabb136d3f9e244ab9fcc40a05dc97cd537c68b8f8083c82cbbc2812ff47dd211fed57526e4649a743a4f1e3480f90151a0f0193db74be08058606b46ebb78cc3911465de28ed81fd59466e24bbb73cd2e880a02833bf6404301c0d0c52eef381415ffdbc3badc79747c3e44395dbbc151e706180a0152e0e6aed172abc678ab7ae41870b45dfdf8ed0329c30b28c8eb3cfb99b7b8a8080a074a07e62ec8601cb080a74b071acc9cc23ee134079137c7c4955b7603fd916c3a08185c4940af6b500466b727eaaa1607a7f60fb947c75d52d08bbd68e5898f11ba057c58a71ea1b2d4cd8db94c73fee1a0d402e2a88f149f2ac0577a65ce043763b80a001dd15f3e3e3ad962529522fec84b2fb9285a1933b471cce2446148488025857a00fa778a067f12adcf5d967ba4b75055a0c76801028127451bf3047c693344abb80a05f8715aacb30c8680edd6f5776e119902cc4747dac42a485c9d79fe0181a6125a00e8c1fdf2da7e992a26589d2f8efa93eb70a27dd5b1eb985541b1c7a8d6842f580f8669d3837e47e9d97fea44bf893a771a304a3232304719598eff3743ca7ae4bb846f8440180a06b58bbd6d52464ecf91852537153b98ae5d05872cd57ef8777e3a158c7158bf0a0614777117c0a31bb33af852628e78b108a6e6e6b3bb9e938deaaee7e2b033adb";
        let fake_root = x"0000000000000000000000000000000000000000000000000000000000000000";
        let account_addr = x"cf2afe102057ba5c16f899271045a0a37fcb10f2";
        let storage_proof = x"b907b5f90211a07ed39b0406d98b1bd4ac969de62251c28166aef8f69e29b63696e872ac189487a0ac5f460011f98632c2a89a230d74496a0f24238ec31b81b976d4e13003c72d6aa0a8fdd52d18c3f32422d855da308c2952d8c3e62d32c7485181002f65ab8b57afa085cbdc3a0cba369c10c95e410f47252771eae14302875332613fa2272185d7b0a0bbb7b4b8517476dbd93814a4261eed6f9c97ca10cd0013cf21a9bffe69f03bdda02b7e730e92a8a17afc75ce75c92392f14f3afa32043e5b657c5591f93e008efaa06031d69caf4b044c76bfb7a5d5858f6379ca738604e6fef330a3b7fc934c6dfaa039a81cf4ec43adc442aeb8d39d0bfb8aea825717d6ec84edaef8a3171b355a6fa0397bc9286b2e7f5a11345fbc1e53723b51574327f4f579c00f271c7cf170c282a040d05c1bac2e6704974b0220b40c98063474954c785440d839079600577e6823a0b0e04d24a63cb027e5fd79eced2cbc22ff9de4e06d5a35ba334962bc651a3c5ca0c1cc67cabe19054542e3868189a139d914a682c079fe24e74ed36d1e6a47b898a0052e33c422e91910ce324727b67906b3ae99c6d743a006864cd27b1db94bc079a0e30908e2fdbf74787f9f314166d71375297e65f616b50241259b2552a454f109a04e8a0da0f4d104807c9179eac1593444c6faa383217e72be55632f3b4a8f82d6a0abcdf9e280b03116a508f9e884d020db4fa6f8c6f99a9876c505e96bb2b1c1ee80f90211a0e8a177164a0903af248c1ce6e407aa3757c2b6e938365119d72680966834944fa0a711179d5280d7807b586b6c6c00a57862d94a74a70622184fe359e6a09fe72fa07f3c6e247a4299cd7363cc1f4c17a095fd3faf2a1e354cbf9181cbb8d89fc369a07e1aead1e3fc3fe359c7d171930b78ec54be8c46f6c14efc279f251725913f0fa0109cead3dc197d9277fb5e2ee00ffcd12f7041371ac2eb0327922b10d4e26b16a0ed93a1e844d80ba5a171225d21389aae47ec2f3716f8b4e3b2e1a133504043e8a090fd100b80e8158b315854543af17087f8857e54184db7bc3d9de77fda32a0bda0851eee7ce719e6a015ec9c875508ac9905c4a2eccda37316446956afcf4e23baa0d2a294eeae765264513ccca891aa919d34c69b3111b835f63c8737d352668009a019285dbf4f245f329403d24543ad83274ecc3284d4c57cc3a88b3ce1ea1ac11ca0d4629a9597ed272e17b235ad29c7da794ee32760ba098bdd7d14b6e810f24368a09c336ad8430de2df7f43ec60444a4ed070ad13922ddab175d86f91addd963297a0a868e36c2bb51e60dd302a18bd778ee75b322b970a08a3649134a8a10e1aba81a07b1a01c6802541dd28d535ae227ac6c98f0ef33f145adf82a4b96852ec6f3f73a0dcc13ebca88dbd8a0c55faeed20caccb28d62a502cf0db77b485784c57c3bf80a0a87e59e39a094f2913274ab52a8de1cf792927ac7d5fee29cdf562e245d0dc2e80f90211a01757917e9224d8e39d6c944a96ced33c52745a1c06314a6ae5c1ef0028ae02b9a0eba8b1fb250c33e15be6403379c85a3f474632f94551e21d2021b835ef1cf16da0971be97201d6089d0284e9ce1390dbb801ea7f7e949d8d27a24c129f152563c1a0a19c1d33affc5b418fd755923e54e9120e474f6b0d2a349cba84b90a0f66ddd4a08a5b25f5767d0654bc9f7ad9bf5bdc498d23e01b768dd2f0ad8932da48614c12a0d9b92383870f2d89401c36ff30cfd1a534c36d15798aae97eb04b9c430694672a0db39ea934e865b4258aa27a1d15d88c8a708b788245f62ea40382c5955a4c011a0c30b5709545fd2f8ba396bc05d72c7f8d5b307707b36971687e6337585576b4aa05c195afb8eceff2cb8956a4c9fd5627f84a5a3f29b75bfca08cf0ab4426f1820a052e65038019b745358c010b86d25da81f8f328e5972821d5a7626c868348a0e3a06d990082b50c7e9ecc641184adafb135659c66e9cb29a423932f511578cb7126a0761b5db9f8e3a19c119684b48a869ac32abd1288905666224112996815d8b499a087be60024fb57677ffc530ce6e9ffe48b1c4a5656466a7a986a6ef0ba4fd44b6a01ebeaf5225b5edc45237db4838fdcf8fbd9f282e3286ef5b1bd54e8d1a3ce027a00f76986377197ea90ee95620eac59eae4d454c9620f6bca769bc90a5984b244ea0c34a527eec08998e829b2df246b503c28551b6f65ca6a0aa3b4350cb17200f8c80f90151a0744d00ff280e769c2daf908c1e8a4b5e5ea9a653295deb0d07160d83eac7435aa010ef6734ed120f8f8ee079d2bf6db2a234d731e7d08c2f31e4738abc0d8443568080a01755a82d129503f82ff0a92265bb8d056a81456a346b788522aad848a99e000580a0ea8e41e2016c801b99b2bf7333bc5f27283388df703546c69d69057b21b085a8a04cf623a5154bdf4f33ccdfc4d4ab38b8165adb1592c425d49cb877244a2fa68280a084d71f99e326177e070f1618a05fb1bb9e3257cc9ea9c2e9cdc367943f41c4dda0a40b555d93923c9fd96e0ad671c722335b0812cd3e451d95b76e2dce5e38cd6580a080a3d9222507178bb567c5e1041070f041661bf60179e5595b044b10cb88fb8580a0334e35ff43871b958ff4b604161c6da0288f61a12316ed4f0a377d3fc06df37aa02081102b6f79d26a1ca5984a8abd89cf434be02ca2f2c4862494dc34dde73fe880e49f2087fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace838277d7";
        let storage_index = x"0000000000000000000000000000000000000000000000000000000000000002";

        verify_account_proof(&account_proof, &fake_root, &account_addr, &storage_proof, &storage_index);
    }

    #[test, expected_failure]
    fun verify_account_proof_fail_wrong_accountAddr_test() {
        let account_proof = x"b90e34f90211a0b741140d3a6318a3379ff67e3bb89fa9780c8aaf0fdabea6198098d792391597a0c4e5a99e315464eaf6392a999144d19f59173753996cf0981e5c148e04fc5d32a0d718273ac08000412a49c02767fff67d6d4d4c108a67082bc75dfa12174fdac0a038d3b6c562304b4e4ee6a7027783276473e734062c067aa9236aea3836e2a4e9a0c6354069b8d0fe2c1ee604a1248b51a90bacce4ac2f21225e07dc63d83fbc5ffa00a242aca34573f747041cf861bb7d41e5b194098183d0d192915e6f43eede54da0f9ea1862eb571abc0af92222417cd83d36c211da4daffa662614ab28d4499deea0907015eea2c82954a0a0bc757f9b54a7fddd2120cc0a1998a68a428052bcc259a03b451915a431e8c0d6c99dc2de4aec8792117eb7f6d7c58eedab5cfd7a33758ca0cb99a9d235236d18334c73714d695776e07368b7d5087c92be48a80ca7780b00a05d8b69b388bcba32e45754df01bda1c4183dd35507a94e2de2bfa0fa927ed790a01ea856df980fe0ad10de0805c075b7f042dced1c0ad518a1210e4e1b80ee109ba0de4c4a786ee86b865a25083400768a7c580a899c489397439b0002a8361a27eea05c72828ffbee3efaf3744d94aadaefb45fa713642c0310e9505bf2e85fb0ce4ea02f47fc136056fc81ab1ae50ea46184641b03e157129314d78d086b59903dfbb1a0f3126aa208eee8ff04ea98e78a0ecf10443685d546f4a91907fbfda662fe8dc380f90211a09103f4a1135b9f75fd25f1ddb7a556dc2c92c3bd809292fad290ed44c51ec9cea028215cc63bb8b282f90b2bae5a26de6ed0828601a1b19def64bff139f11b48a7a05a4672c87f8d864f2f7487bb844ac8fc48f60178787d91c0093b0a0f0a91ab4ba072cd65ce9ea7a398532319b9dc8de24a68e1fb204cf093bd16a9f4c81d4dd0eda0e4d0321d625b06ae6614224a55ff2d359df21ac8528d43d8bae57813f3c512d0a065ddf9a52b8d2bcaa136e2ed26c308ffb332572c9ff9915a2018f1b07a342fa8a043dc357d9a6d033d905316c499808b0c0d0d4b37fa355f504074312d921730a4a09cf5ee09061b795c036c6f22eb2a0ca69e2178058d6207876700039f027949f2a098329197f44a04470159940c9e11df711a58e8816412ab02cdedc2475115e31fa098aff63fd11ccfa9b5f06377972e66e238aad9e083d3f787c9a825ba473e2350a079192192dbe405ef459915a95b7511e6802e80bf57f4a4d664e840310ec61a48a0c487bc8e5fb7562bb943e2f81d148844e7be196df731c33a768bc009c7914d99a0045d014772a883d3d56ee282eff7936bce6d3240092f11a7efb866bf2406d6b9a0d7c2d37368aa37470bab73b697da24bcdf769f8ef1056f7e3928019b43bfe051a054a55cdef313d9b1cf11e19de0c13c77dbf89f1692fa714a2e944e01dcbb0e07a0e9d532c6e53056ecb6580fc9b3cbf75726b0be1909f25320ba4a2eea4cbcafc680f90211a0f8716ee393c51dddd03dbb0df4d2efa45c8513233f7d42dfa71669ce05faaba5a01318320ee4a0dcdfd38621d887fb601a6ff7b4abeafe313bec24e6a07f925417a016895a43fc6599bcfb06c1169d3e5270663482b3a3b7277754f883e1490a7a26a0ae0c4621c60f4be3884845ca4758bb4d6124a272e4c8259416bf5879d95e63eca032f8ced44550c817aed3e1503440ec7a9cef6f7e0cfb43056fb34a4ef531e971a0b86bed75d646921d8b1854e484a7630073d6a291b1e17205d4899e9efccfca77a0a6d2d71554e85f86804efa0442769c11918ee84d3a9a985004c6eee5085c06b7a0f63088a2c97cf5074a694478874cee1a08e34f1cbb2f35854535a15aa3cc1bffa0c81e76ff2013966e71fb13a69055e0d7902c4b1ffe16f4b631f84149ff6d63a7a0e1efae81604bca3a97993542e94fc3bb1515285bf6b0611c27e719f22e24c1c0a050ae095a2dbb29ef45819c896c9e76b925bae9d8aed3d25bcd0396844f695512a03e7d8c2f7e7b47a2dc32a2d2eca44776407e8dfa1b47f2af29a58a4da37e9e8da0a5faab169bf76c36892fae1aa9b1d0b0d751c00e27f5f62bb0aa7535b643922aa0add12c7750f5489f8eafad74404e3271e460b9700824668599772276e82e37b0a03f3a068b40ed8694709e3a09a15293fc57efc7584894bfa9e2673d600c2d3927a0488f598b0d87617c288382e3165b1d905b457c0d714ce87c8ef29a17ffda4cf080f90211a03791718f24ec0d075d271c2a747469f86e4ec80dbd02abde23a000247f0fd60ca00ffff60b659758ba241c4b6b6172c98a77313ddaa3cba1f90cfecbad43b40d95a0669057ff7dfe0570c0574fa12b63669f3a1f301f6d3d66086d7b45afa6464a9fa0c676aa4205537893fb89bcb1843de2bfca789155ec79136c0d83a3c935747f27a0c74fd524eea3c8c27e7f321e8667fdda138fa95beed00829ce70680183c4def2a0e2656dfa1de703af58e027cc73b6e6c0cc4108334b4960cde0453b83803f3e80a00aa05181348042d171583e7e5995f1d4ec8826d73792909a9effe9af72f69123a0106636d7b70674e206c31c14a2a25acf62bebc9e1d80c8488df1363c1e38813fa0d0176a180120a15dccfd4f0303c9606df8eb43618ec3c9b867746faf03eea31ea0f4e46fccc0219acf1c3c77a7d9ad48de815cdeaeba250c60d57ec491fc5cfe52a06d836a64bcd12166dae91d28fa4a7697f963d6a058e364c6773733d58b9272faa0798c6db0eeda2f013592434c5bfa9ddd421d929d764899bfed5178ac3f9190c5a03cc0bb14dc4d16846dbd840189aa93828602e194e87302ee854ef0ae409e8772a07fee766c12d118209c1762047d4d59dc00e210ac0777828ac4830bbf667fbd11a011b715b76f357e822649aa64b1248c2555a9745c1094966d3cdb07e4c91e88b9a02a4caa5cc29911dd3a651260e35afa493a8262548a2a2c23499da6d004dc3ba080f90211a00fcb2b8e33d8534225f2658b37c7c77ee53f30adcac18923c44c3218ae715842a01b48f71fa960f75f14228c0d83b9c230a3b8d719cc8dbbe7586ec61c9716641ba0c322d340c50ba4d1d8cfbd7b0069dca36ca653d87bbadf0dfdebca93eb2148f6a0f2f74a5fa1dda9960bf858b5f5ebd2aef491070f6f16a06ca608291d3895803fa098062c1354c0b90834b0979ee49fba0df675d9af6cf03e4512610296797bc377a00d89a8a8551ad2f21abcc5a5f0ecd6eb7bfa69dcb3aa5edcf506c8648340b3d2a088855a465d789237a4b54afecf7d4a3ab39c4656ffba364fef2dd3e0e8391612a00a4deaf50f402651d43b6213f625011a3466de8214f58d803e9ecfb9c6d32f31a021eb5e5135d77ac459f32aa99843ac50cdab749fd0e733ff478bc51dcdb5638da098aa811c9c145224069e24d558efda6f7c64e1d886394c6fe8892fae95a3922ba005d95fe792634d32ead3406168c7d2c0ded050e47c652cd6f2fb473e29ab0f79a04653b9e5a5fffa6e8c92d9cc3fa7fe42239942db03833aa9e4f210571399d174a01b14d6732668376797dec7a1da1b84d2b59d611324adc902660a92d12d3d4722a0c614db8a884fd513a2367447182e028e0dbaf9b5611acc1b7dbe12a3beebd987a0e328066c1167c02968dc8eab0ce4a4acfacc1b73b37e37f44204ece1ad07a2a9a0e4be8aa9a188a76453218513eccda6c2fe4ad61b1cd43970d64a1e92c8b63c9680f90211a0ee940971034a948744d99fbc58addd15a579e2d85a4f65fcb805f0eeed67bf4fa038ed332850bf07d19e022fb5d949d4fa17863c27788525eb5a4c6ced2568efb6a0e970b422efc8c39b8ed1b6ed57f163027eff6ce3b35277528264299ee25990e7a0be241ddd1c79f5f34fe4e059773d084d6fa4f30939a9b0ce3acdee3c03f97a22a09e814449c24dad2bf119541863cebd094f803666e7dd499fa76d9afd3a1af29ea021c860a5f7a50b183ef2cf2b1cfa7ff4457fc0e0ac5ebce5e826a44a02471f8da0f144e39fb40ae9528759fb524d64274ccffc044339cc56751f9335942d47b6c5a0f5f1ea3b4c496fcf2c86cf622e90083787d3b159304936d858dd7454302abf66a0b124f85d96b311bbc255135e0bec0d3ac4437da0003edaeaf3cdff05038144efa0d17bb8aa7775a9ed5746c47504a123f194cdee2d4a7c48cc36272120061588f6a0eb75ebdd6fde798d6e8e4b0eac8ae24b46e70a7bf6a94b6c9f34d38cfaf2a4bca0274e9ebb63919d9491b5cdeea4810b1eb7e4bf30eaf8f2be3c832638c06ec0c2a067df00968f1926dc7e5b26079156e3c496d61b9bb601fed5bbbce627c651d790a0ecf18162af98abd61084233499216ae327f78655bc49d36463238bfad8dd9cb2a0c898d513f8446f4dc600d16dfb5ae11e219fc22b2fabb136d3f9e244ab9fcc40a05dc97cd537c68b8f8083c82cbbc2812ff47dd211fed57526e4649a743a4f1e3480f90151a0f0193db74be08058606b46ebb78cc3911465de28ed81fd59466e24bbb73cd2e880a02833bf6404301c0d0c52eef381415ffdbc3badc79747c3e44395dbbc151e706180a0152e0e6aed172abc678ab7ae41870b45dfdf8ed0329c30b28c8eb3cfb99b7b8a8080a074a07e62ec8601cb080a74b071acc9cc23ee134079137c7c4955b7603fd916c3a08185c4940af6b500466b727eaaa1607a7f60fb947c75d52d08bbd68e5898f11ba057c58a71ea1b2d4cd8db94c73fee1a0d402e2a88f149f2ac0577a65ce043763b80a001dd15f3e3e3ad962529522fec84b2fb9285a1933b471cce2446148488025857a00fa778a067f12adcf5d967ba4b75055a0c76801028127451bf3047c693344abb80a05f8715aacb30c8680edd6f5776e119902cc4747dac42a485c9d79fe0181a6125a00e8c1fdf2da7e992a26589d2f8efa93eb70a27dd5b1eb985541b1c7a8d6842f580f8669d3837e47e9d97fea44bf893a771a304a3232304719598eff3743ca7ae4bb846f8440180a06b58bbd6d52464ecf91852537153b98ae5d05872cd57ef8777e3a158c7158bf0a0614777117c0a31bb33af852628e78b108a6e6e6b3bb9e938deaaee7e2b033adb";
        let header_root = x"b2d2e3feec4af059219e8afdbabfcf4df54aa2a0374bb0206abc4685c60879dc";
        let fake_addr = x"0000000000000000000000000000000000000000";
        let storage_proof = x"b907b5f90211a07ed39b0406d98b1bd4ac969de62251c28166aef8f69e29b63696e872ac189487a0ac5f460011f98632c2a89a230d74496a0f24238ec31b81b976d4e13003c72d6aa0a8fdd52d18c3f32422d855da308c2952d8c3e62d32c7485181002f65ab8b57afa085cbdc3a0cba369c10c95e410f47252771eae14302875332613fa2272185d7b0a0bbb7b4b8517476dbd93814a4261eed6f9c97ca10cd0013cf21a9bffe69f03bdda02b7e730e92a8a17afc75ce75c92392f14f3afa32043e5b657c5591f93e008efaa06031d69caf4b044c76bfb7a5d5858f6379ca738604e6fef330a3b7fc934c6dfaa039a81cf4ec43adc442aeb8d39d0bfb8aea825717d6ec84edaef8a3171b355a6fa0397bc9286b2e7f5a11345fbc1e53723b51574327f4f579c00f271c7cf170c282a040d05c1bac2e6704974b0220b40c98063474954c785440d839079600577e6823a0b0e04d24a63cb027e5fd79eced2cbc22ff9de4e06d5a35ba334962bc651a3c5ca0c1cc67cabe19054542e3868189a139d914a682c079fe24e74ed36d1e6a47b898a0052e33c422e91910ce324727b67906b3ae99c6d743a006864cd27b1db94bc079a0e30908e2fdbf74787f9f314166d71375297e65f616b50241259b2552a454f109a04e8a0da0f4d104807c9179eac1593444c6faa383217e72be55632f3b4a8f82d6a0abcdf9e280b03116a508f9e884d020db4fa6f8c6f99a9876c505e96bb2b1c1ee80f90211a0e8a177164a0903af248c1ce6e407aa3757c2b6e938365119d72680966834944fa0a711179d5280d7807b586b6c6c00a57862d94a74a70622184fe359e6a09fe72fa07f3c6e247a4299cd7363cc1f4c17a095fd3faf2a1e354cbf9181cbb8d89fc369a07e1aead1e3fc3fe359c7d171930b78ec54be8c46f6c14efc279f251725913f0fa0109cead3dc197d9277fb5e2ee00ffcd12f7041371ac2eb0327922b10d4e26b16a0ed93a1e844d80ba5a171225d21389aae47ec2f3716f8b4e3b2e1a133504043e8a090fd100b80e8158b315854543af17087f8857e54184db7bc3d9de77fda32a0bda0851eee7ce719e6a015ec9c875508ac9905c4a2eccda37316446956afcf4e23baa0d2a294eeae765264513ccca891aa919d34c69b3111b835f63c8737d352668009a019285dbf4f245f329403d24543ad83274ecc3284d4c57cc3a88b3ce1ea1ac11ca0d4629a9597ed272e17b235ad29c7da794ee32760ba098bdd7d14b6e810f24368a09c336ad8430de2df7f43ec60444a4ed070ad13922ddab175d86f91addd963297a0a868e36c2bb51e60dd302a18bd778ee75b322b970a08a3649134a8a10e1aba81a07b1a01c6802541dd28d535ae227ac6c98f0ef33f145adf82a4b96852ec6f3f73a0dcc13ebca88dbd8a0c55faeed20caccb28d62a502cf0db77b485784c57c3bf80a0a87e59e39a094f2913274ab52a8de1cf792927ac7d5fee29cdf562e245d0dc2e80f90211a01757917e9224d8e39d6c944a96ced33c52745a1c06314a6ae5c1ef0028ae02b9a0eba8b1fb250c33e15be6403379c85a3f474632f94551e21d2021b835ef1cf16da0971be97201d6089d0284e9ce1390dbb801ea7f7e949d8d27a24c129f152563c1a0a19c1d33affc5b418fd755923e54e9120e474f6b0d2a349cba84b90a0f66ddd4a08a5b25f5767d0654bc9f7ad9bf5bdc498d23e01b768dd2f0ad8932da48614c12a0d9b92383870f2d89401c36ff30cfd1a534c36d15798aae97eb04b9c430694672a0db39ea934e865b4258aa27a1d15d88c8a708b788245f62ea40382c5955a4c011a0c30b5709545fd2f8ba396bc05d72c7f8d5b307707b36971687e6337585576b4aa05c195afb8eceff2cb8956a4c9fd5627f84a5a3f29b75bfca08cf0ab4426f1820a052e65038019b745358c010b86d25da81f8f328e5972821d5a7626c868348a0e3a06d990082b50c7e9ecc641184adafb135659c66e9cb29a423932f511578cb7126a0761b5db9f8e3a19c119684b48a869ac32abd1288905666224112996815d8b499a087be60024fb57677ffc530ce6e9ffe48b1c4a5656466a7a986a6ef0ba4fd44b6a01ebeaf5225b5edc45237db4838fdcf8fbd9f282e3286ef5b1bd54e8d1a3ce027a00f76986377197ea90ee95620eac59eae4d454c9620f6bca769bc90a5984b244ea0c34a527eec08998e829b2df246b503c28551b6f65ca6a0aa3b4350cb17200f8c80f90151a0744d00ff280e769c2daf908c1e8a4b5e5ea9a653295deb0d07160d83eac7435aa010ef6734ed120f8f8ee079d2bf6db2a234d731e7d08c2f31e4738abc0d8443568080a01755a82d129503f82ff0a92265bb8d056a81456a346b788522aad848a99e000580a0ea8e41e2016c801b99b2bf7333bc5f27283388df703546c69d69057b21b085a8a04cf623a5154bdf4f33ccdfc4d4ab38b8165adb1592c425d49cb877244a2fa68280a084d71f99e326177e070f1618a05fb1bb9e3257cc9ea9c2e9cdc367943f41c4dda0a40b555d93923c9fd96e0ad671c722335b0812cd3e451d95b76e2dce5e38cd6580a080a3d9222507178bb567c5e1041070f041661bf60179e5595b044b10cb88fb8580a0334e35ff43871b958ff4b604161c6da0288f61a12316ed4f0a377d3fc06df37aa02081102b6f79d26a1ca5984a8abd89cf434be02ca2f2c4862494dc34dde73fe880e49f2087fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace838277d7";
        let storage_index = x"0000000000000000000000000000000000000000000000000000000000000002";

        verify_account_proof(&account_proof, &header_root, &fake_addr, &storage_proof, &storage_index);
    }

    #[test, expected_failure]
    fun verify_account_proof_fail_wrong_storageProof_test() {
        let account_proof = x"b90e34f90211a0b741140d3a6318a3379ff67e3bb89fa9780c8aaf0fdabea6198098d792391597a0c4e5a99e315464eaf6392a999144d19f59173753996cf0981e5c148e04fc5d32a0d718273ac08000412a49c02767fff67d6d4d4c108a67082bc75dfa12174fdac0a038d3b6c562304b4e4ee6a7027783276473e734062c067aa9236aea3836e2a4e9a0c6354069b8d0fe2c1ee604a1248b51a90bacce4ac2f21225e07dc63d83fbc5ffa00a242aca34573f747041cf861bb7d41e5b194098183d0d192915e6f43eede54da0f9ea1862eb571abc0af92222417cd83d36c211da4daffa662614ab28d4499deea0907015eea2c82954a0a0bc757f9b54a7fddd2120cc0a1998a68a428052bcc259a03b451915a431e8c0d6c99dc2de4aec8792117eb7f6d7c58eedab5cfd7a33758ca0cb99a9d235236d18334c73714d695776e07368b7d5087c92be48a80ca7780b00a05d8b69b388bcba32e45754df01bda1c4183dd35507a94e2de2bfa0fa927ed790a01ea856df980fe0ad10de0805c075b7f042dced1c0ad518a1210e4e1b80ee109ba0de4c4a786ee86b865a25083400768a7c580a899c489397439b0002a8361a27eea05c72828ffbee3efaf3744d94aadaefb45fa713642c0310e9505bf2e85fb0ce4ea02f47fc136056fc81ab1ae50ea46184641b03e157129314d78d086b59903dfbb1a0f3126aa208eee8ff04ea98e78a0ecf10443685d546f4a91907fbfda662fe8dc380f90211a09103f4a1135b9f75fd25f1ddb7a556dc2c92c3bd809292fad290ed44c51ec9cea028215cc63bb8b282f90b2bae5a26de6ed0828601a1b19def64bff139f11b48a7a05a4672c87f8d864f2f7487bb844ac8fc48f60178787d91c0093b0a0f0a91ab4ba072cd65ce9ea7a398532319b9dc8de24a68e1fb204cf093bd16a9f4c81d4dd0eda0e4d0321d625b06ae6614224a55ff2d359df21ac8528d43d8bae57813f3c512d0a065ddf9a52b8d2bcaa136e2ed26c308ffb332572c9ff9915a2018f1b07a342fa8a043dc357d9a6d033d905316c499808b0c0d0d4b37fa355f504074312d921730a4a09cf5ee09061b795c036c6f22eb2a0ca69e2178058d6207876700039f027949f2a098329197f44a04470159940c9e11df711a58e8816412ab02cdedc2475115e31fa098aff63fd11ccfa9b5f06377972e66e238aad9e083d3f787c9a825ba473e2350a079192192dbe405ef459915a95b7511e6802e80bf57f4a4d664e840310ec61a48a0c487bc8e5fb7562bb943e2f81d148844e7be196df731c33a768bc009c7914d99a0045d014772a883d3d56ee282eff7936bce6d3240092f11a7efb866bf2406d6b9a0d7c2d37368aa37470bab73b697da24bcdf769f8ef1056f7e3928019b43bfe051a054a55cdef313d9b1cf11e19de0c13c77dbf89f1692fa714a2e944e01dcbb0e07a0e9d532c6e53056ecb6580fc9b3cbf75726b0be1909f25320ba4a2eea4cbcafc680f90211a0f8716ee393c51dddd03dbb0df4d2efa45c8513233f7d42dfa71669ce05faaba5a01318320ee4a0dcdfd38621d887fb601a6ff7b4abeafe313bec24e6a07f925417a016895a43fc6599bcfb06c1169d3e5270663482b3a3b7277754f883e1490a7a26a0ae0c4621c60f4be3884845ca4758bb4d6124a272e4c8259416bf5879d95e63eca032f8ced44550c817aed3e1503440ec7a9cef6f7e0cfb43056fb34a4ef531e971a0b86bed75d646921d8b1854e484a7630073d6a291b1e17205d4899e9efccfca77a0a6d2d71554e85f86804efa0442769c11918ee84d3a9a985004c6eee5085c06b7a0f63088a2c97cf5074a694478874cee1a08e34f1cbb2f35854535a15aa3cc1bffa0c81e76ff2013966e71fb13a69055e0d7902c4b1ffe16f4b631f84149ff6d63a7a0e1efae81604bca3a97993542e94fc3bb1515285bf6b0611c27e719f22e24c1c0a050ae095a2dbb29ef45819c896c9e76b925bae9d8aed3d25bcd0396844f695512a03e7d8c2f7e7b47a2dc32a2d2eca44776407e8dfa1b47f2af29a58a4da37e9e8da0a5faab169bf76c36892fae1aa9b1d0b0d751c00e27f5f62bb0aa7535b643922aa0add12c7750f5489f8eafad74404e3271e460b9700824668599772276e82e37b0a03f3a068b40ed8694709e3a09a15293fc57efc7584894bfa9e2673d600c2d3927a0488f598b0d87617c288382e3165b1d905b457c0d714ce87c8ef29a17ffda4cf080f90211a03791718f24ec0d075d271c2a747469f86e4ec80dbd02abde23a000247f0fd60ca00ffff60b659758ba241c4b6b6172c98a77313ddaa3cba1f90cfecbad43b40d95a0669057ff7dfe0570c0574fa12b63669f3a1f301f6d3d66086d7b45afa6464a9fa0c676aa4205537893fb89bcb1843de2bfca789155ec79136c0d83a3c935747f27a0c74fd524eea3c8c27e7f321e8667fdda138fa95beed00829ce70680183c4def2a0e2656dfa1de703af58e027cc73b6e6c0cc4108334b4960cde0453b83803f3e80a00aa05181348042d171583e7e5995f1d4ec8826d73792909a9effe9af72f69123a0106636d7b70674e206c31c14a2a25acf62bebc9e1d80c8488df1363c1e38813fa0d0176a180120a15dccfd4f0303c9606df8eb43618ec3c9b867746faf03eea31ea0f4e46fccc0219acf1c3c77a7d9ad48de815cdeaeba250c60d57ec491fc5cfe52a06d836a64bcd12166dae91d28fa4a7697f963d6a058e364c6773733d58b9272faa0798c6db0eeda2f013592434c5bfa9ddd421d929d764899bfed5178ac3f9190c5a03cc0bb14dc4d16846dbd840189aa93828602e194e87302ee854ef0ae409e8772a07fee766c12d118209c1762047d4d59dc00e210ac0777828ac4830bbf667fbd11a011b715b76f357e822649aa64b1248c2555a9745c1094966d3cdb07e4c91e88b9a02a4caa5cc29911dd3a651260e35afa493a8262548a2a2c23499da6d004dc3ba080f90211a00fcb2b8e33d8534225f2658b37c7c77ee53f30adcac18923c44c3218ae715842a01b48f71fa960f75f14228c0d83b9c230a3b8d719cc8dbbe7586ec61c9716641ba0c322d340c50ba4d1d8cfbd7b0069dca36ca653d87bbadf0dfdebca93eb2148f6a0f2f74a5fa1dda9960bf858b5f5ebd2aef491070f6f16a06ca608291d3895803fa098062c1354c0b90834b0979ee49fba0df675d9af6cf03e4512610296797bc377a00d89a8a8551ad2f21abcc5a5f0ecd6eb7bfa69dcb3aa5edcf506c8648340b3d2a088855a465d789237a4b54afecf7d4a3ab39c4656ffba364fef2dd3e0e8391612a00a4deaf50f402651d43b6213f625011a3466de8214f58d803e9ecfb9c6d32f31a021eb5e5135d77ac459f32aa99843ac50cdab749fd0e733ff478bc51dcdb5638da098aa811c9c145224069e24d558efda6f7c64e1d886394c6fe8892fae95a3922ba005d95fe792634d32ead3406168c7d2c0ded050e47c652cd6f2fb473e29ab0f79a04653b9e5a5fffa6e8c92d9cc3fa7fe42239942db03833aa9e4f210571399d174a01b14d6732668376797dec7a1da1b84d2b59d611324adc902660a92d12d3d4722a0c614db8a884fd513a2367447182e028e0dbaf9b5611acc1b7dbe12a3beebd987a0e328066c1167c02968dc8eab0ce4a4acfacc1b73b37e37f44204ece1ad07a2a9a0e4be8aa9a188a76453218513eccda6c2fe4ad61b1cd43970d64a1e92c8b63c9680f90211a0ee940971034a948744d99fbc58addd15a579e2d85a4f65fcb805f0eeed67bf4fa038ed332850bf07d19e022fb5d949d4fa17863c27788525eb5a4c6ced2568efb6a0e970b422efc8c39b8ed1b6ed57f163027eff6ce3b35277528264299ee25990e7a0be241ddd1c79f5f34fe4e059773d084d6fa4f30939a9b0ce3acdee3c03f97a22a09e814449c24dad2bf119541863cebd094f803666e7dd499fa76d9afd3a1af29ea021c860a5f7a50b183ef2cf2b1cfa7ff4457fc0e0ac5ebce5e826a44a02471f8da0f144e39fb40ae9528759fb524d64274ccffc044339cc56751f9335942d47b6c5a0f5f1ea3b4c496fcf2c86cf622e90083787d3b159304936d858dd7454302abf66a0b124f85d96b311bbc255135e0bec0d3ac4437da0003edaeaf3cdff05038144efa0d17bb8aa7775a9ed5746c47504a123f194cdee2d4a7c48cc36272120061588f6a0eb75ebdd6fde798d6e8e4b0eac8ae24b46e70a7bf6a94b6c9f34d38cfaf2a4bca0274e9ebb63919d9491b5cdeea4810b1eb7e4bf30eaf8f2be3c832638c06ec0c2a067df00968f1926dc7e5b26079156e3c496d61b9bb601fed5bbbce627c651d790a0ecf18162af98abd61084233499216ae327f78655bc49d36463238bfad8dd9cb2a0c898d513f8446f4dc600d16dfb5ae11e219fc22b2fabb136d3f9e244ab9fcc40a05dc97cd537c68b8f8083c82cbbc2812ff47dd211fed57526e4649a743a4f1e3480f90151a0f0193db74be08058606b46ebb78cc3911465de28ed81fd59466e24bbb73cd2e880a02833bf6404301c0d0c52eef381415ffdbc3badc79747c3e44395dbbc151e706180a0152e0e6aed172abc678ab7ae41870b45dfdf8ed0329c30b28c8eb3cfb99b7b8a8080a074a07e62ec8601cb080a74b071acc9cc23ee134079137c7c4955b7603fd916c3a08185c4940af6b500466b727eaaa1607a7f60fb947c75d52d08bbd68e5898f11ba057c58a71ea1b2d4cd8db94c73fee1a0d402e2a88f149f2ac0577a65ce043763b80a001dd15f3e3e3ad962529522fec84b2fb9285a1933b471cce2446148488025857a00fa778a067f12adcf5d967ba4b75055a0c76801028127451bf3047c693344abb80a05f8715aacb30c8680edd6f5776e119902cc4747dac42a485c9d79fe0181a6125a00e8c1fdf2da7e992a26589d2f8efa93eb70a27dd5b1eb985541b1c7a8d6842f580f8669d3837e47e9d97fea44bf893a771a304a3232304719598eff3743ca7ae4bb846f8440180a06b58bbd6d52464ecf91852537153b98ae5d05872cd57ef8777e3a158c7158bf0a0614777117c0a31bb33af852628e78b108a6e6e6b3bb9e938deaaee7e2b033adb";
        let header_root = x"b2d2e3feec4af059219e8afdbabfcf4df54aa2a0374bb0206abc4685c60879dc";
        let account_addr = x"cf2afe102057ba5c16f899271045a0a37fcb10f2";
        let invalid_storage_proof = x"b907b5f90211a07687280b5ba058a93b413af112a130a8d39637c247f8d85192a7c67c70ee3950a09cb1f22c785aa679546ca918b95aa6c5104599632ffddbc5a1d512fddd2ef71fa055c8df2b2e43e8a5eea117ab89503f37322511e79cf85b8cfce984b28b7a2aa1a08e0962297f7a46090c3b032219747225116e76d6ebc1bafef7be592de9e1bfa2a0377dd047779e0391709fb1ea4ff97a994de6e7aeba1495f233dc75c365f38216a027f4962abe05821d4fcfd5f0e904698030352123a7f712dfbc614e96661ed063a0424b3a3cf2ab62f6c30dd3c3b6ebdefb0845b2f8fb4be70616ace3d9cb161817a0d5bab3d07df6d090da36de41ab18c22c23d29b6687ff1e8f375f1993d979c93ea089f2ad61b3afb974b8b79d2d55448537b539d17224f8e1cc2ed295322aab010ca0d64da88dd795554c52ec51ae52a16ada35cae4e6b7e4668eb41d6e74cf27640fa0caeccfa6e0d12f1294d875a0f050605e313925586b2d3f2493444f0c6869d0dfa097a42c039fa8d4905ec2c04fd2e72c24266ff79b9c87b850bef961daff7a6fb3a0df45dd7904409da0b383f85db1ef4c48f3122adc9b5abf27ccb60ef289fea54da04178aa4710a49814f40094eb21ad07261080bdba8c1451a2e45b4ed1361a0c13a0620d569ac2590827749739a545f47f237e8e2680bef2374327fad845c8296c93a0e95707a43973f82676ce9b35e3b7f2fdfba4e45a0b881d83cf82f36123ca930080f90211a0b037fdbdf256ff0ecca12de327d220ff28b3f3d312cc2e8b70e34586739e5c81a0fc894be17703ca157bf8f71587b42d0edca445b0720539201e68ee082af7eb6ba05cbda5d75281c8e1077b80785fa479301fd19ddbc6294e8c9a0624ed3fb96a76a0ba46ed4b15b5a6d555af8936388de319ba0235e9133df4afe88ec352d47df36fa0ff27f15fbe221fabec8e1ee1f0d1636de5fc1e6b125e2078032fc9aabdf03c05a0530e5949f4f4c3e7d2e289033332e823bf8ff1eced5fd0d58f6a1d7472944275a0cecb7c33f85f57fef3332095ff42dcaadbeb628119489fa8208a0a8c73a32436a028278f80ac8f391556534ea318023f52e771fe2a7743a745ab1bf58573a4133da04dfa02bb84ff96b50105e701b21822a529f3dbc9f0f6fe59fe219e8520221b27a0741c90073feccaa156ba8be321eb940f04614fba23157986e2e3b426277d53a7a0fdce8171737b54cc5ed4d53d23feef560f7035ec7dc34e33428e2caefd50d82ea0e852d38aeeb1862f232352c139ad640e857e7565e7a6d667b2196074dcac7a3ea05429a515bcf40e1cbc650bfca440e1a41d5fd0b9684764028a850ed66d69b17ca03447aa76626b769e552d4a98e336a79c083015665b5af3f4b5e6314f4592aecfa0bbd0785e0b664b80a3baf8130348df9e1e18fc5dcae41a9c9888df41486a9d08a0c09fcaf04068f935ef9bcbb4819c0cdc5cfc5ea68feedd4fe6cabc9c83e7561480f90211a05149ec605b794803218602aea6a0c8c8f2f4cb67435bf252225b2126ee219d48a0b9c3d332d3ed112cfddfdcf94ec567e7d900255ea7019035de992e0a11a10047a0a0150e15e0a12f891fd0191eb1777c709c5f994d9d3cbb0fb11dba6e6b779395a0e3804dd5ea32d1d04f20713c9feae3f47ab55f37b9ae300118a194764ed34c91a0f759bc4b416e2fa1ab4985eb97add20796e1d9be8a00cee66d60a7a32eebe465a071cd26dbffe9cd773fcd505876366427c6b85f9a17ee98ecdae0a6eaa776d1d3a0828996a14daca6697b777f99d05464f1f27caffb242892acae6d4b952a96ca90a0808f3bc9523251abeab1fc1321b9248aeaa495cf14a977f1e482153b6e9bfeada045b5a0071ea3f220397cf1d3971cd29aa50fc9636613f5e69937c7b31e565414a0086202c405274eef66d29e86ee76d933c3debb4cc4e182373b6980ee2c606b4ca0777206af7ac6d1cd3ebc0d5320553c7550ddd8eb1d6b00350aa9d4753c1fb136a0f149f52d5625645ee858246d3294ca169afaa6c146313b15c1c86b2cf4bccd43a0cd6293863bde44dd4a1df7c7919538617e8f107140562087ae2885c35758702ea00d1e699c3613983556a77316d656b67831c13c5e069fb18e2e96e0ed1a80a21da0424155278afe97e32747e3c25fd3340e68e6350a9ea7a06327368064c074d6a5a0c34a527eec08998e829b2df246b503c28551b6f65ca6a0aa3b4350cb17200f8c80f90151a0744d00ff280e769c2daf908c1e8a4b5e5ea9a653295deb0d07160d83eac7435aa010ef6734ed120f8f8ee079d2bf6db2a234d731e7d08c2f31e4738abc0d8443568080a01755a82d129503f82ff0a92265bb8d056a81456a346b788522aad848a99e000580a0ea8e41e2016c801b99b2bf7333bc5f27283388df703546c69d69057b21b085a8a0b0889dcbe633df5eb88b7a612bb25bd685c5d661dbd38b6819d0c197ab30e07680a084d71f99e326177e070f1618a05fb1bb9e3257cc9ea9c2e9cdc367943f41c4dda042d09c033a316c486dd6052b725fefc6d575ecb1a92389ed51db07236cde662180a080a3d9222507178bb567c5e1041070f041661bf60179e5595b044b10cb88fb8580a0334e35ff43871b958ff4b604161c6da0288f61a12316ed4f0a377d3fc06df37aa02081102b6f79d26a1ca5984a8abd89cf434be02ca2f2c4862494dc34dde73fe880e49f2087fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace83828a1c";
        let storage_index = x"0000000000000000000000000000000000000000000000000000000000000002";

        verify_account_proof(&account_proof, &header_root, &account_addr, &invalid_storage_proof, &storage_index);
    }

    #[test, expected_failure]
    fun verify_account_proof_fail_wrong_storageIndex_test() {
        let account_proof = x"b90e34f90211a0b741140d3a6318a3379ff67e3bb89fa9780c8aaf0fdabea6198098d792391597a0c4e5a99e315464eaf6392a999144d19f59173753996cf0981e5c148e04fc5d32a0d718273ac08000412a49c02767fff67d6d4d4c108a67082bc75dfa12174fdac0a038d3b6c562304b4e4ee6a7027783276473e734062c067aa9236aea3836e2a4e9a0c6354069b8d0fe2c1ee604a1248b51a90bacce4ac2f21225e07dc63d83fbc5ffa00a242aca34573f747041cf861bb7d41e5b194098183d0d192915e6f43eede54da0f9ea1862eb571abc0af92222417cd83d36c211da4daffa662614ab28d4499deea0907015eea2c82954a0a0bc757f9b54a7fddd2120cc0a1998a68a428052bcc259a03b451915a431e8c0d6c99dc2de4aec8792117eb7f6d7c58eedab5cfd7a33758ca0cb99a9d235236d18334c73714d695776e07368b7d5087c92be48a80ca7780b00a05d8b69b388bcba32e45754df01bda1c4183dd35507a94e2de2bfa0fa927ed790a01ea856df980fe0ad10de0805c075b7f042dced1c0ad518a1210e4e1b80ee109ba0de4c4a786ee86b865a25083400768a7c580a899c489397439b0002a8361a27eea05c72828ffbee3efaf3744d94aadaefb45fa713642c0310e9505bf2e85fb0ce4ea02f47fc136056fc81ab1ae50ea46184641b03e157129314d78d086b59903dfbb1a0f3126aa208eee8ff04ea98e78a0ecf10443685d546f4a91907fbfda662fe8dc380f90211a09103f4a1135b9f75fd25f1ddb7a556dc2c92c3bd809292fad290ed44c51ec9cea028215cc63bb8b282f90b2bae5a26de6ed0828601a1b19def64bff139f11b48a7a05a4672c87f8d864f2f7487bb844ac8fc48f60178787d91c0093b0a0f0a91ab4ba072cd65ce9ea7a398532319b9dc8de24a68e1fb204cf093bd16a9f4c81d4dd0eda0e4d0321d625b06ae6614224a55ff2d359df21ac8528d43d8bae57813f3c512d0a065ddf9a52b8d2bcaa136e2ed26c308ffb332572c9ff9915a2018f1b07a342fa8a043dc357d9a6d033d905316c499808b0c0d0d4b37fa355f504074312d921730a4a09cf5ee09061b795c036c6f22eb2a0ca69e2178058d6207876700039f027949f2a098329197f44a04470159940c9e11df711a58e8816412ab02cdedc2475115e31fa098aff63fd11ccfa9b5f06377972e66e238aad9e083d3f787c9a825ba473e2350a079192192dbe405ef459915a95b7511e6802e80bf57f4a4d664e840310ec61a48a0c487bc8e5fb7562bb943e2f81d148844e7be196df731c33a768bc009c7914d99a0045d014772a883d3d56ee282eff7936bce6d3240092f11a7efb866bf2406d6b9a0d7c2d37368aa37470bab73b697da24bcdf769f8ef1056f7e3928019b43bfe051a054a55cdef313d9b1cf11e19de0c13c77dbf89f1692fa714a2e944e01dcbb0e07a0e9d532c6e53056ecb6580fc9b3cbf75726b0be1909f25320ba4a2eea4cbcafc680f90211a0f8716ee393c51dddd03dbb0df4d2efa45c8513233f7d42dfa71669ce05faaba5a01318320ee4a0dcdfd38621d887fb601a6ff7b4abeafe313bec24e6a07f925417a016895a43fc6599bcfb06c1169d3e5270663482b3a3b7277754f883e1490a7a26a0ae0c4621c60f4be3884845ca4758bb4d6124a272e4c8259416bf5879d95e63eca032f8ced44550c817aed3e1503440ec7a9cef6f7e0cfb43056fb34a4ef531e971a0b86bed75d646921d8b1854e484a7630073d6a291b1e17205d4899e9efccfca77a0a6d2d71554e85f86804efa0442769c11918ee84d3a9a985004c6eee5085c06b7a0f63088a2c97cf5074a694478874cee1a08e34f1cbb2f35854535a15aa3cc1bffa0c81e76ff2013966e71fb13a69055e0d7902c4b1ffe16f4b631f84149ff6d63a7a0e1efae81604bca3a97993542e94fc3bb1515285bf6b0611c27e719f22e24c1c0a050ae095a2dbb29ef45819c896c9e76b925bae9d8aed3d25bcd0396844f695512a03e7d8c2f7e7b47a2dc32a2d2eca44776407e8dfa1b47f2af29a58a4da37e9e8da0a5faab169bf76c36892fae1aa9b1d0b0d751c00e27f5f62bb0aa7535b643922aa0add12c7750f5489f8eafad74404e3271e460b9700824668599772276e82e37b0a03f3a068b40ed8694709e3a09a15293fc57efc7584894bfa9e2673d600c2d3927a0488f598b0d87617c288382e3165b1d905b457c0d714ce87c8ef29a17ffda4cf080f90211a03791718f24ec0d075d271c2a747469f86e4ec80dbd02abde23a000247f0fd60ca00ffff60b659758ba241c4b6b6172c98a77313ddaa3cba1f90cfecbad43b40d95a0669057ff7dfe0570c0574fa12b63669f3a1f301f6d3d66086d7b45afa6464a9fa0c676aa4205537893fb89bcb1843de2bfca789155ec79136c0d83a3c935747f27a0c74fd524eea3c8c27e7f321e8667fdda138fa95beed00829ce70680183c4def2a0e2656dfa1de703af58e027cc73b6e6c0cc4108334b4960cde0453b83803f3e80a00aa05181348042d171583e7e5995f1d4ec8826d73792909a9effe9af72f69123a0106636d7b70674e206c31c14a2a25acf62bebc9e1d80c8488df1363c1e38813fa0d0176a180120a15dccfd4f0303c9606df8eb43618ec3c9b867746faf03eea31ea0f4e46fccc0219acf1c3c77a7d9ad48de815cdeaeba250c60d57ec491fc5cfe52a06d836a64bcd12166dae91d28fa4a7697f963d6a058e364c6773733d58b9272faa0798c6db0eeda2f013592434c5bfa9ddd421d929d764899bfed5178ac3f9190c5a03cc0bb14dc4d16846dbd840189aa93828602e194e87302ee854ef0ae409e8772a07fee766c12d118209c1762047d4d59dc00e210ac0777828ac4830bbf667fbd11a011b715b76f357e822649aa64b1248c2555a9745c1094966d3cdb07e4c91e88b9a02a4caa5cc29911dd3a651260e35afa493a8262548a2a2c23499da6d004dc3ba080f90211a00fcb2b8e33d8534225f2658b37c7c77ee53f30adcac18923c44c3218ae715842a01b48f71fa960f75f14228c0d83b9c230a3b8d719cc8dbbe7586ec61c9716641ba0c322d340c50ba4d1d8cfbd7b0069dca36ca653d87bbadf0dfdebca93eb2148f6a0f2f74a5fa1dda9960bf858b5f5ebd2aef491070f6f16a06ca608291d3895803fa098062c1354c0b90834b0979ee49fba0df675d9af6cf03e4512610296797bc377a00d89a8a8551ad2f21abcc5a5f0ecd6eb7bfa69dcb3aa5edcf506c8648340b3d2a088855a465d789237a4b54afecf7d4a3ab39c4656ffba364fef2dd3e0e8391612a00a4deaf50f402651d43b6213f625011a3466de8214f58d803e9ecfb9c6d32f31a021eb5e5135d77ac459f32aa99843ac50cdab749fd0e733ff478bc51dcdb5638da098aa811c9c145224069e24d558efda6f7c64e1d886394c6fe8892fae95a3922ba005d95fe792634d32ead3406168c7d2c0ded050e47c652cd6f2fb473e29ab0f79a04653b9e5a5fffa6e8c92d9cc3fa7fe42239942db03833aa9e4f210571399d174a01b14d6732668376797dec7a1da1b84d2b59d611324adc902660a92d12d3d4722a0c614db8a884fd513a2367447182e028e0dbaf9b5611acc1b7dbe12a3beebd987a0e328066c1167c02968dc8eab0ce4a4acfacc1b73b37e37f44204ece1ad07a2a9a0e4be8aa9a188a76453218513eccda6c2fe4ad61b1cd43970d64a1e92c8b63c9680f90211a0ee940971034a948744d99fbc58addd15a579e2d85a4f65fcb805f0eeed67bf4fa038ed332850bf07d19e022fb5d949d4fa17863c27788525eb5a4c6ced2568efb6a0e970b422efc8c39b8ed1b6ed57f163027eff6ce3b35277528264299ee25990e7a0be241ddd1c79f5f34fe4e059773d084d6fa4f30939a9b0ce3acdee3c03f97a22a09e814449c24dad2bf119541863cebd094f803666e7dd499fa76d9afd3a1af29ea021c860a5f7a50b183ef2cf2b1cfa7ff4457fc0e0ac5ebce5e826a44a02471f8da0f144e39fb40ae9528759fb524d64274ccffc044339cc56751f9335942d47b6c5a0f5f1ea3b4c496fcf2c86cf622e90083787d3b159304936d858dd7454302abf66a0b124f85d96b311bbc255135e0bec0d3ac4437da0003edaeaf3cdff05038144efa0d17bb8aa7775a9ed5746c47504a123f194cdee2d4a7c48cc36272120061588f6a0eb75ebdd6fde798d6e8e4b0eac8ae24b46e70a7bf6a94b6c9f34d38cfaf2a4bca0274e9ebb63919d9491b5cdeea4810b1eb7e4bf30eaf8f2be3c832638c06ec0c2a067df00968f1926dc7e5b26079156e3c496d61b9bb601fed5bbbce627c651d790a0ecf18162af98abd61084233499216ae327f78655bc49d36463238bfad8dd9cb2a0c898d513f8446f4dc600d16dfb5ae11e219fc22b2fabb136d3f9e244ab9fcc40a05dc97cd537c68b8f8083c82cbbc2812ff47dd211fed57526e4649a743a4f1e3480f90151a0f0193db74be08058606b46ebb78cc3911465de28ed81fd59466e24bbb73cd2e880a02833bf6404301c0d0c52eef381415ffdbc3badc79747c3e44395dbbc151e706180a0152e0e6aed172abc678ab7ae41870b45dfdf8ed0329c30b28c8eb3cfb99b7b8a8080a074a07e62ec8601cb080a74b071acc9cc23ee134079137c7c4955b7603fd916c3a08185c4940af6b500466b727eaaa1607a7f60fb947c75d52d08bbd68e5898f11ba057c58a71ea1b2d4cd8db94c73fee1a0d402e2a88f149f2ac0577a65ce043763b80a001dd15f3e3e3ad962529522fec84b2fb9285a1933b471cce2446148488025857a00fa778a067f12adcf5d967ba4b75055a0c76801028127451bf3047c693344abb80a05f8715aacb30c8680edd6f5776e119902cc4747dac42a485c9d79fe0181a6125a00e8c1fdf2da7e992a26589d2f8efa93eb70a27dd5b1eb985541b1c7a8d6842f580f8669d3837e47e9d97fea44bf893a771a304a3232304719598eff3743ca7ae4bb846f8440180a06b58bbd6d52464ecf91852537153b98ae5d05872cd57ef8777e3a158c7158bf0a0614777117c0a31bb33af852628e78b108a6e6e6b3bb9e938deaaee7e2b033adb";
        let header_root = x"b2d2e3feec4af059219e8afdbabfcf4df54aa2a0374bb0206abc4685c60879dc";
        let account_addr = x"cf2afe102057ba5c16f899271045a0a37fcb10f2";
        let storage_proof = x"b907b5f90211a07ed39b0406d98b1bd4ac969de62251c28166aef8f69e29b63696e872ac189487a0ac5f460011f98632c2a89a230d74496a0f24238ec31b81b976d4e13003c72d6aa0a8fdd52d18c3f32422d855da308c2952d8c3e62d32c7485181002f65ab8b57afa085cbdc3a0cba369c10c95e410f47252771eae14302875332613fa2272185d7b0a0bbb7b4b8517476dbd93814a4261eed6f9c97ca10cd0013cf21a9bffe69f03bdda02b7e730e92a8a17afc75ce75c92392f14f3afa32043e5b657c5591f93e008efaa06031d69caf4b044c76bfb7a5d5858f6379ca738604e6fef330a3b7fc934c6dfaa039a81cf4ec43adc442aeb8d39d0bfb8aea825717d6ec84edaef8a3171b355a6fa0397bc9286b2e7f5a11345fbc1e53723b51574327f4f579c00f271c7cf170c282a040d05c1bac2e6704974b0220b40c98063474954c785440d839079600577e6823a0b0e04d24a63cb027e5fd79eced2cbc22ff9de4e06d5a35ba334962bc651a3c5ca0c1cc67cabe19054542e3868189a139d914a682c079fe24e74ed36d1e6a47b898a0052e33c422e91910ce324727b67906b3ae99c6d743a006864cd27b1db94bc079a0e30908e2fdbf74787f9f314166d71375297e65f616b50241259b2552a454f109a04e8a0da0f4d104807c9179eac1593444c6faa383217e72be55632f3b4a8f82d6a0abcdf9e280b03116a508f9e884d020db4fa6f8c6f99a9876c505e96bb2b1c1ee80f90211a0e8a177164a0903af248c1ce6e407aa3757c2b6e938365119d72680966834944fa0a711179d5280d7807b586b6c6c00a57862d94a74a70622184fe359e6a09fe72fa07f3c6e247a4299cd7363cc1f4c17a095fd3faf2a1e354cbf9181cbb8d89fc369a07e1aead1e3fc3fe359c7d171930b78ec54be8c46f6c14efc279f251725913f0fa0109cead3dc197d9277fb5e2ee00ffcd12f7041371ac2eb0327922b10d4e26b16a0ed93a1e844d80ba5a171225d21389aae47ec2f3716f8b4e3b2e1a133504043e8a090fd100b80e8158b315854543af17087f8857e54184db7bc3d9de77fda32a0bda0851eee7ce719e6a015ec9c875508ac9905c4a2eccda37316446956afcf4e23baa0d2a294eeae765264513ccca891aa919d34c69b3111b835f63c8737d352668009a019285dbf4f245f329403d24543ad83274ecc3284d4c57cc3a88b3ce1ea1ac11ca0d4629a9597ed272e17b235ad29c7da794ee32760ba098bdd7d14b6e810f24368a09c336ad8430de2df7f43ec60444a4ed070ad13922ddab175d86f91addd963297a0a868e36c2bb51e60dd302a18bd778ee75b322b970a08a3649134a8a10e1aba81a07b1a01c6802541dd28d535ae227ac6c98f0ef33f145adf82a4b96852ec6f3f73a0dcc13ebca88dbd8a0c55faeed20caccb28d62a502cf0db77b485784c57c3bf80a0a87e59e39a094f2913274ab52a8de1cf792927ac7d5fee29cdf562e245d0dc2e80f90211a01757917e9224d8e39d6c944a96ced33c52745a1c06314a6ae5c1ef0028ae02b9a0eba8b1fb250c33e15be6403379c85a3f474632f94551e21d2021b835ef1cf16da0971be97201d6089d0284e9ce1390dbb801ea7f7e949d8d27a24c129f152563c1a0a19c1d33affc5b418fd755923e54e9120e474f6b0d2a349cba84b90a0f66ddd4a08a5b25f5767d0654bc9f7ad9bf5bdc498d23e01b768dd2f0ad8932da48614c12a0d9b92383870f2d89401c36ff30cfd1a534c36d15798aae97eb04b9c430694672a0db39ea934e865b4258aa27a1d15d88c8a708b788245f62ea40382c5955a4c011a0c30b5709545fd2f8ba396bc05d72c7f8d5b307707b36971687e6337585576b4aa05c195afb8eceff2cb8956a4c9fd5627f84a5a3f29b75bfca08cf0ab4426f1820a052e65038019b745358c010b86d25da81f8f328e5972821d5a7626c868348a0e3a06d990082b50c7e9ecc641184adafb135659c66e9cb29a423932f511578cb7126a0761b5db9f8e3a19c119684b48a869ac32abd1288905666224112996815d8b499a087be60024fb57677ffc530ce6e9ffe48b1c4a5656466a7a986a6ef0ba4fd44b6a01ebeaf5225b5edc45237db4838fdcf8fbd9f282e3286ef5b1bd54e8d1a3ce027a00f76986377197ea90ee95620eac59eae4d454c9620f6bca769bc90a5984b244ea0c34a527eec08998e829b2df246b503c28551b6f65ca6a0aa3b4350cb17200f8c80f90151a0744d00ff280e769c2daf908c1e8a4b5e5ea9a653295deb0d07160d83eac7435aa010ef6734ed120f8f8ee079d2bf6db2a234d731e7d08c2f31e4738abc0d8443568080a01755a82d129503f82ff0a92265bb8d056a81456a346b788522aad848a99e000580a0ea8e41e2016c801b99b2bf7333bc5f27283388df703546c69d69057b21b085a8a04cf623a5154bdf4f33ccdfc4d4ab38b8165adb1592c425d49cb877244a2fa68280a084d71f99e326177e070f1618a05fb1bb9e3257cc9ea9c2e9cdc367943f41c4dda0a40b555d93923c9fd96e0ad671c722335b0812cd3e451d95b76e2dce5e38cd6580a080a3d9222507178bb567c5e1041070f041661bf60179e5595b044b10cb88fb8580a0334e35ff43871b958ff4b604161c6da0288f61a12316ed4f0a377d3fc06df37aa02081102b6f79d26a1ca5984a8abd89cf434be02ca2f2c4862494dc34dde73fe880e49f2087fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace838277d7";
        let invalid_storage_index = x"0000000000000000000000000000000000000000000000000000000000000000";

        verify_account_proof(&account_proof, &header_root, &account_addr, &storage_proof, &invalid_storage_index);
    }

    #[test]
    fun verify_header_test() {
        let raw_header = x"f90228a0df4418b616c081d43ed9fc95f0d4aade6dd53b8142501c2b50194ff657b8c5faa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794258af48e28e4a6846e931ddff8e1cdf8579821e5a065d89a0ab347c7447eb652cbc75bc47259fada45a1e20bd617d23b22433a7109a0cb1b6e0b67e482d7449e8fc0fc36b7f9ce5a9fb0cf45f6a9199a5d9e12216d5ea0d4e4d938901e00ea4da08917593dba522a19b68413162444389bb35251dd96e3b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001830f0cc08411e1a30083029bf88463f34193ad0000000000000000000000000000000000000000000000000000000000000000cc830f03c0830f0f78c080c080a063746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365880000000000000000";
        let header_hash = x"3783ca1fac023336e50f0bfc01a66f98b6c54a7c406c22b17159e775928f2e67";
        let validators = vector[x"258af48e28e4a6846e931ddff8e1cdf8579821e5",x"6a708455c8777630aac9d1e7702d13f7a865b27c",x"8c09d936a1b408d6e0afaa537ba4e06c4504a0ae",x"ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c"];
        let rawSealsValid1 = x"f8c9b841a223e26e4a97a82233a12364fc08ee186309ac43b6218d6437b21f67752cf2333e931dae8053b5abb0220b0a66f24a6945c2762817e6ae2b3c1f61ff4296690a01b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501";
        let rawSealsValid2 = x"f9010cb841a223e26e4a97a82233a12364fc08ee186309ac43b6218d6437b21f67752cf2333e931dae8053b5abb0220b0a66f24a6945c2762817e6ae2b3c1f61ff4296690a01b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501b84159d8a54f0840f9bcbfba3e881c74191f0a1593cdc0551d1fdf723cda10ac24af57e1c4278324ec9dc163752148005e975a78265ad688b81c4cc01524f59f811900";
        let rawSealsInvalid1 = x"f886b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501";
        let rawSealsInvalid2 = x"f8c9b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501b84159d8a54f0840f9bcbfba3e881c74191f0a1593cdc0551d1fdf723cda10ac24af57e1c4278324ec9dc163752148005e975a78265ad688b81c4cc01524f59f811900";
        let rawSealsInvalid3 = x"f8c9b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501";
        
        assert!(get_header_hash(raw_header) == header_hash, 0);

        // enough valid seals
        assert!(verify_header(&header_hash, &rawSealsValid1, &validators), 1);

        // there is some fake seals and enough valid seals
        assert!(verify_header(&header_hash, &rawSealsValid2, &validators), 2);

        // no enough valid seals
        assert!(!verify_header(&header_hash, &rawSealsInvalid1, &validators), 3);

        // there is some fake seals and no enough valid seals
        assert!(!verify_header(&header_hash, &rawSealsInvalid2, &validators), 4);

        // there is duplicate seals and no enough valid seals
        assert!(!verify_header(&header_hash, &rawSealsInvalid3, &validators), 5);
    }

    #[test, expected_failure(abort_code = ECRECOVER_EINVALID_SIGNATURE)]
    fun verify_header_fail_fake_seals_test() {
        let header_hash = x"3783ca1fac023336e50f0bfc01a66f98b6c54a7c406c22b17159e775928f2e67";
        let validators = vector[x"258af48e28e4a6846e931ddff8e1cdf8579821e5",x"6a708455c8777630aac9d1e7702d13f7a865b27c",x"8c09d936a1b408d6e0afaa537ba4e06c4504a0ae",x"ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c"];
        let rawSealsInvalid4 = x"f9010cb841a223e26e4a97a82233a12364fc08ee186309ac43b6218d6437b21f67752cf2333e931dae8053b5abb0220b0a66f24a6945c2762817e6ae2b3c1f61ff4296690a01b8415c7d47956a9e7044d598e328e5a53f2458a8424aa1302687c2a7faf307b22ecf22d531d5621b3018789c4da719e3cb602b714171eb519d0dcab8dbb023cd404401b841ef9c48bfb1ed827ad6a966d366679139167164045430694b80d77492eb78331d49a8a48c3b61991fe156b2426704dfd2bfd0c768fe22b815418c911d08e33d4501b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        // there is invalid seals that fail to recover
        verify_header(&header_hash, &rawSealsInvalid4, &validators);
    }

    #[test]
    fun decode_header_test() {
        let raw_header = x"f90280a08321410bfbf19381ae3d66615fac42fd2d12b4948292119f8f0cd0e4b56a6de9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948c09d936a1b408d6e0afaa537ba4e06c4504a0aea0aa61b49fed0bb4a81ae0516acc7f2e1e349046c223303d863f27905b81fdc8cfa0cc566bb4aff22e12218d0fe2c06bd3e4fbf39a2c2510483cd7b9e12c5a54cfd6a0d4e4d938901e00ea4da08917593dba522a19b68413162444389bb35251dd96e3b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000183015f908411e1a30083029bf884640eb1bdb8830000000000000000000000000000000000000000000000000000000000000000f86183015f908301d4c0f85494258af48e28e4a6846e931ddff8e1cdf8579821e5946a708455c8777630aac9d1e7702d13f7a865b27c948c09d936a1b408d6e0afaa537ba4e06c4504a0ae94ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c80c080a063746963616c2062797a616e74696e65206661756c7420746f6c6572616e636588000000000000000008";
        let root = x"aa61b49fed0bb4a81ae0516acc7f2e1e349046c223303d863f27905b81fdc8cf";
        let number = 90000u64;
        let epoch_end_height = 120000u64;
        let validators = vector[x"258af48e28e4a6846e931ddff8e1cdf8579821e5",x"6a708455c8777630aac9d1e7702d13f7a865b27c",x"8c09d936a1b408d6e0afaa537ba4e06c4504a0ae",x"ad3bf5ed640cc72f37bd21d64a65c3c756e9c88c"];
        
        let (root_, number_) = decode_header(&raw_header);
        let (epoch_end_height_, validators_) = decode_extra(&raw_header);

        assert!(root == root_, 1);
        assert!(number == number_, 2);
        assert!(epoch_end_height == epoch_end_height_, 3);
        assert!(validators == validators_, 4);
    }
}

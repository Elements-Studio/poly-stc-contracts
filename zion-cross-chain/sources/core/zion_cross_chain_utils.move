module Bridge::zion_cross_chain_utils {

    use Bridge::Bytes;

    use StarcoinFramework::BCS;
    use StarcoinFramework::EVMAddress;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Math;
    use StarcoinFramework::Option;
    use StarcoinFramework::Signature;
    use StarcoinFramework::Vector;

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
        let account_key = Hash::sha3_256(*account_addr);
        let account = verify_mpt_proof(account_proof, &account_key, header_root);

        (account, _) = rlp_split(&account, 0);
        let (_, offset) = rlp_split(&account, 0); // nonce
        (_, offset) = rlp_split(&account, offset); // balance
        let (storage_root, _) = rlp_split(&account, offset);

        let storage_key = Hash::sha3_256(*storage_index);
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
        let node = Bytes::slice(raw, offset, full_size);
        if (full_size < 32) {
            node == *hash
        } else {
            Hash::sha3_256(node) == *hash
        }
    }

    public fun compare_and_slice_key(key: &mut vector<u8>, element: &vector<u8>): bool {
        let element_len = Vector::length(element);
        let key_len = Vector::length(key);
        if (key_len < element_len) return false;
        if (Bytes::slice(key, 0, element_len) == *element) {
            *key = Bytes::slice(key, element_len, key_len - element_len);
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
        Hash::sha3_256(key)
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
        let prefix = if (is_odd == 1) {
            *Vector::borrow(key_hex, 0)
        }  else {
            0x00
        };
        prefix = prefix + (t << 4);
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
        let sig_bytes = Bytes::slice(seal, 0, APTOS_SIG_LEN);
        let recovery_id = *Vector::borrow<u8>(seal, APTOS_SIG_LEN);
        ecrecover(msg_hash, &sig_bytes, recovery_id)
    }

    public fun ecrecover(
        msg_hash: &vector<u8>,
        sig_bytes: &vector<u8>,
        _recovery_id: u8,
    ): vector<u8> {
        let evm_address = Signature::ecrecover(*msg_hash, *sig_bytes);
        if (Option::is_some(&evm_address)) {
            EVMAddress::into_bytes(Option::destroy_some(evm_address))
        } else {
            Vector::empty<u8>()
        }
    }
    //     let sig = secp256k1::ecdsa_signature_from_bytes(*sig_bytes);
    //     let signer_opt = secp256k1::ecdsa_recover(*msg_hash, recovery_id, &sig);
    //     assert!(option::is_some(&signer_opt), ECRECOVER_EINVALID_SIGNATURE);
    //     ecdsa_public_key_to_zion_address(&option::destroy_some<secp256k1::ECDSARawPublicKey>(signer_opt))
    // }
    //
    // public fun ecdsa_public_key_to_zion_address(pk: &secp256k1::ECDSARawPublicKey): vector<u8> {
    //     let pk_bytes = secp256k1::ecdsa_raw_public_key_to_bytes(pk);
    //     let pk_hash = Hash::sha3_256(pk_bytes);
    //     Bytes::slice(&pk_hash, Vector::length<u8>(&pk_hash) - ZION_ADDRESS_LEN, ZION_ADDRESS_LEN)
    // }

    public fun get_header_hash(raw_header: vector<u8>): vector<u8> {
        Hash::sha3_256(raw_header)
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
        (_, offset) = rlp_read_kind(raw_header, offset + size); // position of Extra(with digest)
        (_, offset) = rlp_read_kind(
            raw_header,
            offset + 0x20
        ); // position of Extra(without digest) , a bytes32 digest is appended before extra
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
        let enc_value = u64_to_evm_format_bytes32(value_len);
        Vector::append(&mut enc_value, Bytes::right_padding(&padded_value, padding_zeros));
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
        Vector::reverse(&mut Bytes::right_padding(&value_bytes, EVM_SLOT_LENGTH - value_len));
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
        (Bytes::slice(raw, offset, size), offset + size)
    }

    // return (value, offset_)
    public fun rlp_get_next_zion_address(
        raw: &vector<u8>,
        offset: u64,
    ): (vector<u8>, u64) {
        let size;
        (size, offset) = rlp_read_kind(raw, offset);
        assert!(size == ZION_ADDRESS_LEN, RLP_ZION_ADDRESS_EINVALID_DATA_LENGTH);
        (Bytes::slice(raw, offset, size), offset + size)
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
        assert!(size <= 16, RLP_U128_EINVALID_DATA_LENGTH);
        rlp_read_uint(raw, offset, size)
    }

    // return (value, offset_)
    public fun rlp_get_next_u256(
        raw: &vector<u8>,
        offset: u64,
    ): (u128, u64) {
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
        (Bytes::slice(raw, offset, size), offset + size)
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
    ): (u128, u64) {
        let index = len;
        let val = 0;
        while (index > 0) {
            index = index - 1;
            let b = *Vector::borrow(raw, offset + index);
            if (b == 0) continue;
            val = val + (b as u128) * Math::pow(0x100, (len - index - 1))
        };
        (val, offset + len)
    }
}

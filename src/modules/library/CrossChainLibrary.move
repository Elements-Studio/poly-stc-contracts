address 0xe52552637c5897a2d499fbf08216f73e {
module CrossChainLibrary {
    use 0xe52552637c5897a2d499fbf08216f73e::Bytes;
    use 0xe52552637c5897a2d499fbf08216f73e::ZeroCopySink;
    use 0xe52552637c5897a2d499fbf08216f73e::ZeroCopySource;

    use 0x1::Vector;
    use 0x1::Hash;
    use 0x1::Errors;
    use 0x1::Signature;
    use 0x1::Option::{Self, Option};
    use 0x1::EVMAddress::{Self, EVMAddress};

//    struct Header has key, store, drop, copy {
//        version: u64, //origin uint32
//        chain_id: u64, //origin uint64
//        timestamp: u64, //origin uint32
//        height: u64, //origin uint32
//        consensus_data: u64, //origin uint64
//        prev_block_hash: vector<u8>, //origin bytes32
//        transactions_root: vector<u8>, //origin bytes32
//        cross_states_root: vector<u8>, //origin bytes32
//        block_root: vector<u8>, //origin bytes32
//        consensus_payload: vector<u8>, //origin bytes
//        next_bookkeeper: vector<u8>, //origin bytes20
//    }

//    struct ToMerkleValue has key, store, drop {
//        tx_hash: vector<u8>, //origin bytes, cross chain txhash
//        from_chain_id: u64, //origin uint64
//        make_tx_param: TxParam,
//    }

//    struct TxParam has key, store, drop {
//        tx_hash: vector<u8>, //origin bytes, source chain txhash
//        cross_chain_id: vector<u8>, //origin bytes
//        from_contract: vector<u8>, //origin bytes
//        to_chain_id: u64, //origin uint64
//        to_contract: vector<u8>, //origin bytes
//        method: vector<u8>, //origin bytes
//        args: vector<u8>, //origin bytes
//    }
//

    const POLYCHAIN_PUBKEY_LEN: u64 = 67;
    const POLYCHAIN_SIGNATURE_LEN: u64 = 65;
    const POLYCHAIN_HASH_BYTES_LEN: u64 = 32;
    const BYTES20_LEN: u64 = 20;

    const EQUAL: u8 = 0;
    const LESS_THAN: u8 = 1;
    const GREATER_THAN: u8 = 2;

    const ERR_PUB_KEY_LIST_LEN_ILLEGAL: u64 = 251;  // pub_key_list length illegal!
    const ERR_PUB_KEY_LIST_TOO_SHORT: u64 = 252;  // too short pub_key_list!
    const ERR_MERKLE_PROVE_NEXT_BYTE_FAILED: u64 = 255;  // merkleProve, get NextByte for position info failed
    const ERR_MERKLE_PROVE_FAIL: u64 = 256;  // merkleProve, expect root is not equal actual root
    const ERR_COMPRESS_MC_KEY_LENGTH_TOO_SHORT: u64 = 257;  //compress_mc_pub_key,  key length is too short


    /// @notice                  Verify Poly chain transaction whether exist or not
    /// @param audit_path        Poly chain merkle proof
    /// @param root              Poly chain root
    /// @return                  The verified value included in audit_path
    public fun merkle_prove(audit_path: &vector<u8>, root: &vector<u8>): (vector<u8>){
        let offset: u64 = 0;
        let (value, offset) = ZeroCopySource::next_var_bytes(audit_path, offset);
        let hash = hash_leaf(&value);
        let size = (Vector::length(audit_path) - offset) / 33;
        let node_hash;
        let pos;
        let i = 0;
        while ( i < size){
            (pos, offset) = ZeroCopySource::next_byte(audit_path, offset);
            (node_hash, offset) = ZeroCopySource::next_bytes(audit_path, offset, POLYCHAIN_HASH_BYTES_LEN);
            if (copy pos == x"00") {
                hash = hash_children(&node_hash, &hash);
            } else if (copy pos ==  x"01") {
                hash = hash_children(&hash, &node_hash);
            } else {
                abort ERR_MERKLE_PROVE_NEXT_BYTE_FAILED
            };
            i = i + 1;
        };
        assert(hash == *root, ERR_MERKLE_PROVE_FAIL);
        value
    }


    /// @notice              calculate next book keeper according to public key list
    /// @param keyLen        consensus node number
    /// @param m             minimum signature number
    /// @param pubKeyList    consensus node public key list
    /// @return              two element: next book keeper, consensus node signer addresses
    public fun get_book_keeper(key_len: u64, m: u64, pub_key_list: &vector<u8>): (vector<u8>, vector<vector<u8>>){
        let buf = ZeroCopySink::write_u16(key_len);
        let keepers = Vector::empty();
        let i = 0;
        while ( i < key_len ){
            let public_key = Bytes::slice(pub_key_list, i*POLYCHAIN_PUBKEY_LEN, i*POLYCHAIN_PUBKEY_LEN + POLYCHAIN_PUBKEY_LEN);
            buf = Bytes::concat(&buf, ZeroCopySink::write_var_bytes(&compress_mc_pubkey(&public_key)));
            let hash = Hash::keccak_256(Bytes::slice(&public_key, 3, 3 + 64));
            //slice to 20 bytes
            let hash_len = Vector::length(&hash);
            let keeper:vector<u8>;
            if (hash_len >= BYTES20_LEN){
                keeper = Bytes::slice(&hash, hash_len - BYTES20_LEN, hash_len);
            } else {
                keeper = Bytes::left_padding(&hash, BYTES20_LEN);
            };
            Vector::push_back(&mut keepers, keeper);
            i = i + 1;
        };

        buf = Bytes::concat(&buf, ZeroCopySink::write_u16(m));
        let next_book_keeper = Hash::ripemd160(Hash::sha2_256(buf));
        (next_book_keeper, keepers)
    }



    /// @notice              Verify public key derived from Poly chain
    /// @param _pubKeyList   serialized consensus node public key list
    /// @param sig_list      consensus node signature list
    /// @return              return two element: next book keeper, consensus node signer addresses
    public fun verify_pubkey(pub_key_list: &vector<u8>): (vector<u8>, vector<vector<u8>>){
        assert(Vector::length(pub_key_list) % POLYCHAIN_PUBKEY_LEN == 0 , Errors::invalid_state(ERR_PUB_KEY_LIST_LEN_ILLEGAL));
        let n = Vector::length(pub_key_list) / POLYCHAIN_PUBKEY_LEN;
        assert(n > 1, Errors::invalid_state(ERR_PUB_KEY_LIST_TOO_SHORT));
        get_book_keeper(n, (n - (n - 1) / 3), pub_key_list)
    }


    /// @notice              Verify Poly chain consensus node signature
    /// @param raw_header    Poly chain block header raw bytes
    /// @param sig_list      consensus node signature list
    /// @param keepers       addresses corresponding with Poly chain book keepers' public keys
    /// @param m             minimum signature number
    /// @return              true or false
    public fun verify_sig(raw_header: &vector<u8>, sig_list: &vector<u8>, keepers: &vector<vector<u8>>, m: u64): bool{
        let hash = get_header_hash(raw_header);
        let sig_count = Vector::length(sig_list) / POLYCHAIN_SIGNATURE_LEN;
        let signers = Vector::empty();
        let i = 0;
        while (i < sig_count) {
//            r = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN, i*POLYCHAIN_SIGNATURE_LEN + 32);
//            s = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN + 32, (i*POLYCHAIN_SIGNATURE_LEN + 32) + 32);
//            v_bytes = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN + 64, (i*POLYCHAIN_SIGNATURE_LEN + 64)  + 1);
//            v = (Bytes::bytes_to_u64(&v_bytes) as u8) + 27;
            let signer_buf = Hash::sha2_256(*&hash);
            let signature = Bytes::slice(sig_list, i * POLYCHAIN_SIGNATURE_LEN, (i + 1) * POLYCHAIN_SIGNATURE_LEN);
            let signer_opt: Option<EVMAddress> = Signature::ecrecover(signer_buf, signature);
            if (Option::is_none<EVMAddress>(&signer_opt)) {
                return false
            };
            let signer = EVMAddress::as_bytes(Option::borrow(&signer_opt));
            Vector::push_back(&mut signers, *signer);
            i = i + 1;
        };
        contain_m_addresses(keepers, &signers, m)
    }


    /// @notice               Serialize Poly chain book keepers' info in Starcoin addresses format into raw bytes
    /// @param keepers        The serialized addresses
    /// @return               serialized bytes result
    public fun serialize_keepers(keepers: &vector<vector<u8>>): vector<u8>{
        let keeper_len = Vector::length(keepers);
        let keeper_bytes = ZeroCopySink::write_u64(keeper_len);
        let i = 0;
        while (i < keeper_len){
            keeper_bytes = Bytes::concat(&keeper_bytes, ZeroCopySink::write_var_bytes(Vector::borrow(keepers, i)));
            i = i + 1;
        };
        keeper_bytes
    }


    /// @notice               Deserialize bytes into Starcoin addresses
    /// @param data           The serialized addresses derived from Poly chain book keepers in bytes format
    /// @return               addresses
    //TODO format bytes to starcoin address, which bytes lenght is 16; otherwise, EVMAddress length is 20.
    public fun deserialize_keepers(data: &vector<u8>): vector<vector<u8>>{
        let offset: u64 = 0;
        let keeper_len: u64;
        (keeper_len, offset) = ZeroCopySource::next_u64(data, offset);
        let keepers = Vector::empty();
        let keeper_bytes;
        let i = 0 ;
        while (i < keeper_len) {
            (keeper_bytes, offset) = ZeroCopySource::next_var_bytes(data, offset);
            Vector::push_back(&mut keepers, keeper_bytes);
            i = i + 1;
        };
        keepers
    }


    /// @notice               Deserialize Poly chain transaction raw value
    /// @param data           Poly chain transaction raw bytes
    /// @return               ToMerkleValue struct
    public fun deserialize_merkle_value(data: &vector<u8>):  (
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>) {
        let offset: u64 = 0;

        let (tx_hash, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (from_chain_id, offset) = ZeroCopySource::next_u64(data, offset);
        let (tx_param_tx_hash, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (cross_chain_id, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (from_contract, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (to_chain_id, offset) = ZeroCopySource::next_u64(data, offset);
        let (to_contract, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (method, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (args, _) = ZeroCopySource::next_var_bytes(data, offset);

        (
            tx_hash,
            from_chain_id,
            tx_param_tx_hash,
            cross_chain_id,
            from_contract,
            to_chain_id,
            to_contract,
            method,
            args
        )
    }


    /// @notice            Deserialize Poly chain block header raw bytes
    /// @param *data       Poly chain block header raw bytes
    /// @return            Header struct
    public fun deserialize_header(data: &vector<u8>): (
        u64,
        u64,
        u64,
        u64,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>
    ) {
        let offset: u64 = 0;

        let (version, offset) = ZeroCopySource::next_u32(data, offset);
        let (chain_id, offset) = ZeroCopySource::next_u64(data, offset);
        let (prev_block_hash, offset) = ZeroCopySource::next_bytes(data, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (transactions_root, offset) = ZeroCopySource::next_bytes(data, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (cross_states_root, offset) = ZeroCopySource::next_bytes(data, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (block_root, offset) = ZeroCopySource::next_bytes(data, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (timestamp, offset) = ZeroCopySource::next_u32(data, offset);
        let (height, offset) = ZeroCopySource::next_u32(data, offset);
        let (consensus_data, offset) = ZeroCopySource::next_u64(data, offset);
        let (consensus_payload, offset) = ZeroCopySource::next_var_bytes(data, offset);
        let (next_bookkeeper, _) = ZeroCopySource::next_bytes(data, offset, BYTES20_LEN);

        (
            version,
            chain_id,
            timestamp,
            height,
            consensus_data,
            prev_block_hash,
            transactions_root,
            cross_states_root,
            block_root,
            consensus_payload,
            next_bookkeeper,
        )
    }


    /// @notice            Deserialize Poly chain block header raw bytes
    /// @param rawHeader   Poly chain block header raw bytes
    /// @return            header hash same as Poly chain
    public fun get_header_hash(raw_header: &vector<u8>): vector<u8>{
        Hash::sha2_256(Hash::sha2_256(*raw_header))
    }


    /// @notice          Do hash leaf as the multi-chain does
    /// @param data      Data in bytes format
    /// @return          Hashed value in bytes32 format
    public fun hash_leaf(data: &vector<u8>): vector<u8>{
        Hash::sha2_256(Bytes::concat(&x"00", *data))
    }


    /// @notice          Do hash children as the multi-chain does
    /// @param l         Left node
    /// @param r         Right node
    /// @return          Hashed value in bytes32 format
    public fun hash_children(l: &vector<u8>, r: &vector<u8>): vector<u8>{
        let bytes = Bytes::concat(&x"01", *l);
        Hash::sha2_256(Bytes::concat(&bytes, *r))
    }


    /// @notice              Check if the elements number of signers within keepers array is no less than m
    /// @param keepers       The array consists of serveral address
    /// @param signers       Some specific addresses to be looked into
    /// @param m             The number requirement paramter
    /// @return              True means containment, false meansdo do not contain.
    public fun contain_m_addresses(keepers: &vector<vector<u8>>, signers: &vector<vector<u8>>, m: u64): bool{
        let cm:u64 = 0;
        let i = 0;
        let signers_len = Vector::length(signers);
        while ( i < signers_len){
            let j = 0;
            let keepers_len = Vector::length(keepers);
            while ( j < keepers_len) {
                let signer = Vector::borrow(signers, i);
                let keeper = Vector::borrow(keepers, j);
                if (*signer == *keeper) {
                    cm = cm + 1;
                    // Delete does not change the array length.
                    // It resets the value at index to it's default value,
                    // in this case 0
                    let delete_keeper = Vector::borrow_mut(&mut *keepers, j);
                    *delete_keeper = x"00";
                };
                j = j + 1;
            };
            i = i + 1;
        };
        return cm >= m
    }


    public fun compress_mc_pubkey(key: &vector<u8>): vector<u8> {
        assert(Vector::length(key) >= 67, ERR_COMPRESS_MC_KEY_LENGTH_TOO_SHORT);
        let newkey = Bytes::slice(key, 0, 35);
        let newkey_index_2 = Vector::borrow_mut(&mut newkey, 2);
        if (*Vector::borrow(key, 66) % 2 == 0){
            *newkey_index_2 = 02u8;
        } else {
            *newkey_index_2 = 03u8;
        };
        newkey
    }

}
}
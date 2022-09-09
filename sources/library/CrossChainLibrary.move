module Bridge::CrossChainLibrary {
    use Bridge::Bytes;
    use Bridge::ZeroCopySink;
    use Bridge::ZeroCopySource;

    use StarcoinFramework::Vector;
    use StarcoinFramework::Hash;
    use StarcoinFramework::Errors;
    use StarcoinFramework::Signature;
    use StarcoinFramework::Option::{Self, Option};
    use StarcoinFramework::EVMAddress::{Self, EVMAddress};
    use StarcoinFramework::BCS;

    // struct Header has key, store, drop, copy {
    //     version: u64, //origin uint32
    //     chain_id: u64, //origin uint64
    //     timestamp: u64, //origin uint32
    //     height: u64, //origin uint32
    //     consensus_data: u64, //origin uint64
    //     prev_block_hash: vector<u8>, //origin bytes32
    //     transactions_root: vector<u8>, //origin bytes32
    //     cross_states_root: vector<u8>, //origin bytes32
    //     block_root: vector<u8>, //origin bytes32
    //     consensus_payload: vector<u8>, //origin bytes
    //     next_bookkeeper: vector<u8>, //origin bytes20
    // }

    // struct ToMerkleValue has key, store, drop {
    //     tx_hash: vector<u8>, //origin bytes, cross chain txhash
    //     from_chain_id: u64, //origin uint64
    //     make_tx_param: TxParam,
    // }

    // struct TxParam has key, store, drop {
    //     tx_hash: vector<u8>, //origin bytes, source chain txhash
    //     cross_chain_id: vector<u8>, //origin bytes
    //     from_contract: vector<u8>, //origin bytes
    //     to_chain_id: u64, //origin uint64
    //     to_contract: vector<u8>, //origin bytes
    //     method: vector<u8>, //origin bytes
    //     args: vector<u8>, //origin bytes
    // }

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


    // @notice                  Verify Poly chain transaction whether exist or not
    // @param audit_path        Poly chain merkle proof
    // @param root              Poly chain root
    // @return                  The verified value included in audit_path
    public fun merkle_prove(audit_path: &vector<u8>, root: &vector<u8>): vector<u8>{
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
        assert!(hash == *root, ERR_MERKLE_PROVE_FAIL);
        value
    }


    // @notice              calculate next book keeper according to public key list
    // @param keyLen        consensus node number
    // @param m             minimum signature number
    // @param pubKeyList    consensus node public key list
    // @return              two element: next book keeper, consensus node signer addresses
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



    // @notice              Verify public key derived from Poly chain
    // @param _pubKeyList   serialized consensus node public key list
    // @param sig_list      consensus node signature list
    // @return              return two element: next book keeper, consensus node signer addresses
    public fun verify_pubkey(pub_key_list: &vector<u8>): (vector<u8>, vector<vector<u8>>){
        assert!(Vector::length(pub_key_list) % POLYCHAIN_PUBKEY_LEN == 0 , Errors::invalid_state(ERR_PUB_KEY_LIST_LEN_ILLEGAL));
        let n = Vector::length(pub_key_list) / POLYCHAIN_PUBKEY_LEN;
        assert!(n > 1, Errors::invalid_state(ERR_PUB_KEY_LIST_TOO_SHORT));
        get_book_keeper(n, (n - (n - 1) / 3), pub_key_list)
    }


    // @notice              Verify Poly chain consensus node signature
    // @param raw_header    Poly chain block header raw bytes
    // @param sig_list      consensus node signature list
    // @param keepers       addresses corresponding with Poly chain book keepers' public keys
    // @param m             minimum signature number
    // @return              true or false
    public fun verify_sig(raw_header: &vector<u8>, sig_list: &vector<u8>, keepers: &vector<vector<u8>>, m: u64): bool{
        let hash = get_header_hash(raw_header);
        let sig_count = Vector::length(sig_list) / POLYCHAIN_SIGNATURE_LEN;
        let signers = Vector::empty();
        let i = 0;
        while (i < sig_count) {
            // r = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN, i*POLYCHAIN_SIGNATURE_LEN + 32);
            // s = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN + 32, (i*POLYCHAIN_SIGNATURE_LEN + 32) + 32);
            // v_bytes = Bytes::slice(sig_list, i*POLYCHAIN_SIGNATURE_LEN + 64, (i*POLYCHAIN_SIGNATURE_LEN + 64)  + 1);
            // v = (Bytes::bytes_to_u64(&v_bytes) as u8) + 27;
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


    // @notice               Serialize Poly chain book keepers' info in Starcoin addresses format into raw bytes
    // @param keepers        The serialized addresses
    // @return               serialized bytes result
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


    // @notice               Deserialize bytes into Starcoin addresses
    // @param data           The serialized addresses derived from Poly chain book keepers in bytes format
    // @return               addresses
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


    // @notice               Deserialize Poly chain transaction raw value
    // @param data           Poly chain transaction raw bytes
    // @return               ToMerkleValue struct
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


    // @notice            Deserialize Poly chain block header raw bytes
    // @param *data       Poly chain block header raw bytes
    // @return            Header struct
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


    // @notice            Deserialize Poly chain block header raw bytes
    // @param rawHeader   Poly chain block header raw bytes
    // @return            header hash same as Poly chain
    public fun get_header_hash(raw_header: &vector<u8>): vector<u8>{
        Hash::sha2_256(Hash::sha2_256(*raw_header))
    }


    // @notice          Do hash leaf as the multi-chain does
    // @param data      Data in bytes format
    // @return          Hashed value in bytes32 format
    public fun hash_leaf(data: &vector<u8>): vector<u8>{
        Hash::sha2_256(Bytes::concat(&x"00", *data))
    }


    // @notice          Do hash children as the multi-chain does
    // @param l         Left node
    // @param r         Right node
    // @return          Hashed value in bytes32 format
    public fun hash_children(l: &vector<u8>, r: &vector<u8>): vector<u8>{
        let bytes = Bytes::concat(&x"01", *l);
        Hash::sha2_256(Bytes::concat(&bytes, *r))
    }


    // @notice              Check if the elements number of signers within keepers array is no less than m
    // @param keepers       The array consists of serveral address
    // @param signers       Some specific addresses to be looked into
    // @param m             The number requirement paramter
    // @return              True means containment, false meansdo do not contain.
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
        assert!(Vector::length(key) >= 67, ERR_COMPRESS_MC_KEY_LENGTH_TOO_SHORT);
        let newkey = Bytes::slice(key, 0, 35);
        let newkey_index_2 = Vector::borrow_mut(&mut newkey, 2);
        if (*Vector::borrow(key, 66) % 2 == 0){
            *newkey_index_2 = 02u8;
        } else {
            *newkey_index_2 = 03u8;
        };
        newkey
    }


    public fun serialize_tx_args(to_asset_hash: vector<u8>,
                                 to_address: vector<u8>,
                                 amount: u128): vector<u8> {
        let buff = Vector::empty<u8>();
        buff = Bytes::concat(&buff, ZeroCopySink::write_var_bytes(&to_asset_hash));
        buff = Bytes::concat(&buff, ZeroCopySink::write_var_bytes(&to_address));
        buff = Bytes::concat(&buff, ZeroCopySink::write_u256(ZeroCopySink::write_u128(amount)));
        buff
    }

    /**
    * Parse args from transaction value bytes
    * struct TxArgs {
    *    bytes toAssetHash;
    *    bytes toAddress;
    *    uint256 amount;
    * }
    */
    public fun deserialize_tx_args(value_bs: vector<u8>): (vector<u8>, vector<u8>, u128) {
        let offset = 0;
        let (to_asset_hash, offset) = ZeroCopySource::next_var_bytes(&value_bs, offset);
        let (to_address, offset) = ZeroCopySource::next_var_bytes(&value_bs, offset);
        let (amount, _) = ZeroCopySource::next_u128(&value_bs, offset);
        (
            to_asset_hash,
            to_address,
            amount,
        )
    }

    const HEX_SYMBOLS: vector<u8> = b"0123456789abcdef";

    /// Converts a `u8` to its  hexadecimal representation with fixed length (in whole bytes).
    /// so the returned String is `2 * length`  in size
    public fun to_hex_string_without_prefix(value: u8): vector<u8> {
        if (value == 0) {
            return b"00"
        };

        let buffer = Vector::empty<u8>();
        let len = 1;
        let i: u64 = 0;
        while (i < len * 2) {
            Vector::push_back(&mut buffer, *Vector::borrow(&HEX_SYMBOLS, (value & 0xf as u64)));
            value = value >> 4;
            i = i + 1;
        };
        assert!(value == 0, 1);
        Vector::reverse(&mut buffer);
        buffer
    }

    /// Converts a `address` to its  hexadecimal representation with fixed length (in whole bytes).
    /// so the returned String is `2 * length + 2`(with '0x') in size
    public fun address_to_hex_string(addr: address): vector<u8> {
        let hex_string = Vector::empty<u8>();
        Vector::append(&mut hex_string, b"0x");
        let addr_bytes = BCS::to_bytes<address>(&addr);
        let i = 0;
        let len = Vector::length(&addr_bytes);
        while (i < len) {
            let hex_slice = to_hex_string_without_prefix(*Vector::borrow(&addr_bytes, i));
            Vector::append(&mut hex_string, hex_slice);
            i = i + 1;
        };
        hex_string
    }
}

#[test_only]
module Bridge::CrossChainLibraryTest {
    use Bridge::CrossChainLibrary;
    use Bridge::ZeroCopySource;
    use StarcoinFramework::Debug::{Self};
    use StarcoinFramework::Vector;
    use Bridge::CrossChainLibrary::address_to_hex_string;

    const POLYCHAIN_PUBKEY_LEN: u64 = 67;
    const POLYCHAIN_SIGNATURE_LEN: u64 = 65;
    const POLYCHAIN_HASH_BYTES_LEN: u64 = 32;
    const BYTES20_LEN: u64 = 20;

    struct Header has key, store, drop {
        version: u64, //origin uint32
        chain_id: u64, //origin uint64
        timestamp: u64, //origin uint32
        height: u64, //origin uint32
        consensus_data: u64, //origin uint64
        prev_block_hash: vector<u8>, //origin bytes32
        transactions_root: vector<u8>, //origin bytes32
        cross_states_root: vector<u8>, //origin bytes32
        block_root: vector<u8>, //origin bytes32
        consensus_payload: vector<u8>, //origin bytes
        next_bookkeeper: vector<u8>, //origin bytes20
    }

    struct ToMerkleValue has key, store, drop {
        tx_hash: vector<u8>, //origin bytes, cross chain txhash
        from_chain_id: u64, //origin uint64
        make_tx_param: TxParam,
    }

    struct TxParam has key, store, drop {
        tx_hash: vector<u8>, //origin bytes, source chain txhash
        cross_chain_id: vector<u8>, //origin bytes
        from_contract: vector<u8>, //origin bytes
        to_chain_id: u64, //origin uint64
        to_contract: vector<u8>, //origin bytes
        method: vector<u8>, //origin bytes
        args: vector<u8>, //origin bytes
    }


    #[test]
    public fun test_deserialize_header() {
        let raw_header = x"000000009b91561700000000285c4b50cb092422c306eee00b18730bd1e05f0c144bc04d0adf1f44e0aef6c70000000000000000000000000000000000000000000000000000000000000000829ba7727b3bb7d42eff74342bafb37362b4898169750e8b2b8af2267c863ebf6fb8849a086fbed1ccd873b63642cce60ac54875cc3c1f054c1866e0bca5136dc90a185f5e4100007de0abdc2a5b63d5fd0c017b226c6561646572223a312c227672665f76616c7565223a224249703243555764736c424c6b34754979584174417949682f74685a6b5072445539566279697358754c574d6e634a775a49515161434f4b74724474793437454d3541554e4a7542523133546b6857616e56422b4b7a493d222c227672665f70726f6f66223a224a3830534c2b6c62433537306f64426374486f477a45504631516d506f7a4f4332323132553563796b4949346a6b77374d2f74746f317537386e4634347256433443676d344f786f71667943656b3568487132576a413d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a302c226e65775f636861696e5f636f6e666967223a6e756c6c7d0000000000000000000000000000000000000000";

        let _version = 0;
        let _chain_id = 391549339;
        let _prev_block_hash = x"285c4b50cb092422c306eee00b18730bd1e05f0c144bc04d0adf1f44e0aef6c7";
        let _transactions_root = x"0000000000000000000000000000000000000000000000000000000000000000";
        let _cross_states_root = x"829ba7727b3bb7d42eff74342bafb37362b4898169750e8b2b8af2267c863ebf";
        let _block_root = x"6fb8849a086fbed1ccd873b63642cce60ac54875cc3c1f054c1866e0bca5136d";
        let _timestamp = 1595411145;
        let _height = 16734;
        let _consensus_data = 15376233792422011005;
        let _consensus_payload = x"7b226c6561646572223a312c227672665f76616c7565223a224249703243555764736c424c6b34754979584174417949682f74685a6b5072445539566279697358754c574d6e634a775a49515161434f4b74724474793437454d3541554e4a7542523133546b6857616e56422b4b7a493d222c227672665f70726f6f66223a224a3830534c2b6c62433537306f64426374486f477a45504631516d506f7a4f4332323132553563796b4949346a6b77374d2f74746f317537386e4634347256433443676d344f786f71667943656b3568487132576a413d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a302c226e65775f636861696e5f636f6e666967223a6e756c6c7d";
        let _next_bookkeeper = x"0000000000000000000000000000000000000000";

        let offset: u64 = 0;

        let (version, offset) = ZeroCopySource::next_u32(&raw_header, offset);
        let (chain_id, offset) = ZeroCopySource::next_u64(&raw_header, offset);
        let (prev_block_hash, offset) = ZeroCopySource::next_bytes(&raw_header, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (transactions_root, offset) = ZeroCopySource::next_bytes(&raw_header, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (cross_states_root, offset) = ZeroCopySource::next_bytes(&raw_header, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (block_root, offset) = ZeroCopySource::next_bytes(&raw_header, offset, POLYCHAIN_HASH_BYTES_LEN);
        let (timestamp, offset) = ZeroCopySource::next_u32(&raw_header, offset);
        let (height, offset) = ZeroCopySource::next_u32(&raw_header, offset);
        let (consensus_data, offset) = ZeroCopySource::next_u64(&raw_header, offset);
        let (consensus_payload, offset) = ZeroCopySource::next_var_bytes(&raw_header, offset);
        let (next_bookkeeper, _) = ZeroCopySource::next_bytes(&raw_header, offset, BYTES20_LEN);

        Debug::print<u64>(&222110);

        Debug::print(&version);
        Debug::print<u64>(&chain_id);
        Debug::print<u64>(&timestamp);
        Debug::print<u64>(&height);
        Debug::print<u64>(&consensus_data);
        Debug::print<vector<u8>>(&prev_block_hash);
        Debug::print<vector<u8>>(&transactions_root);
        Debug::print<vector<u8>>(&cross_states_root);
        Debug::print<vector<u8>>(&block_root);
        Debug::print<vector<u8>>(&consensus_payload);
        Debug::print<vector<u8>>(&next_bookkeeper);

        assert!(_version == version, 1101);
        assert!(_chain_id == chain_id, 1102);
        assert!(_timestamp == timestamp, 1103);
        assert!(_height == height, 1104);
        assert!(_consensus_data == consensus_data, 1105);
        assert!(_prev_block_hash == prev_block_hash, 1106);
        assert!(_transactions_root == transactions_root, 1107);
        assert!(_cross_states_root == cross_states_root, 1108);
        assert!(_block_root == block_root, 1109);
        assert!(_consensus_payload == consensus_payload, 1110);
        assert!(_next_bookkeeper == next_bookkeeper, 1111);
    }


    #[test]
    public fun test_deserializekeepers() {
        let data = x"08000000000000001409732fac787afb2c5d3abb45f3927da18504f10f147fbfc361a31bdbc57ccc7917fe5dbdbba744e3a814a42a4e85034d5bebc225743da400cc4c0e43727a145d60f39ab5bec41fa712562a5c098d8a128cd40614da9cdffbfccab4181efc77831dc8ce7c442a7c7f14b98d72dc7743ede561f225e1bf258f49aea8f78614b27c53c3fac2d374d86187a51c5e4404fc51bc041402cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"b27c53c3fac2d374d86187a51c5e4404fc51bc04";
        let _keeper_slice_7:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);
        Vector::push_back(&mut _keepers, _keeper_slice_7);

        let keepers = CrossChainLibrary::deserialize_keepers(&data);

        assert!(_keepers == keepers, 1115);
    }


    #[test]
    public fun test_serializekeepers() {
        let _keeper_bytes = x"08000000000000001409732fac787afb2c5d3abb45f3927da18504f10f147fbfc361a31bdbc57ccc7917fe5dbdbba744e3a814a42a4e85034d5bebc225743da400cc4c0e43727a145d60f39ab5bec41fa712562a5c098d8a128cd40614da9cdffbfccab4181efc77831dc8ce7c442a7c7f14b98d72dc7743ede561f225e1bf258f49aea8f78614b27c53c3fac2d374d86187a51c5e4404fc51bc041402cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"b27c53c3fac2d374d86187a51c5e4404fc51bc04";
        let _keeper_slice_7:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);
        Vector::push_back(&mut _keepers, _keeper_slice_7);

        let keeper_bytes = CrossChainLibrary::serialize_keepers(&_keepers);
        Debug::print(&500500);
        Debug::print(&keeper_bytes);
        Debug::print(&_keeper_bytes);
        assert!(keeper_bytes == _keeper_bytes, 1118);
    }


    #[test]
    public fun test_deserialize_merkle_value() {
        let data = x"20e91d858cba58b3dff91bf4b3adcacabf899e106ed6ad86a16a4a29e7817e307c080000000000000020b697330bd7a5850235f97d1bcd1c37739f4bc79a4f8e635dcb46ba45bc600ef4012f14f71b55ef55cedc91fd007f7a9ba386ec978f3aa80200000000000000144ddcf539d13e92d4151b7f5e607d4a09f725c47d06756e6c6f636b4a14000000000000000000000000000000000000000014344cfc3b8635f72f14200aaf2168d9f75df86fd36226100000000000000000000000000000000000000000000000000000000000";

        let _tx_hash = x"e91d858cba58b3dff91bf4b3adcacabf899e106ed6ad86a16a4a29e7817e307c";
        let _from_chain_id = 8;
        let _tx_param_tx_hash = x"b697330bd7a5850235f97d1bcd1c37739f4bc79a4f8e635dcb46ba45bc600ef4";
        let _cross_chain_id = x"2f";
        let _from_contract = x"f71b55ef55cedc91fd007f7a9ba386ec978f3aa8";
        let _to_chain_id = 2;
        let _to_contract = x"4ddcf539d13e92d4151b7f5e607d4a09f725c47d";
        let _method = x"756e6c6f636b";
        let _args = x"14000000000000000000000000000000000000000014344cfc3b8635f72f14200aaf2168d9f75df86fd36226100000000000000000000000000000000000000000000000000000000000";

        let offset: u64 = 0;

        let (tx_hash, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (from_chain_id, offset) = ZeroCopySource::next_u64(&data, offset);
        let (tx_param_tx_hash, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (cross_chain_id, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (from_contract, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (to_chain_id, offset) = ZeroCopySource::next_u64(&data, offset);
        let (to_contract, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (method, offset) = ZeroCopySource::next_var_bytes(&data, offset);
        let (args, _) = ZeroCopySource::next_var_bytes(&data, offset);

        assert!(_tx_hash == tx_hash, 1120);
        assert!(_from_chain_id == from_chain_id, 1121);
        assert!(_tx_param_tx_hash == tx_param_tx_hash, 1122);
        assert!(_cross_chain_id == cross_chain_id, 1123);
        assert!(_from_contract == from_contract, 1124);
        assert!(_to_chain_id == to_chain_id, 1125);
        assert!(_to_contract == to_contract, 1126);
        assert!(_method == method, 1127);
        assert!(_args == args, 1128);
    }


    #[test]
    public fun test_hash_leaf(){
        let _data = x"c73c8b3c730086cfae83d735d2c405d6f5a00c3f1ff21ce91d223038d3c1ab4d";
        let _expect_value = x"a7a6f1010a046d0be82054cfaf0c1c0d664ace8a0f983bed90959f282266d081";

        let value = CrossChainLibrary::hash_leaf(&_data);
        Debug::print(&value);
        Debug::print(&_expect_value);
        assert!(_expect_value == value, 2001);
    }

    #[test]
    public fun test_hash_children(){
        let _l = x"c023ad493c982544e2510b5aeae2bc323a8c42f2ab4dc681e099f6ba6cd50f33";
        let _r = x"061cd147d032d11b1b7b6b5edc389f56d33f939e51be3c7949b357aac4e120df";
        let _expect_value = x"51d45928d93800ffebc80373df7dbe735a2e9c5998b883e69494921fedbbe858";

        let value = CrossChainLibrary::hash_children(&_l, &_r);
        Debug::print(&value);
        Debug::print(&_expect_value);
        assert!(_expect_value == value, 2002);
    }


    #[test]
    public fun test_merkle_prove(){
        let _audit_path = x"20c73c8b3c730086cfae83d735d2c405d6f5a00c3f1ff21ce91d223038d3c1ab4d000213149490394c2a8701af2dba1a303df05148a14092f6e59febca31eee4da660079807fe94ecb6f6d1b0b65be5f45159925a905bab8040af476c372ea0583dbba00b41a753c36f64bbe6d6fcd6c2ba40dc09c4c25b6b877bd363696fe1f62cbf6f700059195b0df4add4239eaef270bc187217dc872d11723d4fce02a3c2510461e5900f3c3d66c4611791ff1ebe8a2ef43f1cbf40876b637522c60a81f511445f8dc17011f86c65842afb760457d5ce8ad38821d2110331a7bbae87fe131a5e610f3a146004add0a7a5c74a56ce64a3555b4a73f367c414c80ecc15672dd86f7bff8bf65bc011daedaae87fc34d28ec3116dc04386c7c650f5db9e3a9a853c6e518821069bda001c6cf42ace3bf6b1a7e60ae29dc10aad67cdf672cdb083c601ee3996576cc2e401a1a8ab20062ebdcfa7a6e8f0c6c8b3de823920abd351eedc33d043de1c1449880171c734d6d77806f9475b69c8426bc5c09ce54c0b4ccb13df4315c62899e9926201f459d25426b21e5f2f6bdabf5e6a79f36002114b1ecc5cfa30a18cf3e4baf98d01ad42157822143a7be209b907901a31863d1b35ad9118c4c45d476e405872fb66017badaf21d00ca7e2a73c64dd7738ddcb6a881dcfb88ef0c171e33bfec529fe0a00e0a6008bab76556dbf47269adc41d6820c6a55982e9362257bfdf02a79ff5b8d01061cd147d032d11b1b7b6b5edc389f56d33f939e51be3c7949b357aac4e120df";
        let _root = x"51d45928d93800ffebc80373df7dbe735a2e9c5998b883e69494921fedbbe858";
        let _expect_value = x"c73c8b3c730086cfae83d735d2c405d6f5a00c3f1ff21ce91d223038d3c1ab4d";

        let value = CrossChainLibrary::merkle_prove(&_audit_path, &_root);
        Debug::print(&value);
        assert!(_expect_value == value, 2003);
    }

    #[test]
    public fun test_get_header_hash(){
        let _raw_header = x"000000009b91561700000000f48a4057bef268cc3fdb034e69dc2e942907e08ac4a420d1b196b8c28ebf5bf2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a8be0a1605a63a31704aec4eb4f1023f1ecc2934bd86f119ab77526f9477af9a57e1a5f508e0000410782720ab189fffd84057b226c6561646572223a332c227672665f76616c7565223a22424f4f336f58796b32524970655651593338547133714a423832737a4a68366e4f6f724a55702f4a4d582b474c707a347a497347394c4a6c34784a6f34657448674f56357169364d484b6674714f69724f755a495a69593d222c227672665f70726f6f66223a22635953525746506f69394748414247526255646836612b35506f4f317776354a557a53417457786845637071757430536a595873344c7453353574534a74334174493059616d4c67524a797a524f68564756626d34673d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a33363433322c226e65775f636861696e5f636f6e666967223a7b2276657273696f6e223a312c2276696577223a342c226e223a382c2263223a322c22626c6f636b5f6d73675f64656c6179223a31303030303030303030302c22686173685f6d73675f64656c6179223a31303030303030303030302c22706565725f68616e647368616b655f74696d656f7574223a31303030303030303030302c227065657273223a5b7b22696e646578223a312c226964223a2231323035303238313732393138353430623262353132656165313837326132613265336132386439383963363064393564616238383239616461376437646437303664363538227d2c7b22696e646578223a342c226964223a2231323035303236373939333061343261616633633639373938636138613366313265313334633031393430353831386437383364313137343865303339646538353135393838227d2c7b22696e646578223a332c226964223a2231323035303234383261636236353634623139623930363533663665396338303632393265386161383366373865376139333832613234613665666534316330633036663339227d2c7b22696e646578223a352c226964223a2231323035303234363864643138393965643264316363326238323938383261313635613065636236613734356166306337326562323938326436366234333131623465663733227d2c7b22696e646578223a382c226964223a2231323035303339333432313434356239343231626434636339306437626338386339333031353538303437613736623230633539653763353131656537643232393938326231227d2c7b22696e646578223a322c226964223a2231323035303338623861663632313065636664636263616232323535326566386438636634316336663836663963663961623533643836353734316366646238333366303662227d2c7b22696e646578223a372c226964223a2231323035303331653037373966356335636362323631323335326665346132303066393964336537373538653730626135336636303763353966663232613330663637386666227d2c7b22696e646578223a362c226964223a2231323035303265623162616162363032633538393932383235363163646161613761616262636464306363666362633365373937393361633234616366393037373866333561227d5d2c22706f735f7461626c65223a5b322c382c352c352c382c372c312c342c352c362c352c342c372c372c332c332c342c362c312c322c342c382c352c342c372c342c362c362c322c322c312c312c382c382c362c362c362c372c382c372c342c382c352c312c332c332c382c352c332c362c332c362c372c352c362c322c332c312c322c362c352c322c312c342c322c312c382c342c382c332c382c372c372c352c312c372c342c342c312c352c322c352c362c312c322c382c332c332c312c332c312c342c312c372c382c362c382c322c352c312c342c352c332c322c322c322c382c332c332c332c362c372c342c372c342c322c372c352c362c375d2c226d61785f626c6f636b5f6368616e67655f76696577223a36303030307d7df8fc7a1f6a856313c591a3a747f4eca7218a820b";
        let _expect_value = x"c8908c09c4303ce7932b9119a9f08101df89fcfed880b77c2eed5c09b2fdd361";

        let value = CrossChainLibrary::get_header_hash(&_raw_header);
        Debug::print(&value);
        assert!(_expect_value == value, 2004);
    }

    #[test]
    public fun test_verify_sig(){
        let _raw_header = x"000000009b91561700000000f48a4057bef268cc3fdb034e69dc2e942907e08ac4a420d1b196b8c28ebf5bf2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a8be0a1605a63a31704aec4eb4f1023f1ecc2934bd86f119ab77526f9477af9a57e1a5f508e0000410782720ab189fffd84057b226c6561646572223a332c227672665f76616c7565223a22424f4f336f58796b32524970655651593338547133714a423832737a4a68366e4f6f724a55702f4a4d582b474c707a347a497347394c4a6c34784a6f34657448674f56357169364d484b6674714f69724f755a495a69593d222c227672665f70726f6f66223a22635953525746506f69394748414247526255646836612b35506f4f317776354a557a53417457786845637071757430536a595873344c7453353574534a74334174493059616d4c67524a797a524f68564756626d34673d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a33363433322c226e65775f636861696e5f636f6e666967223a7b2276657273696f6e223a312c2276696577223a342c226e223a382c2263223a322c22626c6f636b5f6d73675f64656c6179223a31303030303030303030302c22686173685f6d73675f64656c6179223a31303030303030303030302c22706565725f68616e647368616b655f74696d656f7574223a31303030303030303030302c227065657273223a5b7b22696e646578223a312c226964223a2231323035303238313732393138353430623262353132656165313837326132613265336132386439383963363064393564616238383239616461376437646437303664363538227d2c7b22696e646578223a342c226964223a2231323035303236373939333061343261616633633639373938636138613366313265313334633031393430353831386437383364313137343865303339646538353135393838227d2c7b22696e646578223a332c226964223a2231323035303234383261636236353634623139623930363533663665396338303632393265386161383366373865376139333832613234613665666534316330633036663339227d2c7b22696e646578223a352c226964223a2231323035303234363864643138393965643264316363326238323938383261313635613065636236613734356166306337326562323938326436366234333131623465663733227d2c7b22696e646578223a382c226964223a2231323035303339333432313434356239343231626434636339306437626338386339333031353538303437613736623230633539653763353131656537643232393938326231227d2c7b22696e646578223a322c226964223a2231323035303338623861663632313065636664636263616232323535326566386438636634316336663836663963663961623533643836353734316366646238333366303662227d2c7b22696e646578223a372c226964223a2231323035303331653037373966356335636362323631323335326665346132303066393964336537373538653730626135336636303763353966663232613330663637386666227d2c7b22696e646578223a362c226964223a2231323035303265623162616162363032633538393932383235363163646161613761616262636464306363666362633365373937393361633234616366393037373866333561227d5d2c22706f735f7461626c65223a5b322c382c352c352c382c372c312c342c352c362c352c342c372c372c332c332c342c362c312c322c342c382c352c342c372c342c362c362c322c322c312c312c382c382c362c362c362c372c382c372c342c382c352c312c332c332c382c352c332c362c332c362c372c352c362c322c332c312c322c362c352c322c312c342c322c312c382c342c382c332c382c372c372c352c312c372c342c342c312c352c322c352c362c312c322c382c332c332c312c332c312c342c312c372c382c362c382c322c352c312c342c352c332c322c322c322c382c332c332c332c362c372c342c372c342c322c372c352c362c375d2c226d61785f626c6f636b5f6368616e67655f76696577223a36303030307d7df8fc7a1f6a856313c591a3a747f4eca7218a820b";
        let _sig_list = x"7d588d79ac9f0931c69150de6bfe5289f0147893781bffbcc32b5e07bd687d1048dda039ffc1e87de2e98610dc876e97411d604948473904b12b64bed8880bcc00ea8be33bb197c82690987e22e970221de11dfa019f470d784ef211edb6c9a3fd75bf74904adea08ed37a635c4dc58ccc21369afc1abcab4696a42be1097468a400289be668444122fd1d48c62781ded43e6fbda9bdd587dc7ee1bd326390d70e3f0e174fbd4854ed96c697dcee93feabbf7cdf290ebee93d4f5156d75d62b80ba301e79df9e679af49c403bbf05a24af2307adc96b641f4501fdb96e6704d27b2a87278e15bfee5909d4fa62dd45907cba23f833b3e96378d140d56722d1f59821e4006d8349493021e2cd6af96524357867b6be9d24ef33aaf66c430d5f91c33253304380ee17c6839fed964e7ba4910dd26533125b548cff6450140b10caec1b08fe01";

        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);

        let m = 5;

        let value = CrossChainLibrary::verify_sig(&_raw_header, &_sig_list, &_keepers, m);
        Debug::print(&value);
        assert!(value == true, 2011);

        let _signer_0 = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _signer_1 = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _signer_2 = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _signer_3 = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _signer_4 = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        Debug::print(&300600);
        Debug::print(&_signer_0);
        Debug::print(&_signer_1);
        Debug::print(&_signer_2);
        Debug::print(&_signer_3);
        Debug::print(&_signer_4);
    }


    #[test]
    public fun test_contain_m_addresses(){
        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);


        let _signer_slice_0 = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _signer_slice_1 = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _signer_slice_2 = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _signer_slice_3 = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _signer_slice_4 = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";

        let _signers = Vector::empty();
        Vector::push_back(&mut _signers, _signer_slice_0);
        Vector::push_back(&mut _signers, _signer_slice_1);
        Vector::push_back(&mut _signers, _signer_slice_2);
        Vector::push_back(&mut _signers, _signer_slice_3);
        Vector::push_back(&mut _signers, _signer_slice_4);


        let m = 5;

        let value = CrossChainLibrary::contain_m_addresses(&_keepers, &_signers, m);
        Debug::print(&value);
        assert!(value == true, 2012);
    }


    #[test]
    public fun test_compress_mc_pubkey(){
        let _key = x"120504482acb6564b19b90653f6e9c806292e8aa83f78e7a9382a24a6efe41c0c06f39ef0a95ee60ad9213eb0be343b703dd32b12db32f098350cf3f4fc3bad6db23ce";
        let _expect_value = x"120502482acb6564b19b90653f6e9c806292e8aa83f78e7a9382a24a6efe41c0c06f39";

        let value = CrossChainLibrary::compress_mc_pubkey(&_key);
        Debug::print(&value);
        Debug::print(&_expect_value);
        assert!(_expect_value == value, 2013);
    }


    #[test]
    public fun test_get_book_keeper(){
        let _key_len = 8;
        let _m = 6;
        let _pub_key_list = x"1205041e0779f5c5ccb2612352fe4a200f99d3e7758e70ba53f607c59ff22a30f678ff757519efff911efc7ed326890a2752b9456cc0054f9b63215f1d616e574d6197120504468dd1899ed2d1cc2b829882a165a0ecb6a745af0c72eb2982d66b4311b4ef73cff28a6492b076445337d8037c6c7be4d3ec9c4dbe8d7dc65d458181de7b5250120504482acb6564b19b90653f6e9c806292e8aa83f78e7a9382a24a6efe41c0c06f39ef0a95ee60ad9213eb0be343b703dd32b12db32f098350cf3f4fc3bad6db23ce120504679930a42aaf3c69798ca8a3f12e134c019405818d783d11748e039de8515988754f348293c65055f0f1a9a5e895e4e7269739e243a661fff801941352c387121205048172918540b2b512eae1872a2a2e3a28d989c60d95dab8829ada7d7dd706d658df044eb93bbe698eff62156fc14d6d07b7aebfbc1a98ec4180b4346e67cc3fb01205048b8af6210ecfdcbcab22552ef8d8cf41c6f86f9cf9ab53d865741cfdb833f06b72fcc7e7d8b9e738b565edf42d8769fd161178432eadb2e446dd0a8785ba088f12050493421445b9421bd4cc90d7bc88c9301558047a76b20c59e7c511ee7d229982b142bbf593006e8099ad4a2e3a2a9067ce46b7d54bab4b8996e7abc3fcd8bf0a5f120504eb1baab602c5899282561cdaaa7aabbcdd0ccfcbc3e79793ac24acf90778f35a059fca7f73aeb60666178db8f704b58452b7a0b86219402c0770fcb52ac9828c";
        let _next_book_keeper = x"f8fc7a1f6a856313c591a3a747f4eca7218a820b";

        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"b27c53c3fac2d374d86187a51c5e4404fc51bc04";
        let _keeper_slice_7:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);
        Vector::push_back(&mut _keepers, _keeper_slice_7);

        let (next_book_keeper, keepers) = CrossChainLibrary::get_book_keeper(_key_len, _m, &_pub_key_list);

        Debug::print(&333666);
        let i = 0;
        while (i < Vector::length(&_keepers)) {
            Debug::print<vector<u8>>(Vector::borrow(&_keepers, i));
            i = i + 1;
        };
        Debug::print(&_next_book_keeper);
        Debug::print(&next_book_keeper);
        Debug::print(&keepers);

        assert!(_next_book_keeper == next_book_keeper, 2014);
        assert!(_keepers == keepers, 2015);
    }


    #[test]
    public fun test_verify_pubkey(){
        let _pub_key_list = x"1205041e0779f5c5ccb2612352fe4a200f99d3e7758e70ba53f607c59ff22a30f678ff757519efff911efc7ed326890a2752b9456cc0054f9b63215f1d616e574d6197120504468dd1899ed2d1cc2b829882a165a0ecb6a745af0c72eb2982d66b4311b4ef73cff28a6492b076445337d8037c6c7be4d3ec9c4dbe8d7dc65d458181de7b5250120504482acb6564b19b90653f6e9c806292e8aa83f78e7a9382a24a6efe41c0c06f39ef0a95ee60ad9213eb0be343b703dd32b12db32f098350cf3f4fc3bad6db23ce120504679930a42aaf3c69798ca8a3f12e134c019405818d783d11748e039de8515988754f348293c65055f0f1a9a5e895e4e7269739e243a661fff801941352c387121205048172918540b2b512eae1872a2a2e3a28d989c60d95dab8829ada7d7dd706d658df044eb93bbe698eff62156fc14d6d07b7aebfbc1a98ec4180b4346e67cc3fb01205048b8af6210ecfdcbcab22552ef8d8cf41c6f86f9cf9ab53d865741cfdb833f06b72fcc7e7d8b9e738b565edf42d8769fd161178432eadb2e446dd0a8785ba088f12050493421445b9421bd4cc90d7bc88c9301558047a76b20c59e7c511ee7d229982b142bbf593006e8099ad4a2e3a2a9067ce46b7d54bab4b8996e7abc3fcd8bf0a5f120504eb1baab602c5899282561cdaaa7aabbcdd0ccfcbc3e79793ac24acf90778f35a059fca7f73aeb60666178db8f704b58452b7a0b86219402c0770fcb52ac9828c";
        let _next_book_keeper = x"f8fc7a1f6a856313c591a3a747f4eca7218a820b";

        let _keeper_slice_0:vector<u8> = x"09732fac787afb2c5d3abb45f3927da18504f10f";
        let _keeper_slice_1:vector<u8> = x"7fbfc361a31bdbc57ccc7917fe5dbdbba744e3a8";
        let _keeper_slice_2:vector<u8> = x"a42a4e85034d5bebc225743da400cc4c0e43727a";
        let _keeper_slice_3:vector<u8> = x"5d60f39ab5bec41fa712562a5c098d8a128cd406";
        let _keeper_slice_4:vector<u8> = x"da9cdffbfccab4181efc77831dc8ce7c442a7c7f";
        let _keeper_slice_5:vector<u8> = x"b98d72dc7743ede561f225e1bf258f49aea8f786";
        let _keeper_slice_6:vector<u8> = x"b27c53c3fac2d374d86187a51c5e4404fc51bc04";
        let _keeper_slice_7:vector<u8> = x"02cbc020209ef8835388882e2c4c4e6acef96f28";

        let _keepers = Vector::empty();
        Vector::push_back(&mut _keepers, _keeper_slice_0);
        Vector::push_back(&mut _keepers, _keeper_slice_1);
        Vector::push_back(&mut _keepers, _keeper_slice_2);
        Vector::push_back(&mut _keepers, _keeper_slice_3);
        Vector::push_back(&mut _keepers, _keeper_slice_4);
        Vector::push_back(&mut _keepers, _keeper_slice_5);
        Vector::push_back(&mut _keepers, _keeper_slice_6);
        Vector::push_back(&mut _keepers, _keeper_slice_7);

        let (next_book_keeper, keepers) = CrossChainLibrary::verify_pubkey(&_pub_key_list);

        Debug::print(&333666);
        let i = 0;
        while (i < Vector::length(&_keepers)) {
            Debug::print<vector<u8>>(Vector::borrow(&_keepers, i));
            i = i + 1;
        };

        assert!(_next_book_keeper == next_book_keeper, 2017);
        assert!(_keepers == keepers, 2018);
    }

    #[test]
    public fun test_address_to_hex_string() {
        assert!(b"0x4783d08fb16990bd35d83f3e23bf93b8" == address_to_hex_string(@0x4783d08fb16990bd35d83f3e23bf93b8), 2020);
        assert!(b"0x4783d08fb16990bd35d83f3e23bf93b8" != address_to_hex_string(@0x416b32009fe49fcab1d5f2ba0153838f), 2021);

        let str = Vector::empty<u8>();
        Vector::append(&mut str, b"Script::");
        Vector::append(&mut str, address_to_hex_string(@0x416b32009fe49fcab1d5f2ba0153838f));
        assert!(b"Script::0x4783d08fb16990bd35d83f3e23bf93b8" != str, 2021);
    }


}
address 0x2d81a0427d64ff61b11ede9085efa5ad {

module LockProxy {

    use 0x1::Token;
    use 0x1::Event;
    use 0x1::Signer;
    use 0x1::Vector;
    use 0x1::Errors;
    use 0x1::Account;

    use 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainGlobal;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::Address;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::Bytes;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::ZeroCopySink;
    use 0x2d81a0427d64ff61b11ede9085efa5ad::ZeroCopySource;

    const ERROR_LOCK_AMOUNT_ZERO: u64 = 101;
    const ERROR_LOCK_EMPTY_ILLEGAL_TOPROXY_HASH: u64 = 102;
    const ERROR_UNLOCK_CHAIN_ID_NOT_MATCH: u64 = 103;
    const ERROR_UNLOCK_CHAIN_TYPE_NOT_SUPPORT: u64 = 104;
    const ERROR_UNLOCK_EXECUTECAP_INVALID: u64 = 105;
    const ERROR_UNLOCK_INVALID_ADDRESS: u64 = 106;
    const ERROR_UNLOCK_ILLEGAL_FROM_PROXY_HASH: u64 = 107;

    const ADDRESS_LENGTH: u64 = 16;

    struct AssetHashMap<TokenT, ChainType> has key, store {
        to_asset_hash: vector<u8>
    }

    struct ProxyHashMap<ChainType> has key, store {
        to_proxy_hash: vector<u8>,
    }

    struct LockTreasury<TokenT> has key, store {
        token: Token::Token<TokenT>,
    }

    struct LockEventStore has key, store {
        bind_proxy_event: Event::EventHandle<BindProxyEvent>,
        bind_asset_event: Event::EventHandle<BindAssetEvent>,
        unlock_event: Event::EventHandle<UnlockEvent>,
        lock_event: Event::EventHandle<LockEvent>,
    }

    // using SafeMath for uint;
    // using SafeERC20 for IERC20;

    // struct TxArgs {
    //     bytes toAssetHash;
    //     bytes toAddress;
    //     uint256 amount;
    // }
    // address public managerProxyContract;
    // mapping(uint64 => bytes) public proxyHashMap;
    // mapping(address => mapping(uint64 => bytes)) public assetHashMap;
    // mapping(address => bool) safeTransfer;

    struct SetManagerProxyEvent has store, drop {
        height: u128,
        manager: vector<u8>
    }

    struct BindProxyEvent has store, drop {
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    }

    struct BindAssetEvent has store, drop {
        to_chain_id: u64,
        from_asset_hash: Token::TokenCode,
        target_proxy_hash: vector<u8>,
        initial_amount: u128,
    }

    struct UnlockEvent has store, drop {
        to_asset_hash: vector<u8>,
        to_address: vector<u8>,
        amount: u128,
    }

    struct LockEvent has store, drop {
        from_asset_hash: Token::TokenCode,
        from_address: vector<u8>,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_address: vector<u8>,
        amount: u128,
    }

    public fun init_event(signer: &signer) {
        let account = Signer::address_of(signer);
        CrossChainGlobal::require_genesis_account(account);

        move_to(signer, LockEventStore{
            bind_proxy_event: Event::new_event_handle<BindProxyEvent>(signer),
            bind_asset_event: Event::new_event_handle<BindAssetEvent>(signer),
            unlock_event: Event::new_event_handle<UnlockEvent>(signer),
            lock_event: Event::new_event_handle<LockEvent>(signer),
        });
    }

    /// Bind proxy hash, which called by genesis account
    public fun bind_proxy_hash<ChainType: store>(signer: &signer,
                                                 to_chain_id: u64,
                                                 target_proxy_hash: &vector<u8>)
    acquires LockEventStore, ProxyHashMap {
        let account = Signer::address_of(signer);
        CrossChainGlobal::require_genesis_account(account);
        if (!exists<ProxyHashMap<ChainType>>(account)) {
            move_to(signer, ProxyHashMap<ChainType>{
                to_proxy_hash: *target_proxy_hash
            });
        } else {
            let proxy_hash_map = borrow_global_mut<ProxyHashMap<ChainType>>(account);
            proxy_hash_map.to_proxy_hash = *target_proxy_hash;
        };

        let event_store = borrow_global_mut<LockEventStore>(account);
        Event::emit_event(
            &mut event_store.bind_proxy_event,
            BindProxyEvent{
                to_chain_id,
                target_proxy_hash: *target_proxy_hash,
            },
        );
    }

    /// Bind asset hash, which called by genesis account
    public fun bind_asset_hash<TokenT: store,
                               ToChainType: store>(signer: &signer,
                                                 to_chain_id: u64,
                                                 to_asset_hash: &vector<u8>) acquires LockEventStore, AssetHashMap, LockTreasury {
        let account = Signer::address_of(signer);
        CrossChainGlobal::require_genesis_account(account);

        // Asset hash map
        if (!exists<AssetHashMap<TokenT, ToChainType>>(account)) {
            move_to(signer, AssetHashMap<TokenT, ToChainType>{
                to_asset_hash: *to_asset_hash,
            });
        } else {
            let store = borrow_global_mut<AssetHashMap<TokenT, ToChainType>>(account);
            store.to_asset_hash = *to_asset_hash;
        };

        // Lock proxy treasury initialize
        if (!exists<LockTreasury<TokenT>>(account)) {
            move_to(signer, LockTreasury<TokenT>{
                token: Token::zero<TokenT>(),
            });
        };

        let event_store = borrow_global_mut<LockEventStore>(account);
        Event::emit_event(
            &mut event_store.bind_asset_event,
            BindAssetEvent{
                to_chain_id,
                from_asset_hash: Token::token_code<TokenT>(),
                target_proxy_hash: *to_asset_hash,
                initial_amount: get_balance_for<TokenT>(),
            },
        );
    }

    /* @notice                  This function is meant to be invoked by the user,
    *                           a certin amount teokens will be locked in the proxy contract the invoker/msg.sender immediately.
    *                           Then the same amount of tokens will be unloked from target chain proxy contract at the target chain with chainId later.
    *  @param amount            The amount of tokens to be crossed from ethereum to the chain with chainId
    */
    public fun lock<TokenT: store, ChainType: store>(signer: &signer,
                                                     to_chain_id: u64,
                                                     to_address: &vector<u8>,
                                                     amount: u128):
    (
        vector<u8>,
        vector<u8>,
        vector<u8>,
        LockEvent,
        CrossChainGlobal::ExecutionCapability,
    )
    acquires AssetHashMap, ProxyHashMap, LockTreasury {
        // bytes memory toAssetHash = assetHashMap[fromAssetHash][toChainId];
        // require(toAssetHash.length != 0, "empty illegal toAssetHash");

        // TxArgs memory txArgs = TxArgs({
        //     toAssetHash: toAssetHash,
        //     toAddress: toAddress,
        //     amount: amount
        // });
        // bytes memory txData = serialize_tx_args(txArgs);

        // IEthCrossChainManagerProxy eccmp = IEthCrossChainManagerProxy(managerProxyContract);
        // address eccmAddr = eccmp.getEthCrossChainManager();
        // IEthCrossChainManager eccm = IEthCrossChainManager(eccmAddr);

        // bytes memory toProxyHash = proxyHashMap[toChainId];
        // require(toProxyHash.length != 0, "empty illegal toProxyHash");
        // require(eccm.crossChain(toChainId, toProxyHash, "unlock", txData), "EthCrossChainManager crossChain executed error!");
        // emit LockEvent(fromAssetHash, _msgSender(), toChainId, toAssetHash, toAddress, amount);

        assert(amount > 0, Errors::invalid_argument(ERROR_LOCK_AMOUNT_ZERO));

        let genesis_account = CrossChainGlobal::genesis_account();
        let token = Account::withdraw<TokenT>(signer, amount);

        // Lock token
        let lock_token = borrow_global_mut<LockTreasury<TokenT>>(genesis_account);
        Token::deposit<TokenT>(&mut lock_token.token, token);

        let asset_hash_map = borrow_global_mut<AssetHashMap<TokenT, ChainType>>(genesis_account);
        let tx_data = serialize_tx_args(
            *&asset_hash_map.to_asset_hash,
            *to_address,
            amount);

        let proxy_hash_map = borrow_global_mut<ProxyHashMap<ChainType>>(genesis_account);
        assert(Vector::length(&proxy_hash_map.to_proxy_hash) > 0, Errors::invalid_argument(ERROR_LOCK_EMPTY_ILLEGAL_TOPROXY_HASH));

        (
            *&proxy_hash_map.to_proxy_hash,
            b"unlock",
            *&tx_data,
            LockEvent{
                from_address: Address::bytify(Signer::address_of(signer)),
                from_asset_hash: Token::token_code<TokenT>(),
                to_chain_id,
                to_asset_hash: *&asset_hash_map.to_asset_hash,
                to_address: *to_address,
                amount
            },
            CrossChainGlobal::generate_execution_cap(&tx_data, true),
        )
    }

    /// Lock event publish from script
    public fun publish_lock_event(event: LockEvent) acquires LockEventStore {
        let event_store = borrow_global_mut<LockEventStore>(CrossChainGlobal::genesis_account());
        Event::emit_event(
            &mut event_store.lock_event,
            event,
        );
    }

    /* @notice                  This function is meant to be invoked by the ETH crosschain management contract,
    *                           then mint a certin amount of tokens to the designated address since a certain amount
    *                           was burnt from the source chain invoker.
    *  @param argsBs            The argument bytes recevied by the ethereum lock proxy contract, need to be deserialized.
    *                           based on the way of serialization in the source chain proxy contract.
    *  @param fromContractAddr  The source chain contract address
    *  @param fromChainId       The source chain id
    */
    public fun unlock<TokenT: store, ChainType: store>(from_contract_addr: &vector<u8>,
                                                       to_asset_hash: &vector<u8>,
                                                       to_address: &vector<u8>,
                                                       amount: u128,
                                                       tx_hash: &vector<u8>,
                                                       cap: &CrossChainGlobal::ExecutionCapability):
    UnlockEvent acquires ProxyHashMap, LockTreasury {
        assert(
            CrossChainGlobal::verify_execution_cap(cap, tx_hash),
            Errors::invalid_state(ERROR_UNLOCK_EXECUTECAP_INVALID)
        );

        let genesis_account = CrossChainGlobal::genesis_account();

        // Check from contract address
        assert(Vector::length(from_contract_addr) > 0, Errors::invalid_state(ERROR_UNLOCK_ILLEGAL_FROM_PROXY_HASH));
        let asset_hash_map = borrow_global<ProxyHashMap<ChainType>>(genesis_account);

        assert(*&asset_hash_map.to_proxy_hash == *from_contract_addr,
            Errors::invalid_state(ERROR_UNLOCK_ILLEGAL_FROM_PROXY_HASH));

        assert(Vector::length(to_address) == ADDRESS_LENGTH, Errors::invalid_state(ERROR_UNLOCK_INVALID_ADDRESS));
        let native_to_address = Address::addressify(*to_address);

        // Do unlock from lock token treasury
        let token_store = borrow_global_mut<LockTreasury<TokenT>>(CrossChainGlobal::genesis_account());
        let deposit_token = Token::withdraw<TokenT>(&mut token_store.token, amount);
        Account::deposit<TokenT>(native_to_address, deposit_token);

        UnlockEvent{
            to_asset_hash: *to_asset_hash,
            to_address: *to_address,
            amount,
        }
    }

    /// Emit an unlock event with `UnlockEvent` object
    public fun emit_unlock_event<TokenT: store, ChainType: store>(event: UnlockEvent): bool acquires LockEventStore {
        let genesis_account = CrossChainGlobal::genesis_account();
        let event_store = borrow_global_mut<LockEventStore>(genesis_account);
        Event::emit_event(
            &mut event_store.unlock_event,
            event,
        );
        true
    }

    /// Get balance for token
    public fun get_balance_for<TokenT: store>(): u128 acquires LockTreasury {
        let genesis_account = CrossChainGlobal::genesis_account();
        if (!exists<LockTreasury<TokenT>>(genesis_account)) {
            0
        } else {
            let lock_token = borrow_global_mut<LockTreasury<TokenT>>(CrossChainGlobal::genesis_account());
            Token::value<TokenT>(&lock_token.token)
        }
    }

    // function _transferToContract(address fromAssetHash, uint256 amount) internal returns (bool) {
    //     if (fromAssetHash == address(0)) {
    //         // fromAssetHash === address(0) denotes user choose to lock ether
    //         // passively check if the received msg.value equals amount
    //         require(msg.value != 0, "transferred ether cannot be zero!");
    //         require(msg.value == amount, "transferred ether is not equal to amount!");
    //     } else {
    //         // make sure lockproxy contract will decline any received ether
    //         require(msg.value == 0, "there should be no ether transfer!");
    //         // actively transfer amount of asset from msg.sender to lock_proxy contract
    //         require(_transferERC20ToContract(fromAssetHash, _msgSender(), address(this), amount), "transfer erc20 asset to lock_proxy contract failed!");
    //     }
    //     return true;
    // }
    // function _transferFromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
    //     if (toAssetHash == address(0x0000000000000000000000000000000000000000)) {
    //         // toAssetHash === address(0) denotes contract needs to unlock ether to toAddress
    //         // convert toAddress from 'address' type to 'address payable' type, then actively transfer ether
    //         address(uint160(toAddress)).transfer(amount);
    //     } else {
    //         // actively transfer amount of asset from msg.sender to lock_proxy contract 
    //         require(_transferERC20FromContract(toAssetHash, toAddress, amount), "transfer erc20 asset to lock_proxy contract failed!");
    //     }
    //     return true;
    // }


    // function _transferERC20ToContract(address fromAssetHash, address fromAddress, address toAddress, uint256 amount) internal returns (bool) {
    //      IERC20 erc20Token = IERC20(fromAssetHash);
    //     //  require(erc20Token.transferFrom(fromAddress, toAddress, amount), "trasnfer ERC20 Token failed!");
    //      erc20Token.safeTransferFrom(fromAddress, toAddress, amount);
    //      return true;
    // }
    // function _transferERC20FromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
    //      IERC20 erc20Token = IERC20(toAssetHash);
    //     //  require(erc20Token.transfer(toAddress, amount), "trasnfer ERC20 Token failed!");
    //      erc20Token.safeTransfer(toAddress, amount);
    //      return true;
    // }

    // function serialize_tx_args(TxArgs memory args) internal pure returns (bytes memory) {
    //     bytes memory buff;
    //     buff = abi.encodePacked(
    //         ZeroCopySink.WriteVarBytes(args.toAssetHash),
    //         ZeroCopySink.WriteVarBytes(args.toAddress),
    //         ZeroCopySink.WriteUint255(args.amount)
    //         );
    //     return buff;
    // }

    // function deserialize_tx_args(bytes memory valueBs) internal pure returns (TxArgs memory) {
    //     TxArgs memory args;
    //     uint256 off = 0;
    //     (args.toAssetHash, off) = ZeroCopySource.NextVarBytes(valueBs, off);
    //     (args.toAddress, off) = ZeroCopySource.NextVarBytes(valueBs, off);
    //     (args.amount, off) = ZeroCopySource.NextUint255(valueBs, off);
    //     return args;
    // }

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
}
}
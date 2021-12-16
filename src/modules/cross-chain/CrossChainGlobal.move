address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainGlobal {

    use 0x1::Errors;
    use 0x1::Signer;
    use 0x1::Debug;

    friend 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager;
    friend 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

    const ERR_INVALID_ACCOUNT: u64 = 101;
    const ERR_TOKEN_TYPE_INVALID: u64 = 102;

    struct ExecutionCapability {
        opt_code: vector<u8>,
    }

    struct ChainId<ChainType> has key, store {
        chain_id: u64,
    }

    /// Account permission check
    public fun require_genesis_account(account: address) {
        assert(account == genesis_account(), Errors::invalid_argument(ERR_INVALID_ACCOUNT));
    }

    public fun genesis_account(): address {
        @0x2d81a0427d64ff61b11ede9085efa5ad
    }

    public(friend) fun generate_execution_cap(opt_code: &vector<u8>): ExecutionCapability {
        ExecutionCapability { opt_code: *opt_code }
    }

    public(friend) fun destroy_execution_cap(cap: ExecutionCapability) {
        let ExecutionCapability { opt_code : _ } = cap;
    }

    public(friend) fun verify_execution_cap_opt_code(cap: &ExecutionCapability,
                                                     opt_code: &vector<u8>): bool {
        *&cap.opt_code == *opt_code
    }

    /// Set chain id to Chain Type
    public fun set_chain_id<ChainType: store>(signer: &signer, chain_id: u64) {
        let account = Signer::address_of(signer);
        require_genesis_account(account);

        Debug::print(&11111111);
        Debug::print(&chain_id);

        move_to(signer, ChainId<ChainType> {
            chain_id,
        });
        Debug::print(&11111111);
    }

    /// Check chain id is matched to type
    public fun chain_id_match<ChainType: store>(chain_id: u64) : bool acquires ChainId {
        if (exists<ChainId<ChainType>>(genesis_account())) {
            let chain_id_store = borrow_global<ChainId<ChainType>>(genesis_account());
            Debug::print(&33333333);
            Debug::print(&chain_id_store.chain_id);

            chain_id_store.chain_id == chain_id
        } else {
            Debug::print(&22222222);
            false
        }
    }
}
}
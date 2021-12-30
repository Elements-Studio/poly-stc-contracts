address 0x2d81a0427d64ff61b11ede9085efa5ad {

module CrossChainGlobal {

    use 0x1::Errors;
    use 0x1::Signer;

    friend 0x2d81a0427d64ff61b11ede9085efa5ad::CrossChainManager;
    friend 0x2d81a0427d64ff61b11ede9085efa5ad::LockProxy;

    const ERR_INVALID_ACCOUNT: u64 = 101;
    const ERR_TOKEN_TYPE_INVALID: u64 = 102;

    struct STARCOIN_CHAIN has key, store {}

    struct ExecutionCapability {
        tx_data: vector<u8>,
        proof_tx_non_exists: bool,
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

    public(friend) fun generate_execution_cap(tx_data: &vector<u8>,
                                              proof_tx_non_exists: bool): ExecutionCapability {
        ExecutionCapability{
            tx_data: *tx_data,
            proof_tx_non_exists
        }
    }

    public(friend) fun destroy_execution_cap(cap: ExecutionCapability) {
        let ExecutionCapability{
            tx_data : _,
            proof_tx_non_exists: _
        } = cap;
    }


    public(friend) fun tx_hash_has_proof(cap: &mut ExecutionCapability) {
        cap.proof_tx_non_exists = true
    }

    public(friend) fun verify_execution_cap(cap: &ExecutionCapability,
                                            tx_data: &vector<u8>): bool {
        (*&cap.tx_data == *tx_data && cap.proof_tx_non_exists)
    }

    public(friend) fun verify_execution_tx_non_exists(cap: &ExecutionCapability): bool {
        cap.proof_tx_non_exists
    }


    /// Set chain id to Chain Type
    public fun set_chain_id<ChainType: store>(signer: &signer, chain_id: u64) {
        let account = Signer::address_of(signer);
        require_genesis_account(account);

        move_to(signer, ChainId<ChainType>{
            chain_id
        });
    }

    /// Check chain id is matched to type
    public fun chain_id_match<ChainType: store>(chain_id: u64): bool acquires ChainId {
        if (exists<ChainId<ChainType>>(genesis_account())) {
            let chain_id_store = borrow_global<ChainId<ChainType>>(genesis_account());
            chain_id_store.chain_id == chain_id
        } else {
            false
        }
    }
}
}
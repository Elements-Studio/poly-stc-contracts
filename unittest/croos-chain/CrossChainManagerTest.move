address 0xe52552637c5897a2d499fbf08216f73e {
module CrossChainManagerTest {
    use 0x1::Debug;
    use 0xe52552637c5897a2d499fbf08216f73e::CrossChainLibrary;
    use 0xe52552637c5897a2d499fbf08216f73e::LockProxy;

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
        ) = LockProxy::deserialize_tx_args(args);
        Debug::print(&to_asset_hash);
        Debug::print(&to_address);
        Debug::print(&amount);
    }
}
}
// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

interface Protocol {
    function pause() external;
}

contract VerifyProof {
    /* ----------------------------- STORAGE ---------------------------------- */
    mapping(bytes32 => bytes32) public stateRoots;
    mapping(bytes32 => bytes32) commitments;

    /* ----------------------------- EXTERNAL Functions ---------------------------------- */
    function pauseProtocol(
        address protocol,
        bytes calldata proof,
        bytes calldata witness
    ) external {
        require(_verifyProof(proof, witness), "invalid proof");
        Protocol(protocol).pause();
    }

    function _verifyProof(
        bytes calldata proof,
        bytes calldata witness
    ) internal {
        require(proof.length > 511, "PROOF_LEN");
        emit ProofSubmitted();

        (
            bytes32 parentBlockHash,
            bytes32 blockHash,
            bytes32 blockStateRoot,
            ,
            uint256 blockGas,

        ) = _readHeaderParts(witness);
        uint256 parentStateRoot = uint256(stateRoots[parentBlockHash]);
        uint256 chainId = 99;
        (uint256 MAX_TXS, uint256 MAX_CALLDATA) = _getCircuitConfig(blockGas);

        uint256[] memory publicInput = _buildCommitment(
            MAX_TXS,
            MAX_CALLDATA,
            chainId,
            parentStateRoot,
            witness,
            true
        );

        bytes32 expectedCommitmentHash;
        assembly {
            expectedCommitmentHash := keccak256(
                add(publicInput, 32),
                mul(mload(publicInput), 32)
            )
        }

        assembly {
            // function Error(string)
            function revertWith(msg) {
                mstore(0, shl(224, 0x08c379a0))
                mstore(4, 32)
                mstore(68, msg)
                let msgLen
                for {

                } msg {

                } {
                    msg := shl(8, msg)
                    msgLen := add(msgLen, 1)
                }
                mstore(36, msgLen)
                revert(0, 100)
            }

            // verify commitment hash
            {
                // 5 * 32
                let len := 160
                let ptr := mload(64)
                // skip `blockHash, address, is_aggregated`
                calldatacopy(ptr, add(proof.offset, 96), len)
                let hash := keccak256(ptr, len)
                if iszero(eq(hash, expectedCommitmentHash)) {
                    revertWith("commitment hash")
                }
            }

            {
                // call contract at `addr` for proof verification
                let offset := add(proof.offset, 32)
                let addr := calldataload(offset)
                switch extcodesize(addr)
                case 0 {
                    // no code at `addr`
                    revertWith("verifier missing")
                }

                let len := sub(proof.length, 96)
                offset := add(offset, 64)
                let memPtr := mload(64)
                calldatacopy(memPtr, offset, len)
                let success := staticcall(gas(), addr, memPtr, len, 0, 0)
                switch success
                case 0 {
                    // plonk verification failed
                    //returndatacopy(0, 0, returndatasize())
                    //revert(0, returndatasize())
                    revertWith("verifier failed")
                }
            }
        }
    }

    /* ----------------------------- INTERNAL Functions ---------------------------------- */

    function _getCircuitConfig(
        uint256 blockGasLimit
    ) internal pure returns (uint256, uint256) {
        if (blockGasLimit <= 63000) {
            return (3, 10500);
        }

        if (blockGasLimit <= 300000) {
            return (14, 69750);
        }

        revert("CIRCUIT_CONFIG");
    }

    function _buildCommitment(
        uint256 MAX_TXS,
        uint256 MAX_CALLDATA,
        uint256 chainId,
        uint256 parentStateRoot,
        bytes calldata witness,
        bool clearMemory
    ) internal pure returns (uint256[] memory table) {
        // https://github.com/privacy-scaling-explorations/zkevm-specs/blob/08c6c30a7b53f83558a7ea7e50dc0e4d74fab0c8/src/zkevm_specs/public_inputs.py#L290
        assembly ("memory-safe") {
            //@INCLUDE:rlp.yul
            //@INCLUDE:utils.yul

            function rlc(v) -> acc {
                for {
                    let i := 0
                } lt(i, 256) {
                    i := add(i, 8)
                } {
                    let
                        p
                    := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    let randomness := 0x100
                    acc := mulmod(acc, randomness, p)
                    let raw_value := and(shr(i, v), 0xff)
                    acc := addmod(acc, raw_value, p)
                }
            }

            function rlc_le(v) -> acc {
                let randomness := 0x001
                for {
                    let i := 0
                } lt(i, 256) {
                    i := add(i, 8)
                } {
                    let
                        p
                    := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    acc := mulmod(acc, randomness, p)
                    let raw_value := and(
                        v,
                        shr(
                            i,
                            0xff00000000000000000000000000000000000000000000000000000000000000
                        )
                    )
                    acc := addmod(acc, raw_value, p)
                }
            }

            // Only updates the `raw_public_inputs` array.
            function append(value) {
                // increment index
                let rpi_ptr := mload(0)
                mstore(0, add(rpi_ptr, 32))

                // store block value into raw_public_inputs
                mstore(rpi_ptr, value)
            }

            // Writes to the public input table and
            // the raw_public_inputs array.
            function appendTxRow(txId, tag, value) {
                let callframe := mload(96)

                // update `raw_public_inputs` array
                {
                    // increment index
                    let rpi_ptr := mload(0)
                    mstore(0, add(rpi_ptr, 32))

                    // tx_id_col
                    mstore(rpi_ptr, txId)

                    let id_index_value_spread := mload(add(callframe, 96))

                    // skip index_col
                    rpi_ptr := add(rpi_ptr, id_index_value_spread)

                    // value_col
                    rpi_ptr := add(rpi_ptr, id_index_value_spread)
                    mstore(rpi_ptr, value)
                }
            }

            function appendCallDataRow(value) {
                let callframe := mload(96)

                // advance raw_public_inputs
                {
                    // callframe.rpi_ptr_call_data
                    let ptr := add(callframe, 64)

                    // increment index
                    let rpi_ptr_call_data := mload(ptr)
                    mstore(ptr, add(rpi_ptr_call_data, 32))

                    // calldata byte
                    mstore(rpi_ptr_call_data, value)
                }
            }

            // main
            // 0  = rpi_ptr
            // 32 = start of raw_public_inputs ptr
            // 64 = free memory ptr
            // 96 = callframe ptr
            table := mload(64)
            mstore(96, table)
            // reserve 128 bytes for callframe
            // 0..32: callframe.tableOffset
            // 32..64: callframe.calldataTableOffset
            // 64..96: callframe.rpi_ptr_call_data
            // 96..128: callframe.id_index_value_spread
            // 128..160: callframe.calldataBytes
            table := add(table, 160)
            {
                // hashes(256) + block(8) + extra(2)
                let BLOCK_FIELDS := 266
                let TX_FIELDS := 10
                let MAX_TX_FIELDS := mul(TX_FIELDS, MAX_TXS)
                let TX_TABLE_LEN := add(MAX_TX_FIELDS, 1)

                let N_RAW_INPUTS := add(BLOCK_FIELDS, mul(3, TX_TABLE_LEN))
                N_RAW_INPUTS := add(N_RAW_INPUTS, MAX_CALLDATA)

                let N_INSTANCE_VALUES := 5
                // uint256[].length
                mstore(table, N_INSTANCE_VALUES)
                table := add(table, 32)

                // end of pi table
                let endOfRows := add(table, mul(N_INSTANCE_VALUES, 32))

                // start of raw_public_inputs
                mstore(32, endOfRows)
                // rpi_ptr
                mstore(0, endOfRows)

                // end of raw_public_inputs, update free memory pointer
                {
                    let len := mul(N_RAW_INPUTS, 32)
                    let memTail := add(endOfRows, len)
                    mstore(64, memTail)
                    // XXX: normally we could check if the memory region
                    // is dirty via MSIZE, though solc complaints.
                    // Make it optional.
                    if clearMemory {
                        calldatacopy(table, calldatasize(), len)
                    }
                }

                // callframe.tableOffset
                let callframe := mload(96)
                calldatacopy(callframe, calldatasize(), 160)

                // callframe.rpi_ptr_call_data
                {
                    let valueOffset := add(BLOCK_FIELDS, mul(TX_TABLE_LEN, 3))
                    mstore(
                        add(callframe, 64),
                        add(endOfRows, mul(valueOffset, 32))
                    )
                }

                // callframe.id_index_value_spread
                mstore(add(callframe, 96), mul(32, TX_TABLE_LEN))
            }

            // calldata offsets
            let dataOffset := witness.offset
            let dataOffsetTail := add(dataOffset, witness.length)

            // block+extra table
            {
                let ptr, values, nItems, hash := decodeFlat(dataOffset)
                require(eq(nItems, 15), "BLOCK_ITEMS")

                // initial zero
                append(0)
                // coinbase
                append(loadValue(values, 2))
                // gas_limit
                append(loadValue(values, 9))
                // number
                append(loadValue(values, 8))
                // time
                append(loadValue(values, 11))
                // difficulty
                append(rlc_le(loadValue(values, 7)))
                // base fee
                append(0)
                // chain id
                append(chainId)
                mstore(add(table, 64), chainId)

                // history hashes
                {
                    let tail := add(ptr, 8192)
                    for {

                    } lt(ptr, tail) {
                        ptr := add(ptr, 32)
                    } {
                        append(rlc(calldataload(ptr)))
                    }
                }

                // extra fields
                // block hash
                // append(rlc(hash))
                // stateRoot
                {
                    let stateRoot := rlc(loadValue(values, 3))
                    append(stateRoot)
                    mstore(add(table, 96), stateRoot)
                }
                // parent stateRoot
                {
                    let v := rlc(parentStateRoot)
                    append(v)
                    mstore(add(table, 128), v)
                }

                dataOffset := ptr
                require(
                    or(
                        eq(dataOffset, dataOffsetTail),
                        lt(dataOffset, dataOffsetTail)
                    ),
                    "DATA"
                )
            }
            // end of block+extra table

            // rewind `callframe.tableOffset`
            mstore(mload(96), table)

            // tx table
            {
                // initial zero row
                appendTxRow(0, 0, 0)

                let txId := 0
                for {

                } lt(dataOffset, dataOffsetTail) {

                } {
                    txId := add(txId, 1)

                    let ptr, values, nItems, hash := decodeFlat(dataOffset)
                    require(eq(nItems, 9), "TX_ITEMS")
                    dataOffset := ptr
                    let txFrom := calldataload(dataOffset)
                    // from, r,s
                    dataOffset := add(dataOffset, 96)

                    {
                        let _chain_id := loadValue(values, 6)
                        require(eq(_chain_id, chainId), "TX_CHAINID")
                    }

                    {
                        let txNonce := loadValue(values, 0)
                        let CONST_TX_TAG_NONCE := 1
                        appendTxRow(txId, CONST_TX_TAG_NONCE, rlc_le(txNonce))
                    }

                    {
                        let gasLimit := loadValue(values, 2)
                        let CONST_TX_TAG_GAS := 2
                        appendTxRow(txId, CONST_TX_TAG_GAS, rlc_le(gasLimit))
                    }

                    {
                        let gasPrice := loadValue(values, 1)
                        let CONST_TX_TAG_GAS_PRICE := 3
                        appendTxRow(
                            txId,
                            CONST_TX_TAG_GAS_PRICE,
                            rlc_le(gasPrice)
                        )
                    }

                    {
                        let CONST_TX_TAG_CALLER_ADDRESS := 4
                        appendTxRow(txId, CONST_TX_TAG_CALLER_ADDRESS, txFrom)
                    }

                    {
                        let to, len := loadValueLen(values, 3)
                        let CONST_TX_TAG_CALLEE_ADDRESS := 5
                        appendTxRow(txId, CONST_TX_TAG_CALLEE_ADDRESS, to)

                        let isCreate := iszero(len)
                        let CONST_TX_TAG_IS_CREATE := 6
                        appendTxRow(txId, CONST_TX_TAG_IS_CREATE, isCreate)
                    }

                    {
                        let txValue := loadValue(values, 4)
                        let CONST_TX_TAG_VALUE := 7
                        appendTxRow(txId, CONST_TX_TAG_VALUE, rlc_le(txValue))
                    }

                    let txInputOffset, txInputLen := loadPair(values, 5)
                    {
                        // keep track of calldata bytes being written
                        {
                            let callframe := mload(96)
                            // callframe.calldataBytes
                            let offset := add(callframe, 128)
                            mstore(offset, add(mload(offset), txInputLen))
                        }

                        let CONST_TX_TAG_CALL_DATA_LENGTH := 8
                        appendTxRow(
                            txId,
                            CONST_TX_TAG_CALL_DATA_LENGTH,
                            txInputLen
                        )
                    }

                    // calldata part
                    {
                        let zeroBytes
                        for {
                            let i := 0
                        } lt(i, txInputLen) {
                            i := add(i, 1)
                        } {
                            let val := byte(
                                0,
                                calldataload(add(txInputOffset, i))
                            )
                            appendCallDataRow(val)

                            zeroBytes := add(zeroBytes, iszero(val))
                        }

                        {
                            let gasCost := add(
                                mul(zeroBytes, 4),
                                mul(sub(txInputLen, zeroBytes), 16)
                            )
                            let CONST_TX_TAG_CALL_DATA_GAS := 9
                            appendTxRow(
                                txId,
                                CONST_TX_TAG_CALL_DATA_GAS,
                                gasCost
                            )
                        }
                    }

                    {
                        let
                            SECP256K1_Q
                        := 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                        let msg_hash := mod(hash, SECP256K1_Q)
                        let CONST_TX_TAG_SIGN_HASH := 10
                        appendTxRow(
                            txId,
                            CONST_TX_TAG_SIGN_HASH,
                            rlc_le(msg_hash)
                        )
                    }
                }

                require(eq(dataOffset, dataOffsetTail), "DATA")
                // verify callframe.calldataBytes
                {
                    let callframe := mload(96)
                    let value := mload(add(callframe, 128))
                    require(
                        or(eq(value, MAX_CALLDATA), lt(value, MAX_CALLDATA)),
                        "MAX_DATA"
                    )
                }

                // MAX_TXS padding
                for {

                } lt(txId, MAX_TXS) {

                } {
                    txId := add(txId, 1)

                    // add tag field NONCE...SIG_HASH
                    for {
                        let tag := 1
                    } lt(tag, 11) {
                        tag := add(tag, 1)
                    } {
                        appendTxRow(txId, tag, 0)
                    }
                }

                require(eq(txId, MAX_TXS), "MAX_TXS")
            }

            let NUM_RAW_INPUTS := sub(mload(64), mload(32))
            // hash(raw_public_inputs)
            let rand_rpi := mod(
                keccak256(mload(32), NUM_RAW_INPUTS),
                0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            )
            mstore(add(table, 0), rand_rpi)

            let rpi_rlc := 0
            {
                let raw_head := mload(32)
                let raw_tail := add(raw_head, NUM_RAW_INPUTS)

                for {

                } gt(raw_tail, raw_head) {

                } {
                    raw_tail := sub(raw_tail, 32)
                    let raw_value := mload(raw_tail)

                    let
                        p
                    := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    rpi_rlc := mulmod(rpi_rlc, rand_rpi, p)
                    rpi_rlc := addmod(rpi_rlc, raw_value, p)
                }
            }
            mstore(add(table, 32), rpi_rlc)

            // reset dirty slot
            mstore(96, 0)
            // move free memory pointer to end of table data
            mstore(64, mload(32))
            // return table uint256[]
            table := sub(table, 32)
        }
    }

    function _readHeaderParts(
        bytes calldata blockHeader
    )
        internal
        pure
        returns (
            bytes32 parentHash,
            bytes32 blockHash,
            bytes32 stateRoot,
            uint256 blockNumber,
            uint256 blockGasUsed,
            uint256 blockTimestamp
        )
    {
        assembly {
            //@INCLUDE:utils.yul
            //@INCLUDE:rlp.yul

            // expecting 16 individual items from the block header
            let calldataPtr, memStart, nItems, hash := decodeFlat(
                blockHeader.offset
            )
            require(eq(nItems, 15), "BLOCK_ITEMS")

            // boundary check
            let end := add(blockHeader.offset, blockHeader.length)
            require(or(lt(calldataPtr, end), eq(calldataPtr, end)), "BOUNDS")

            blockHash := hash
            parentHash := loadValue(memStart, 0)
            stateRoot := loadValue(memStart, 3)
            blockNumber := loadValue(memStart, 8)
            blockGasUsed := loadValue(memStart, 10)
            blockTimestamp := loadValue(memStart, 11)
        }
    }

    /* ----------------------------- EVENTS ---------------------------------- */

    event ProofSubmitted();
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice QoreChain post-quantum precompiles.
/// @dev Interface as published in qorechain-core `contracts/interfaces/IQorePQC.sol`
///      and `docs/EVM_PRECOMPILES.md`.
///      - pqcVerify    @ 0x0A01: ML-DSA-87 verify over raw bytes (no prehash, empty context).
///      - pqcKeyStatus @ 0x0A02: the key the chain holds for an account.
///      Both are active on testnet (qorechain-diana), inactive on mainnet.
///      A high-level call to an inactive precompile reverts on empty return data (fail closed).
interface IQorePQC {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool valid);

    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

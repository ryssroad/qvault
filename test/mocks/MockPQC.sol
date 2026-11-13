// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Test double for the QoreChain PQC precompiles, etched at 0x0A01 and 0x0A02.
/// @dev Not cryptography. A signature is valid only if the holder of the (simulated) secret
///      produced it through `mockSign`, which the test calls on behalf of the key holder.
///      The attacker in the tests never gets to call `mockSign` for the owner's key —
///      exactly the position of someone holding only the classical secp256k1 key.
contract MockPQC {
    struct Key {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    mapping(address => Key) internal keys; // used at 0x0A02
    mapping(bytes32 => bool) internal issued; // used at 0x0A01

    // ---------------- 0x0A01
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool)
    {
        return issued[keccak256(abi.encode(pubkey, message, signature))];
    }

    function mockSign(bytes calldata pubkey, bytes calldata message) external returns (bytes memory sig) {
        // 4627 bytes like a real ML-DSA-87 signature, content bound to (pubkey, message)
        sig = new bytes(4627);
        bytes32 seed = keccak256(abi.encode(pubkey, message));
        assembly {
            mstore(add(sig, 32), seed)
        }
        issued[keccak256(abi.encode(pubkey, message, sig))] = true;
    }

    // ---------------- 0x0A02
    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        Key storage k = keys[account];
        return (k.registered, k.algorithmId, k.pubkey, k.possessionProven);
    }

    function setKey(address account, uint8 algorithmId, bytes calldata pubkey, bool proven) external {
        keys[account] = Key(true, algorithmId, pubkey, proven);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IQorePQC} from "./interfaces/IQorePQC.sol";

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title QVault — a vault that a leaked ECDSA key cannot drain.
/// @notice Every action that moves value or changes authority needs an ML-DSA-87 signature
///         by the key the chain itself holds for `owner` (read from the pqcKeyStatus precompile,
///         possession proven). `msg.sender` is never used for authorisation, so anyone may relay
///         a signed operation and the account's classical secp256k1 key grants nothing.
/// @dev    Signed message = keccak256(abi.encode(DOMAIN, chainid, vault, op, nonce, deadline, payload)),
///         passed to pqcVerify as its 32 raw bytes. Owner and guardian have separate nonces so a
///         guardian freeze never invalidates a pending owner signature.
contract QVault {
    IQorePQC internal constant PQC_VERIFY = IQorePQC(address(0x0A01));
    IQorePQC internal constant PQC_KEYSTATUS = IQorePQC(address(0x0A02));
    uint8 internal constant ALGO_MLDSA87 = 1;
    bytes32 public constant DOMAIN = keccak256("QVault.v1");

    enum Op {
        Withdraw, // payload: abi.encode(address token, address to, uint256 amount); token 0 = native QOR
        SetOwner, // payload: abi.encode(address newOwner)
        SetGuardian, // payload: abi.encode(address newGuardian); 0 disables the guardian
        Freeze, // payload: "" — owner or guardian
        Unfreeze // payload: "" — owner only
    }

    address public owner;
    address public guardian;
    uint256 public ownerNonce;
    uint256 public guardianNonce;
    bool public frozen;

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed token, address indexed to, uint256 amount, uint256 nonce);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event GuardianChanged(address indexed previousGuardian, address indexed newGuardian);
    event Frozen(address indexed by);
    event Unfrozen();

    error Expired();
    error IsFrozen();
    error NoPQCKey(address account);
    error WrongAlgorithm(address account, uint8 algorithmId);
    error PossessionNotProven(address account);
    error BadSignature();
    error NoGuardian();
    error TransferFailed();
    error ZeroAddress();

    constructor(address owner_, address guardian_) {
        if (owner_ == address(0)) revert ZeroAddress();
        _requireUsableKey(owner_);
        if (guardian_ != address(0)) _requireUsableKey(guardian_);
        owner = owner_;
        guardian = guardian_;
        emit OwnerChanged(address(0), owner_);
        emit GuardianChanged(address(0), guardian_);
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ------------------------------------------------------------------ owner operations

    function withdraw(address token, address payable to, uint256 amount, uint256 deadline, bytes calldata sig)
        external
    {
        if (frozen) revert IsFrozen();
        if (to == address(0)) revert ZeroAddress();
        uint256 n = _consumeOwner(Op.Withdraw, abi.encode(token, to, amount), deadline, sig);

        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            (bool ok, bytes memory ret) =
                token.call(abi.encodeCall(IERC20Minimal.transfer, (to, amount)));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool))) || token.code.length == 0) {
                revert TransferFailed();
            }
        }
        emit Withdrawn(token, to, amount, n);
    }

    function setOwner(address newOwner, uint256 deadline, bytes calldata sig) external {
        if (newOwner == address(0)) revert ZeroAddress();
        _requireUsableKey(newOwner); // never hand the vault to an account that cannot sign for it
        _consumeOwner(Op.SetOwner, abi.encode(newOwner), deadline, sig);
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function setGuardian(address newGuardian, uint256 deadline, bytes calldata sig) external {
        if (newGuardian != address(0)) _requireUsableKey(newGuardian);
        _consumeOwner(Op.SetGuardian, abi.encode(newGuardian), deadline, sig);
        emit GuardianChanged(guardian, newGuardian);
        guardian = newGuardian;
    }

    function unfreeze(uint256 deadline, bytes calldata sig) external {
        _consumeOwner(Op.Unfreeze, "", deadline, sig);
        frozen = false;
        emit Unfrozen();
    }

    /// @notice Freeze signed by the owner.
    function freeze(uint256 deadline, bytes calldata sig) external {
        _consumeOwner(Op.Freeze, "", deadline, sig);
        frozen = true;
        emit Frozen(owner);
    }

    // ------------------------------------------------------------------ guardian operation

    /// @notice Freeze signed by the guardian. The guardian can stop withdrawals, nothing else.
    function guardianFreeze(uint256 deadline, bytes calldata sig) external {
        address g = guardian;
        if (g == address(0)) revert NoGuardian();
        if (block.timestamp > deadline) revert Expired();
        uint256 n = guardianNonce;
        _verify(g, digest(Op.Freeze, n, deadline, ""), sig);
        guardianNonce = n + 1;
        frozen = true;
        emit Frozen(g);
    }

    // ------------------------------------------------------------------ views

    /// @notice The 32 bytes the signer must sign with ML-DSA-87 (deterministic or hedged).
    function digest(Op op, uint256 nonce, uint256 deadline, bytes memory payload) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), op, nonce, deadline, payload));
    }

    function withdrawDigest(address token, address to, uint256 amount, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        return digest(Op.Withdraw, ownerNonce, deadline, abi.encode(token, to, amount));
    }

    // ------------------------------------------------------------------ internals

    function _consumeOwner(Op op, bytes memory payload, uint256 deadline, bytes calldata sig)
        internal
        returns (uint256 n)
    {
        if (block.timestamp > deadline) revert Expired();
        n = ownerNonce;
        _verify(owner, digest(op, n, deadline, payload), sig);
        ownerNonce = n + 1; // effects before any external value transfer
    }

    function _verify(address who, bytes32 d, bytes calldata sig) internal view {
        bytes memory pub = _requireUsableKey(who);
        if (!PQC_VERIFY.pqcVerify(pub, sig, abi.encodePacked(d))) revert BadSignature();
    }

    /// @dev The chain's key for `who`; possession must be proven, otherwise a copied public key
    ///      would let one address pass as another (see qorechain-core EVM_PRECOMPILES.md).
    function _requireUsableKey(address who) internal view returns (bytes memory pub) {
        (bool registered, uint8 algo, bytes memory key, bool proven) = PQC_KEYSTATUS.pqcKeyStatus(who);
        if (!registered) revert NoPQCKey(who);
        if (algo != ALGO_MLDSA87) revert WrongAlgorithm(who, algo);
        if (!proven) revert PossessionNotProven(who);
        return key;
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IQorePQC} from "./interfaces/IQorePQC.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title QVaultV2 — QVault plus a timelock and a guardian veto.
/// @notice v1 answers "the classical key leaked". v2 also bounds "the owner's ML-DSA-87 key leaked":
///         - small withdrawals are instant, but only up to a per-token budget per 24h;
///         - everything else (larger withdrawals, owner / guardian / policy changes, unfreeze) is queued
///           and executes only after `delay`;
///         - the guardian, with its own ML-DSA-87 key, can freeze the vault and cancel any queued
///           operation. It can never move funds or change authority.
///         With an honest guardian a thief holding the owner's PQ key gets at most one period's budget.
///         The price is liveness: a malicious guardian can veto forever (it cannot steal). A guardian
///         that is merely gone cannot block anything: queued operations, including its own removal,
///         execute after the delay.
/// @dev    As in v1, `msg.sender` is never used for authorisation; every signed digest binds the domain,
///         chain id, vault address, operation, nonce, deadline and payload.
contract QVaultV2 {
    IQorePQC internal constant PQC_VERIFY = IQorePQC(address(0x0A01));
    IQorePQC internal constant PQC_KEYSTATUS = IQorePQC(address(0x0A02));
    uint8 internal constant ALGO_MLDSA87 = 1;
    bytes32 public constant DOMAIN = keccak256("QVault.v2");
    uint64 public constant PERIOD = 1 days;
    uint64 public constant MAX_DELAY = 30 days;
    /// @notice A queued operation that nobody executes within this time after its eta expires.
    uint64 public constant GRACE = 14 days;

    enum Op {
        Withdraw, // instant; payload abi.encode(address token, address to, uint256 amount)
        Queue, // payload abi.encode(Kind kind, bytes data)
        Freeze, // payload ""
        Cancel // payload abi.encode(uint256 id)
    }

    /// @notice What a queued operation does when executed.
    enum Kind {
        Withdraw, // data abi.encode(address token, address to, uint256 amount)
        SetOwner, // data abi.encode(address newOwner)
        SetGuardian, // data abi.encode(address newGuardian); 0 removes the guardian
        SetDelay, // data abi.encode(uint64 newDelay)
        SetLimit, // data abi.encode(address token, uint256 limitPerPeriod)
        Unfreeze // data ""
    }

    struct Pending {
        Kind kind;
        uint64 eta;
        bytes data;
    }

    struct Budget {
        uint256 limit; // instant amount allowed per PERIOD; 0 = every withdrawal is queued
        uint256 spent;
        uint64 periodStart;
    }

    address public owner;
    address public guardian;
    uint256 public ownerNonce;
    uint256 public guardianNonce;
    bool public frozen;
    uint64 public delay;
    uint256 public nextId;
    mapping(uint256 => Pending) internal _pending;
    mapping(address => Budget) public budget; // token => budget; address(0) = native QOR

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed token, address indexed to, uint256 amount, bool instant);
    event Queued(uint256 indexed id, Kind kind, bytes data, uint64 eta);
    event Executed(uint256 indexed id, Kind kind);
    event Cancelled(uint256 indexed id, address indexed by);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event GuardianChanged(address indexed previousGuardian, address indexed newGuardian);
    event DelayChanged(uint64 previousDelay, uint64 newDelay);
    event LimitChanged(address indexed token, uint256 limitPerPeriod);
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
    error OverInstantBudget(uint256 remaining);
    error UnknownOperation(uint256 id);
    error NotReady(uint64 eta);
    error Stale(uint64 expiredAt);
    error DelayTooLong();

    constructor(address owner_, address guardian_, uint64 delay_, uint256 nativeInstantLimit) {
        if (owner_ == address(0)) revert ZeroAddress();
        if (delay_ > MAX_DELAY) revert DelayTooLong();
        _requireUsableKey(owner_);
        if (guardian_ != address(0)) _requireUsableKey(guardian_);
        owner = owner_;
        guardian = guardian_;
        delay = delay_;
        budget[address(0)].limit = nativeInstantLimit;
        emit OwnerChanged(address(0), owner_);
        emit GuardianChanged(address(0), guardian_);
        emit DelayChanged(0, delay_);
        emit LimitChanged(address(0), nativeInstantLimit);
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ------------------------------------------------------------------ owner: instant

    /// @notice Instant withdrawal inside the per-period budget. Reverts above it: queue instead.
    function withdraw(address token, address to, uint256 amount, uint256 deadline, bytes calldata sig) external {
        if (frozen) revert IsFrozen();
        if (to == address(0)) revert ZeroAddress();
        _consumeOwner(Op.Withdraw, abi.encode(token, to, amount), deadline, sig);
        _spend(token, amount);
        _pay(token, to, amount);
        emit Withdrawn(token, to, amount, true);
    }

    /// @notice Owner freeze: stops instant withdrawals and the execution of queued withdrawals.
    function freeze(uint256 deadline, bytes calldata sig) external {
        _consumeOwner(Op.Freeze, "", deadline, sig);
        frozen = true;
        emit Frozen(owner);
    }

    // ------------------------------------------------------------------ owner: timelocked

    /// @notice Queue an operation; it can be executed by anyone once `delay` has passed.
    function queue(Kind kind, bytes calldata data, uint256 deadline, bytes calldata sig) external returns (uint256 id) {
        _validate(kind, data);
        _consumeOwner(Op.Queue, abi.encode(kind, data), deadline, sig);
        id = nextId++;
        uint64 eta = uint64(block.timestamp) + delay;
        _pending[id] = Pending(kind, eta, data);
        emit Queued(id, kind, data, eta);
    }

    /// @notice Execute a queued operation after its eta. No signature: it was authorised when queued.
    function execute(uint256 id) external {
        Pending memory p = _pending[id];
        if (p.eta == 0) revert UnknownOperation(id);
        if (block.timestamp < p.eta) revert NotReady(p.eta);
        if (block.timestamp > p.eta + GRACE) revert Stale(p.eta + GRACE);
        delete _pending[id];

        if (p.kind == Kind.Withdraw) {
            if (frozen) revert IsFrozen();
            (address token, address to, uint256 amount) = abi.decode(p.data, (address, address, uint256));
            _pay(token, to, amount);
            emit Withdrawn(token, to, amount, false);
        } else if (p.kind == Kind.SetOwner) {
            address newOwner = abi.decode(p.data, (address));
            _requireUsableKey(newOwner); // re-checked: the key may have changed since queueing
            emit OwnerChanged(owner, newOwner);
            owner = newOwner;
        } else if (p.kind == Kind.SetGuardian) {
            address newGuardian = abi.decode(p.data, (address));
            if (newGuardian != address(0)) _requireUsableKey(newGuardian);
            emit GuardianChanged(guardian, newGuardian);
            guardian = newGuardian;
        } else if (p.kind == Kind.SetDelay) {
            uint64 newDelay = abi.decode(p.data, (uint64));
            emit DelayChanged(delay, newDelay);
            delay = newDelay;
        } else if (p.kind == Kind.SetLimit) {
            (address token, uint256 limit) = abi.decode(p.data, (address, uint256));
            budget[token].limit = limit;
            emit LimitChanged(token, limit);
        } else {
            frozen = false;
            emit Unfrozen();
        }
        emit Executed(id, p.kind);
    }

    // ------------------------------------------------------------------ guardian: veto only

    /// @notice Guardian freeze.
    function guardianFreeze(uint256 deadline, bytes calldata sig) external {
        _consumeGuardian(Op.Freeze, "", deadline, sig);
        frozen = true;
        emit Frozen(guardian);
    }

    /// @notice Cancel a queued operation. Signed by the guardian; by the owner only when there is no
    ///         guardian (otherwise a thief holding the owner key could cancel the owner's own rescue).
    function cancel(uint256 id, uint256 deadline, bytes calldata sig) external {
        if (_pending[id].eta == 0) revert UnknownOperation(id);
        address by = guardian;
        if (by == address(0)) {
            by = owner;
            _consumeOwner(Op.Cancel, abi.encode(id), deadline, sig);
        } else {
            _consumeGuardian(Op.Cancel, abi.encode(id), deadline, sig);
        }
        delete _pending[id];
        emit Cancelled(id, by);
    }

    // ------------------------------------------------------------------ views

    /// @notice The 32 bytes a signer signs with ML-DSA-87.
    function digest(Op op, uint256 nonce, uint256 deadline, bytes memory payload) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), op, nonce, deadline, payload));
    }

    function withdrawDigest(address token, address to, uint256 amount, uint256 deadline) external view returns (bytes32) {
        return digest(Op.Withdraw, ownerNonce, deadline, abi.encode(token, to, amount));
    }

    function queueDigest(Kind kind, bytes calldata data, uint256 deadline) external view returns (bytes32) {
        return digest(Op.Queue, ownerNonce, deadline, abi.encode(kind, data));
    }

    function pending(uint256 id) external view returns (Kind kind, uint64 eta, bytes memory data) {
        Pending storage p = _pending[id];
        return (p.kind, p.eta, p.data);
    }

    /// @notice How much of `token` can still be withdrawn instantly right now.
    function instantRemaining(address token) public view returns (uint256) {
        Budget storage b = budget[token];
        if (block.timestamp >= uint256(b.periodStart) + PERIOD) return b.limit;
        return b.limit > b.spent ? b.limit - b.spent : 0;
    }

    // ------------------------------------------------------------------ internals

    function _validate(Kind kind, bytes calldata data) internal view {
        if (kind == Kind.Withdraw) {
            (, address to,) = abi.decode(data, (address, address, uint256));
            if (to == address(0)) revert ZeroAddress();
        } else if (kind == Kind.SetOwner) {
            address a = abi.decode(data, (address));
            if (a == address(0)) revert ZeroAddress();
            _requireUsableKey(a);
        } else if (kind == Kind.SetGuardian) {
            address a = abi.decode(data, (address));
            if (a != address(0)) _requireUsableKey(a);
        } else if (kind == Kind.SetDelay) {
            if (abi.decode(data, (uint64)) > MAX_DELAY) revert DelayTooLong();
        } else if (kind == Kind.SetLimit) {
            abi.decode(data, (address, uint256));
        }
    }

    function _spend(address token, uint256 amount) internal {
        Budget storage b = budget[token];
        if (block.timestamp >= uint256(b.periodStart) + PERIOD) {
            b.periodStart = uint64(block.timestamp);
            b.spent = 0;
        }
        uint256 remaining = b.limit > b.spent ? b.limit - b.spent : 0;
        if (amount > remaining) revert OverInstantBudget(remaining);
        b.spent += amount;
    }

    function _pay(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            (bool ok,) = payable(to).call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            (bool ok, bytes memory ret) = token.call(abi.encodeCall(IERC20Min.transfer, (to, amount)));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool))) || token.code.length == 0) {
                revert TransferFailed();
            }
        }
    }

    function _consumeOwner(Op op, bytes memory payload, uint256 deadline, bytes calldata sig) internal {
        if (block.timestamp > deadline) revert Expired();
        uint256 n = ownerNonce;
        _verify(owner, digest(op, n, deadline, payload), sig);
        ownerNonce = n + 1;
    }

    function _consumeGuardian(Op op, bytes memory payload, uint256 deadline, bytes calldata sig) internal {
        address g = guardian;
        if (g == address(0)) revert NoGuardian();
        if (block.timestamp > deadline) revert Expired();
        uint256 n = guardianNonce;
        _verify(g, digest(op, n, deadline, payload), sig);
        guardianNonce = n + 1;
    }

    function _verify(address who, bytes32 d, bytes calldata sig) internal view {
        bytes memory pub = _requireUsableKey(who);
        if (!PQC_VERIFY.pqcVerify(pub, sig, abi.encodePacked(d))) revert BadSignature();
    }

    function _requireUsableKey(address who) internal view returns (bytes memory pub) {
        (bool registered, uint8 algo, bytes memory key, bool proven) = PQC_KEYSTATUS.pqcKeyStatus(who);
        if (!registered) revert NoPQCKey(who);
        if (algo != ALGO_MLDSA87) revert WrongAlgorithm(who, algo);
        if (!proven) revert PossessionNotProven(who);
        return key;
    }
}

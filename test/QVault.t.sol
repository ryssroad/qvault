// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {QVault} from "../src/QVault.sol";
import {MockPQC} from "./mocks/MockPQC.sol";

contract MockToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }
}

/// Non-standard tokens for the Stage 1 audit finding on external token calls.
contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

contract NoReturnToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
    }
}

/// Threat model under test: the attacker holds the owner's classical secp256k1 key
/// (can send any EVM tx as `owner`) but not the owner's ML-DSA-87 secret.
contract QVaultTest is Test {
    address constant VERIFY = address(0x0A01);
    address constant KEYSTATUS = address(0x0A02);

    QVault vault;
    MockToken token;

    address owner = makeAddr("owner"); // drill account: its ECDSA key is public
    address guardian = makeAddr("guardian");
    address attacker = makeAddr("attacker");
    address payable dest = payable(makeAddr("dest"));

    bytes ownerPub = _pub("owner");
    bytes guardianPub = _pub("guardian");

    function setUp() public {
        MockPQC impl = new MockPQC();
        vm.etch(VERIFY, address(impl).code);
        vm.etch(KEYSTATUS, address(impl).code);
        _register(owner, ownerPub, true);
        _register(guardian, guardianPub, true);

        vault = new QVault(owner, guardian);
        token = new MockToken();
        vm.deal(address(vault), 100 ether);
        token.mint(address(vault), 1_000e18);
    }

    // ---------------------------------------------------------------- helpers

    function _pub(string memory label) internal pure returns (bytes memory p) {
        p = new bytes(2592);
        bytes32 s = keccak256(bytes(label));
        assembly {
            mstore(add(p, 32), s)
        }
    }

    function _register(address who, bytes memory pub, bool proven) internal {
        MockPQC(KEYSTATUS).setKey(who, 1, pub, proven);
    }

    function _sign(bytes memory pub, bytes32 d) internal returns (bytes memory) {
        return MockPQC(VERIFY).mockSign(pub, abi.encodePacked(d));
    }

    function _signWithdraw(address tok, address to, uint256 amount, uint256 deadline)
        internal
        returns (bytes memory)
    {
        return _sign(ownerPub, vault.withdrawDigest(tok, to, amount, deadline));
    }

    // ---------------------------------------------------------------- happy path

    function test_withdrawNative_relayedByAnyone() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.prank(attacker); // relayer identity is irrelevant: funds go where the PQ signature says
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
        assertEq(dest.balance, 1 ether);
        assertEq(vault.ownerNonce(), 1);
    }

    function test_withdrawToken() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(token), dest, 5e18, dl);
        vault.withdraw(address(token), dest, 5e18, dl, sig);
        assertEq(token.balanceOf(dest), 5e18);
    }

    function test_deposit() public {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        (bool ok,) = address(vault).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(vault).balance, 101 ether);
    }

    // ---------------------------------------------------------------- leaked ECDSA key

    function test_leakedEcdsa_cannotWithdraw() public {
        vm.prank(owner); // attacker acting with the owner's classical key
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), payable(attacker), 100 ether, block.timestamp + 1, new bytes(4627));
    }

    function test_leakedEcdsa_cannotTakeOver() public {
        _register(attacker, _pub("attacker"), true);
        vm.startPrank(owner);
        vm.expectRevert(QVault.BadSignature.selector);
        vault.setOwner(attacker, block.timestamp + 1, new bytes(4627));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.setGuardian(address(0), block.timestamp + 1, new bytes(4627));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.unfreeze(block.timestamp + 1, new bytes(4627));
        vm.stopPrank();
    }

    function test_attackerOwnPQKey_isNotOwners() public {
        // attacker signs with a valid key of his own — still not the owner's key
        bytes memory aPub = _pub("attacker");
        _register(attacker, aPub, true);
        uint256 dl = block.timestamp + 1;
        bytes memory sig = _sign(aPub, vault.withdrawDigest(address(0), attacker, 1 ether, dl));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), payable(attacker), 1 ether, dl, sig);
    }

    function test_copiedPubkeyWithoutPossession_rejected() public {
        // attacker registers the OWNER's public key on his own account, without proof of possession
        _register(attacker, ownerPub, false);
        vm.expectRevert(abi.encodeWithSelector(QVault.PossessionNotProven.selector, attacker));
        new QVault(attacker, address(0));
    }

    // ---------------------------------------------------------------- binding / replay

    function test_replay_rejected() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
    }

    function test_tamperedRecipient_rejected() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), payable(attacker), 1 ether, dl, sig);
    }

    function test_tamperedAmount_rejected() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), dest, 2 ether, dl, sig);
    }

    function test_otherVault_rejected() public {
        QVault other = new QVault(owner, guardian);
        vm.deal(address(other), 10 ether);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl); // signed for `vault`
        vm.expectRevert(QVault.BadSignature.selector);
        other.withdraw(address(0), dest, 1 ether, dl, sig);
    }

    function test_otherChain_rejected() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.chainId(9801); // signed on testnet (9800 in deployment), replayed on mainnet id
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
    }

    function test_expired_rejected() public {
        uint256 dl = block.timestamp + 10;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.warp(dl + 1);
        vm.expectRevert(QVault.Expired.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
    }

    // ---------------------------------------------------------------- guardian

    function test_guardianFreeze_blocksWithdraw_onlyOwnerUnfreezes() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory wsig = _signWithdraw(address(0), dest, 1 ether, dl);

        bytes memory gsig = _sign(guardianPub, vault.digest(QVault.Op.Freeze, 0, dl, ""));
        vault.guardianFreeze(dl, gsig);
        assertTrue(vault.frozen());

        vm.expectRevert(QVault.IsFrozen.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, wsig);

        // guardian's key cannot unfreeze
        bytes memory bad = _sign(guardianPub, vault.digest(QVault.Op.Unfreeze, 0, dl, ""));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.unfreeze(dl, bad);

        bytes memory usig = _sign(ownerPub, vault.digest(QVault.Op.Unfreeze, 0, dl, ""));
        vault.unfreeze(dl, usig);

        // the owner's pending withdrawal signature survives the guardian freeze (separate nonces)
        wsig = _sign(ownerPub, vault.digest(QVault.Op.Withdraw, 1, dl, abi.encode(address(0), dest, 1 ether)));
        vault.withdraw(address(0), dest, 1 ether, dl, wsig);
        assertEq(dest.balance, 1 ether);
    }

    function test_guardianSig_cannotWithdraw() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _sign(guardianPub, vault.withdrawDigest(address(0), dest, 1 ether, dl));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
    }

    // ---------------------------------------------------------------- authority changes

    function test_setOwner_requiresProvenKey() public {
        address fresh = makeAddr("fresh");
        _register(fresh, _pub("fresh"), false);
        vm.expectRevert(abi.encodeWithSelector(QVault.PossessionNotProven.selector, fresh));
        vault.setOwner(fresh, block.timestamp + 1, "");
    }

    function test_setOwner_rotates() public {
        address next = makeAddr("next");
        bytes memory nextPub = _pub("next");
        _register(next, nextPub, true);
        uint256 dl = block.timestamp + 1 hours;
        vault.setOwner(next, dl, _sign(ownerPub, vault.digest(QVault.Op.SetOwner, 0, dl, abi.encode(next))));
        assertEq(vault.owner(), next);

        // old owner's key is now worthless
        bytes memory old = _sign(ownerPub, vault.withdrawDigest(address(0), dest, 1 ether, dl));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), dest, 1 ether, dl, old);
    }

    // ---------------------------------------------------------------- fail closed

    function test_inactivePrecompile_failsClosed() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.etch(KEYSTATUS, ""); // as on mainnet: precompile not active, empty return data
        vm.expectRevert();
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
        assertEq(dest.balance, 0);
    }

    function testFuzz_randomSignature_neverPasses(bytes calldata sig, address to, uint96 amount) public {
        vm.assume(to != address(0));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), payable(to), amount, block.timestamp + 1, sig);
    }

    // ---------------------------------------------------------------- QCAI audit, Stage 1 (docs/AUDIT.md)

    /// Finding V1-1: the new owner (and guardian) must hold a proven ML-DSA-87 key.
    function test_audit_setGuardian_requiresProvenKey() public {
        address noKey = makeAddr("noKey");
        address unproven = makeAddr("unproven");
        _register(unproven, _pub("unproven"), false);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _sign(ownerPub, vault.digest(QVault.Op.SetGuardian, 0, dl, abi.encode(noKey)));
        vm.expectRevert(abi.encodeWithSelector(QVault.NoPQCKey.selector, noKey));
        vault.setGuardian(noKey, dl, sig);
        sig = _sign(ownerPub, vault.digest(QVault.Op.SetGuardian, 0, dl, abi.encode(unproven)));
        vm.expectRevert(abi.encodeWithSelector(QVault.PossessionNotProven.selector, unproven));
        vault.setGuardian(unproven, dl, sig);
        assertEq(vault.guardian(), guardian);
    }

    /// Finding V1-2: a front-runner can only submit exactly what the owner signed.
    function test_audit_frontRunRelay_cannotChangeOutcome() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(0), dest, 1 ether, dl);
        vm.prank(attacker); // copies the signature from the mempool and redirects it
        vm.expectRevert(QVault.BadSignature.selector);
        vault.withdraw(address(0), payable(attacker), 1 ether, dl, sig);
        vm.prank(attacker); // or relays it unchanged first
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
        vm.expectRevert(QVault.BadSignature.selector); // the original submission is now a replay
        vault.withdraw(address(0), dest, 1 ether, dl, sig);
        assertEq(dest.balance, 1 ether);
        assertEq(attacker.balance, 0);
    }

    /// Finding V1-3: no loop; a malformed token cannot fake a successful transfer.
    function test_audit_tokenReturningFalse_reverts() public {
        FalseToken bad = new FalseToken();
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(bad), dest, 1, dl);
        vm.expectRevert(QVault.TransferFailed.selector);
        vault.withdraw(address(bad), dest, 1, dl, sig);
        assertEq(vault.ownerNonce(), 0);
    }

    function test_audit_tokenWithoutCode_reverts() public {
        address notAToken = makeAddr("notAToken");
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(notAToken, dest, 1, dl);
        vm.expectRevert(QVault.TransferFailed.selector);
        vault.withdraw(notAToken, dest, 1, dl, sig);
    }

    function test_audit_tokenWithoutReturnValue_works() public {
        NoReturnToken usdtLike = new NoReturnToken();
        usdtLike.mint(address(vault), 10);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signWithdraw(address(usdtLike), dest, 10, dl);
        vault.withdraw(address(usdtLike), dest, 10, dl, sig);
        assertEq(usdtLike.balanceOf(dest), 10);
    }

    // ---------------------------------------------------------------- QCAI audit, Stage 2 (docs/AUDIT.md)

    /// Stage 2, V1: guardianFreeze is access-controlled by the guardian's signature, not by msg.sender.
    function test_audit2_guardianFreeze_needsTheGuardiansSignature() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory byOwnerKey = _sign(ownerPub, vault.digest(QVault.Op.Freeze, 0, dl, ""));
        vm.expectRevert(QVault.BadSignature.selector);
        vault.guardianFreeze(dl, byOwnerKey);
        vm.prank(guardian); // the guardian's address alone grants nothing
        vm.expectRevert(QVault.BadSignature.selector);
        vault.guardianFreeze(dl, new bytes(4627));
        assertFalse(vault.frozen());
        assertEq(vault.guardianNonce(), 0);
    }
}

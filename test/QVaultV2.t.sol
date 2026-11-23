// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {QVaultV2} from "../src/QVaultV2.sol";
import {MockPQC} from "./mocks/MockPQC.sol";

contract Token {
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

/// Threat model under test: the THIEF holds the owner's ML-DSA-87 key (can produce any owner
/// signature). The guardian is honest. The thief must not get more than one period's instant budget.
contract QVaultV2Test is Test {
    address constant VERIFY = address(0x0A01);
    address constant KEYSTATUS = address(0x0A02);
    uint64 constant DELAY = 1 hours;
    uint256 constant LIMIT = 5 ether;

    QVaultV2 vault;
    Token token;
    address owner = makeAddr("owner");
    address guardian = makeAddr("guardian");
    address thief = makeAddr("thief");
    address safe = makeAddr("safe");
    bytes ownerPub = _pub("owner");
    bytes guardianPub = _pub("guardian");

    function setUp() public {
        MockPQC impl = new MockPQC();
        vm.etch(VERIFY, address(impl).code);
        vm.etch(KEYSTATUS, address(impl).code);
        MockPQC(KEYSTATUS).setKey(owner, 1, ownerPub, true);
        MockPQC(KEYSTATUS).setKey(guardian, 1, guardianPub, true);
        vault = new QVaultV2(owner, guardian, DELAY, LIMIT);
        token = new Token();
        vm.deal(address(vault), 100 ether);
        token.mint(address(vault), 1000e18);
    }

    // ---------------------------------------------------------------- helpers

    function _pub(string memory label) internal pure returns (bytes memory p) {
        p = new bytes(2592);
        bytes32 s = keccak256(bytes(label));
        assembly {
            mstore(add(p, 32), s)
        }
    }

    function _dl() internal view returns (uint256) {
        return block.timestamp + 10 minutes;
    }

    function _sign(bytes memory pub, bytes32 d) internal returns (bytes memory) {
        return MockPQC(VERIFY).mockSign(pub, abi.encodePacked(d));
    }

    function _withdraw(address tok, address to, uint256 amount) internal {
        uint256 dl = _dl();
        vault.withdraw(tok, to, amount, dl, _sign(ownerPub, vault.withdrawDigest(tok, to, amount, dl)));
    }

    function _queue(QVaultV2.Kind kind, bytes memory data) internal returns (uint256) {
        uint256 dl = _dl();
        return vault.queue(kind, data, dl, _sign(ownerPub, vault.queueDigest(kind, data, dl)));
    }

    function _guardianCancel(uint256 id) internal {
        uint256 dl = _dl();
        bytes memory sig =
            _sign(guardianPub, vault.digest(QVaultV2.Op.Cancel, vault.guardianNonce(), dl, abi.encode(id)));
        vault.cancel(id, dl, sig);
    }

    function _guardianFreeze() internal {
        uint256 dl = _dl();
        vault.guardianFreeze(dl, _sign(guardianPub, vault.digest(QVaultV2.Op.Freeze, vault.guardianNonce(), dl, "")));
    }

    // ---------------------------------------------------------------- instant budget

    function test_instantWithinBudget() public {
        _withdraw(address(0), safe, 2 ether);
        assertEq(safe.balance, 2 ether);
        assertEq(vault.instantRemaining(address(0)), 3 ether);
    }

    function test_instantOverBudget_reverts() public {
        _withdraw(address(0), safe, 4 ether);
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 2 ether, dl));
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.OverInstantBudget.selector, 1 ether));
        vault.withdraw(address(0), safe, 2 ether, dl, sig);
    }

    function test_budgetResetsAfterPeriod() public {
        _withdraw(address(0), safe, 5 ether);
        assertEq(vault.instantRemaining(address(0)), 0);
        vm.warp(block.timestamp + 1 days);
        assertEq(vault.instantRemaining(address(0)), 5 ether);
        _withdraw(address(0), safe, 5 ether);
        assertEq(safe.balance, 10 ether);
    }

    function test_tokenWithoutLimit_isAlwaysQueued() public {
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(token), safe, 1, dl));
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.OverInstantBudget.selector, 0));
        vault.withdraw(address(token), safe, 1, dl, sig);

        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(token), safe, 7e18));
        vm.warp(block.timestamp + DELAY);
        vault.execute(id);
        assertEq(token.balanceOf(safe), 7e18);
    }

    // ---------------------------------------------------------------- timelock

    function test_queuedWithdraw_notBeforeEta_thenAnyoneExecutes() public {
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 50 ether));
        (, uint64 eta,) = vault.pending(id);
        assertEq(eta, block.timestamp + DELAY);

        vm.expectRevert(abi.encodeWithSelector(QVaultV2.NotReady.selector, eta));
        vault.execute(id);

        vm.warp(eta);
        vm.prank(thief); // executor identity is irrelevant: funds go where the owner signed
        vault.execute(id);
        assertEq(safe.balance, 50 ether);

        vm.expectRevert(abi.encodeWithSelector(QVaultV2.UnknownOperation.selector, id));
        vault.execute(id); // no double execution
    }

    function test_staleOperation_cannotExecute() public {
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 50 ether));
        (, uint64 eta,) = vault.pending(id);
        vm.warp(uint256(eta) + 14 days + 1);
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.Stale.selector, eta + 14 days));
        vault.execute(id);
    }

    function test_instantSignature_cannotBeUsedToQueue_andViceVersa() public {
        uint256 dl = _dl();
        bytes memory data = abi.encode(address(0), safe, 1 ether);
        bytes memory instantSig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1 ether, dl));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.queue(QVaultV2.Kind.Withdraw, data, dl, instantSig);

        bytes memory queueSig = _sign(ownerPub, vault.queueDigest(QVaultV2.Kind.Withdraw, data, dl));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.withdraw(address(0), safe, 1 ether, dl, queueSig);
    }

    function test_setDelay_and_setLimit_viaTimelock() public {
        uint256 a = _queue(QVaultV2.Kind.SetDelay, abi.encode(uint64(2 hours)));
        uint256 b = _queue(QVaultV2.Kind.SetLimit, abi.encode(address(token), uint256(10e18)));
        vm.warp(block.timestamp + DELAY);
        vault.execute(a);
        vault.execute(b);
        assertEq(vault.delay(), 2 hours);
        _withdraw(address(token), safe, 10e18);
        assertEq(token.balanceOf(safe), 10e18);
    }

    function test_delayAboveMax_rejected() public {
        uint256 dl = _dl();
        bytes memory data = abi.encode(uint64(31 days));
        bytes memory sig = _sign(ownerPub, vault.queueDigest(QVaultV2.Kind.SetDelay, data, dl));
        vm.expectRevert(QVaultV2.DelayTooLong.selector);
        vault.queue(QVaultV2.Kind.SetDelay, data, dl, sig);
    }

    // ---------------------------------------------------------------- leaked OWNER PQ key

    function test_thiefWithOwnerKey_bigWithdraw_cancelledByGuardian() public {
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), thief, 95 ether)); // thief signs as owner
        _guardianCancel(id);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.UnknownOperation.selector, id));
        vault.execute(id);
        assertEq(thief.balance, 0);
    }

    function test_thiefWithOwnerKey_cannotRemoveGuardianOrRaiseLimitInstantly() public {
        uint256 a = _queue(QVaultV2.Kind.SetGuardian, abi.encode(address(0)));
        uint256 b = _queue(QVaultV2.Kind.SetLimit, abi.encode(address(0), type(uint256).max));
        uint256 c = _queue(QVaultV2.Kind.SetDelay, abi.encode(uint64(0)));
        assertEq(vault.guardian(), guardian); // nothing took effect
        assertEq(vault.delay(), DELAY);
        _guardianCancel(a);
        _guardianCancel(b);
        _guardianCancel(c);
        vm.warp(block.timestamp + DELAY);
        assertEq(vault.guardian(), guardian);
        assertEq(vault.instantRemaining(address(0)), LIMIT);
    }

    function test_thiefWithOwnerKey_cannotCancelOwnersRescue() public {
        // honest owner queues a rescue to a safe address; the thief (same key) tries to cancel it
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 100 ether));
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.digest(QVaultV2.Op.Cancel, vault.ownerNonce(), dl, abi.encode(id)));
        vm.expectRevert(QVaultV2.BadSignature.selector); // with a guardian set, only the guardian cancels
        vault.cancel(id, dl, sig);

        vm.warp(block.timestamp + DELAY);
        vault.execute(id);
        assertEq(safe.balance, 100 ether);
    }

    function test_thiefWithOwnerKey_cannotUnfreezeInstantly() public {
        _guardianFreeze();
        uint256 id = _queue(QVaultV2.Kind.Unfreeze, "");
        assertTrue(vault.frozen());
        _guardianCancel(id);
        vm.warp(block.timestamp + DELAY);
        assertTrue(vault.frozen());

        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), thief, 1 ether, dl));
        vm.expectRevert(QVaultV2.IsFrozen.selector);
        vault.withdraw(address(0), thief, 1 ether, dl, sig);
    }

    function test_maxLossWithHonestGuardian_isOnePeriodBudget() public {
        _withdraw(address(0), thief, 5 ether); // thief takes the whole instant budget
        _guardianFreeze(); // guardian reacts
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), thief, 95 ether));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(QVaultV2.IsFrozen.selector);
        vault.execute(id);
        _guardianCancel(id);
        assertEq(thief.balance, LIMIT);
        assertEq(address(vault).balance, 95 ether);
    }

    // ---------------------------------------------------------------- guardian limits / liveness

    function test_guardianKey_cannotMoveFundsOrChangeAuthority() public {
        uint256 dl = _dl();
        bytes memory data = abi.encode(address(0), thief, 1 ether);
        bytes memory s1 = _sign(guardianPub, vault.withdrawDigest(address(0), thief, 1 ether, dl));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.withdraw(address(0), thief, 1 ether, dl, s1);
        bytes memory s2 = _sign(guardianPub, vault.queueDigest(QVaultV2.Kind.Withdraw, data, dl));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.queue(QVaultV2.Kind.Withdraw, data, dl, s2);
    }

    function test_deadGuardian_cannotBlock_unfreezeAndRemoval() public {
        _guardianFreeze(); // guardian freezes, then disappears
        uint256 a = _queue(QVaultV2.Kind.Unfreeze, "");
        uint256 b = _queue(QVaultV2.Kind.SetGuardian, abi.encode(address(0)));
        vm.warp(block.timestamp + DELAY);
        vault.execute(a);
        vault.execute(b);
        assertFalse(vault.frozen());
        assertEq(vault.guardian(), address(0));

        // without a guardian the owner cancels
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 1 ether));
        uint256 dl = _dl();
        vault.cancel(id, dl, _sign(ownerPub, vault.digest(QVaultV2.Op.Cancel, vault.ownerNonce(), dl, abi.encode(id))));
        (, uint64 eta,) = vault.pending(id);
        assertEq(eta, 0);
    }

    function test_setOwner_recheckedAtExecution() public {
        address next = makeAddr("next");
        MockPQC(KEYSTATUS).setKey(next, 1, _pub("next"), true);
        uint256 id = _queue(QVaultV2.Kind.SetOwner, abi.encode(next));
        MockPQC(KEYSTATUS).setKey(next, 1, _pub("next"), false); // key re-registered without proof meanwhile
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.PossessionNotProven.selector, next));
        vault.execute(id);
    }

    // ---------------------------------------------------------------- v1 properties still hold

    function test_leakedEcdsa_stillNothing() public {
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 1 ether));
        uint256 dl = _dl();
        vm.startPrank(owner); // acting with the owner's classical key only
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.withdraw(address(0), thief, 1 ether, dl, new bytes(4627));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.queue(QVaultV2.Kind.SetOwner, abi.encode(owner), dl, new bytes(4627));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.cancel(id, dl, new bytes(4627));
        vm.stopPrank();
    }

    function test_replayAndExpiry() public {
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1 ether, dl));
        vault.withdraw(address(0), safe, 1 ether, dl, sig);
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.withdraw(address(0), safe, 1 ether, dl, sig);

        bytes memory sig2 = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1 ether, dl));
        vm.warp(dl + 1);
        vm.expectRevert(QVaultV2.Expired.selector);
        vault.withdraw(address(0), safe, 1 ether, dl, sig2);
    }

    function test_inactivePrecompile_failsClosed() public {
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1 ether, dl));
        vm.etch(KEYSTATUS, "");
        vm.expectRevert();
        vault.withdraw(address(0), safe, 1 ether, dl, sig);
    }

    function testFuzz_instantNeverExceedsBudgetPerPeriod(uint96[6] memory amounts) public {
        uint256 taken;
        for (uint256 i; i < amounts.length; i++) {
            uint256 a = uint256(amounts[i]) % 4 ether;
            uint256 dl = _dl();
            bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), thief, a, dl));
            try vault.withdraw(address(0), thief, a, dl, sig) {
                taken += a;
            } catch {}
        }
        assertLe(taken, LIMIT);
        assertEq(thief.balance, taken);
    }

    // ---------------------------------------------------------------- QCAI audit, Stage 1 (docs/AUDIT.md)

    /// Finding V2-1: cancel is access-controlled by signature, not by msg.sender.
    function test_audit_cancel_needsTheGuardiansSignatureForThatId() public {
        uint256 a = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 10 ether));
        uint256 b = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 20 ether));
        uint256 dl = _dl();
        vm.prank(guardian); // being the guardian's address grants nothing
        vm.expectRevert(QVaultV2.BadSignature.selector);
        vault.cancel(a, dl, new bytes(4627));
        bytes memory forB = _sign(guardianPub, vault.digest(QVaultV2.Op.Cancel, vault.guardianNonce(), dl, abi.encode(b)));
        vm.expectRevert(QVaultV2.BadSignature.selector); // a signature for one id does not cancel another
        vault.cancel(a, dl, forB);
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.UnknownOperation.selector, 99));
        vault.cancel(99, dl, forB);
        (, uint64 eta,) = vault.pending(a);
        assertGt(eta, 0);
    }

    function test_audit_cancel_withoutGuardian_onlyTheOwnerSigns() public {
        QVaultV2 solo = new QVaultV2(owner, address(0), DELAY, LIMIT);
        uint256 dl = _dl();
        bytes memory data = abi.encode(address(0), safe, 1 ether);
        uint256 id = solo.queue(QVaultV2.Kind.Withdraw, data, dl, _sign(ownerPub, solo.queueDigest(QVaultV2.Kind.Withdraw, data, dl)));
        bytes memory byGuardianKey = _sign(guardianPub, solo.digest(QVaultV2.Op.Cancel, solo.ownerNonce(), dl, abi.encode(id)));
        vm.expectRevert(QVaultV2.BadSignature.selector);
        solo.cancel(id, dl, byGuardianKey);
        solo.cancel(id, dl, _sign(ownerPub, solo.digest(QVaultV2.Op.Cancel, solo.ownerNonce(), dl, abi.encode(id))));
        (, uint64 eta,) = solo.pending(id);
        assertEq(eta, 0);
    }

    /// Finding V2-2: budget arithmetic at its edges (checked arithmetic, no underflow).
    function test_audit_budget_exactLimit_thenOneWeiReverts() public {
        _withdraw(address(0), safe, LIMIT);
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1, dl));
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.OverInstantBudget.selector, 0));
        vault.withdraw(address(0), safe, 1, dl, sig);
    }

    function test_audit_limitLoweredBelowSpent_leavesZero() public {
        _withdraw(address(0), safe, 4 ether);
        uint256 id = _queue(QVaultV2.Kind.SetLimit, abi.encode(address(0), uint256(1 ether)));
        vm.warp(block.timestamp + DELAY);
        vault.execute(id);
        assertEq(vault.instantRemaining(address(0)), 0); // spent 4 > limit 1: no underflow
        uint256 dl = _dl();
        bytes memory sig = _sign(ownerPub, vault.withdrawDigest(address(0), safe, 1, dl));
        vm.expectRevert(abi.encodeWithSelector(QVaultV2.OverInstantBudget.selector, 0));
        vault.withdraw(address(0), safe, 1, dl, sig);
    }

    function test_audit_maxLimit_noOverflow() public {
        uint256 id = _queue(QVaultV2.Kind.SetLimit, abi.encode(address(0), type(uint256).max));
        vm.warp(block.timestamp + DELAY);
        vault.execute(id);
        _withdraw(address(0), safe, 60 ether);
        _withdraw(address(0), safe, 40 ether);
        assertEq(vault.instantRemaining(address(0)), type(uint256).max - 100 ether);
    }

    /// Finding V2-3: pending operations are a mapping, never iterated; stale ones are inert.
    function test_audit_manyPending_doNotAffectOtherOperations() public {
        for (uint256 i; i < 50; i++) {
            _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 1 wei));
        }
        uint256 id = _queue(QVaultV2.Kind.Withdraw, abi.encode(address(0), safe, 1 ether));
        vm.warp(block.timestamp + DELAY);
        uint256 g = gasleft();
        vault.execute(id);
        assertLt(g - gasleft(), 100_000); // cost of one execute does not grow with the queue
        assertEq(safe.balance, 1 ether);
    }
}

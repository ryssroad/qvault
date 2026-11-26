# QCAI audit

Two-stage audit with the QoreChain AI Smart Contract Auditor (dashboard.qorechain.io/audit), setting **Ethereum (EVM/Solidity)** for both stages.

| Stage | Date | QVault | QVaultV2 |
|---|---|---|---|
| 1 | 24 Nov 2026 (04:01 / 04:04 Almaty) | [report](audit/2026-11-24-stage1-QVault.pdf): 92/100, 4 findings | [report](audit/2026-11-24-stage1-QVaultV2.pdf): 85/100, 4 findings |
| 2 | 26 Nov 2026 (19:54 / 19:55 Almaty) | [report](audit/2026-11-26-stage2-QVault.pdf): 92/100, 4 findings | [report](audit/2026-11-26-stage2-QVaultV2.pdf): 85/100, 5 findings |

**What was audited.** Both stages audited the same source: no Stage 1 finding needed a contract change, so the contracts did not change between the stages. `src/QVault.sol` and `src/QVaultV2.sol`, each with `src/interfaces/IQorePQC.sol` pasted in place of its `import`, because the auditor takes one file. The exact uploads are [`audit/QVault.flat.sol`](audit/QVault.flat.sol) and [`audit/QVaultV2.flat.sol`](audit/QVaultV2.flat.sol). The line numbers in the reports do not match these files, so the findings below are matched by their description.

**Quantum readiness: "not scored".** The auditor produces this rating only for its CosmWasm setting. The PQC design is described [below](#pqc-design).

## Stage 1 findings

No contract change was needed. Each finding is answered with a regression test that pins the behaviour, so a future change that breaks it fails `forge test`. All tests are in `test/QVault.t.sol` and `test/QVaultV2.t.sol`, prefixed `test_audit_`.

### QVault

| # | Finding | Severity | Resolution |
|---|---|---|---|
| V1-1 | Privilege escalation via owner change: "ensure the new owner has a valid PQC key" | High | **False positive.** `setOwner` already calls `_requireUsableKey(newOwner)` before the signature is consumed: the new owner must have a registered ML-DSA-87 key with proven possession, and the change needs the current owner's ML-DSA-87 signature. `setGuardian` does the same for a non-zero guardian. Tests: existing `test_setOwner_requiresProvenKey`, `test_leakedEcdsa_cannotTakeOver`; new `test_audit_setGuardian_requiresProvenKey`. |
| V1-2 | Front-running in `withdraw` | Medium | **False positive by design.** Authorisation never uses `msg.sender`; anyone may relay a signed operation. The signature binds domain, chain id, vault, operation, nonce, deadline, token, recipient and amount, so a front-runner can only submit exactly what the owner signed: same recipient, same amount. A changed recipient fails the signature; the nonce makes a second submission a replay. Tests: existing `test_withdrawNative_relayedByAnyone`, `test_tamperedRecipient_rejected`, `test_replay_rejected`; new `test_audit_frontRunRelay_cannotChangeOutcome`. |
| V1-3 | Unbounded loop in external calls; "check the token is well-formed" | Low | **False positive** for the loop: the contract has no loop. The token call is already defensive: it reverts if the call fails, if the token returns `false`, or if the address has no code; tokens that return nothing (USDT-style) are accepted. Tests (new): `test_audit_tokenReturningFalse_reverts`, `test_audit_tokenWithoutCode_reverts`, `test_audit_tokenWithoutReturnValue_works`. |
| V1-4 | Missing ERC-20 implementation | Info | **Not applicable.** QVault is a vault that holds tokens, not a token. |

### QVaultV2

| # | Finding | Severity | Resolution |
|---|---|---|---|
| V2-1 | Missing access control on `cancel` | High | **False positive.** `cancel` requires the guardian's ML-DSA-87 signature over this operation id with the guardian's nonce, or, only when no guardian is set, the owner's. Being the guardian's address grants nothing. The owner cannot cancel while a guardian exists, on purpose: a thief holding the owner's PQ key must not be able to cancel the owner's queued rescue. Tests: existing `test_thiefWithOwnerKey_cannotCancelOwnersRescue`; new `test_audit_cancel_needsTheGuardiansSignatureForThatId`, `test_audit_cancel_withoutGuardian_onlyTheOwnerSigns`. |
| V2-2 | Potential overflow in budget calculation | Medium | **False positive.** Solidity 0.8 checked arithmetic. `spent` grows only after `amount <= limit - spent` is checked, and the remaining budget is computed as `limit > spent ? limit - spent : 0`, so lowering the limit below what was already spent cannot underflow. Tests: existing `testFuzz_instantNeverExceedsBudgetPerPeriod`, `test_budgetResetsAfterPeriod`; new `test_audit_budget_exactLimit_thenOneWeiReverts`, `test_audit_limitLoweredBelowSpent_leavesZero`, `test_audit_maxLimit_noOverflow`. |
| V2-3 | Unbounded loop in pending operations | Low | **False positive** for the loop: pending operations are a mapping by id and are never iterated, so their number does not change the cost of any call. Each one needs the owner's signature and a transaction fee to create. An operation not executed within `GRACE` (14 days) after its eta can never execute. Tests: existing `test_staleOperation_cannotExecute`; new `test_audit_manyPending_doNotAffectOtherOperations`. |
| V2-4 | Guardian veto; "consider multi-signature for the guardian" | Info | **Acknowledged, by design.** The guardian can only freeze and cancel; it can never move funds or change authority (`test_guardianKey_cannotMoveFundsOrChangeAuthority`), and a guardian that disappears blocks nothing (`test_deadGuardian_cannotBlock_unfreezeAndRemoval`). Its key is a separate ML-DSA-87 key held by the guardian agent. A post-quantum multisig guardian is future work. |

## Stage 2 findings

Stage 2 ran on the same source in the same setting, after every Stage 1 finding had been worked through. The auditor is a language model and words its findings differently on each run, so most Stage 2 items restate Stage 1 ones; three are new and are answered below. Two new regression tests, prefixed `test_audit2_`, pin them.

| Contract | Finding | Severity | Resolution |
|---|---|---|---|
| QVault | Missing access control on `guardianFreeze`: "require msg.sender == guardian" | High | **False positive.** `guardianFreeze` verifies the guardian's ML-DSA-87 signature with the guardian's nonce; a `msg.sender` check would add nothing, since the threat model assumes classical keys leak. Test (new): `test_audit2_guardianFreeze_needsTheGuardiansSignature`; existing `test_guardianFreeze_blocksWithdraw_onlyOwnerUnfreezes`. |
| QVault | Potential overflow in nonce increment | Medium | **False positive.** Solidity 0.8 checked arithmetic; a `uint256` nonce incremented once per signed operation cannot reach 2^256. |
| QVault | Unbounded loop in external calls | Low | Same as V1-3. |
| QVault | Signature replay protection | Info | Positive note; covered by `test_replay_rejected`. |
| QVaultV2 | Missing access control: "prevent the owner from cancelling when a guardian exists" | High | **Already the behaviour.** The owner's signature is accepted only when no guardian is set. Same as V2-1; `test_thiefWithOwnerKey_cannotCancelOwnersRescue`. |
| QVaultV2 | Potential overflow in budget calculation | Medium | Same as V2-2. |
| QVaultV2 | Front-running in `queue` | Medium | **False positive by design**, as V1-2: the signature binds the kind and data of the operation, the nonce and the deadline, so a front-runner can only queue exactly what the owner signed. Test (new): `test_audit2_queueFrontRun_cannotChangeTheOperation`. |
| QVaultV2 | Unbounded storage mapping | Low | Same as V2-3. |
| QVaultV2 | Missing ERC-20 implementation | Info | Same as V1-4: a vault, not a token. |

## PQC design

Both contracts use the two QoreChain PQC precompiles, active on Diana testnet:

| Call | Where | What it protects |
|---|---|---|
| `pqcKeyStatus` (0x0A02) | `_requireUsableKey`: in the constructor, before every signature check, and when a new owner or guardian is set (v2 also re-checks the new owner when the queued change executes) | Uses the key the chain holds for the account, never a key passed in by the caller. Requires ML-DSA-87 (algorithm 1) with proven possession, so a copied public key cannot make one address pass as another. |
| `pqcVerify` (0x0A01) | `_verify`, behind every operation: withdraw, owner and guardian changes, freeze, unfreeze, queue, cancel | Every move of value or authority needs an ML-DSA-87 signature over `keccak256(DOMAIN, chainid, vault, op, nonce, deadline, payload)`. The account's classical secp256k1 key grants nothing. |

An inactive precompile makes both calls revert, so the vault fails closed. Tests: `test_inactivePrecompile_failsClosed` (both contracts), `test_copiedPubkeyWithoutPossession_rejected`, `test_attackerOwnPQKey_isNotOwners`, `test_leakedEcdsa_cannotWithdraw`, `test_leakedEcdsa_stillNothing`, `testFuzz_randomSignature_neverPasses`. On Diana, the Q-Day Drill (README) exercised this with the account's ECDSA key handed to the organizers.

Run: `forge test` (53 tests).

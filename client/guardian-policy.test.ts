import { test } from "node:test";
import assert from "node:assert/strict";
import { AbiCoder } from "ethers";
import { approvalHash, decide, type Policy } from "./guardian-policy.js";

const c = AbiCoder.defaultAbiCoder();
const SAFE = "0x478E3441ec3f2Aad43bDec30F46756F8cD544f21";
const THIEF = "0x000000000000000000000000000000000000dEaD";
const ZERO = "0x0000000000000000000000000000000000000000";
const wd = (to: string) => c.encode(["address", "address", "uint256"], [ZERO, to, 10n ** 18n]);
const policy: Policy = { allowedRecipients: [SAFE.toLowerCase()], approved: [] };

test("queued withdrawal to an allowed recipient passes (case-insensitive)", () => {
  assert.equal(decide({ type: "queued", id: 0n, kind: 0, data: wd(SAFE) }, policy).type, "none");
});

test("queued withdrawal to an unknown recipient is cancelled", () => {
  const a = decide({ type: "queued", id: 3n, kind: 0, data: wd(THIEF) }, policy);
  assert.deepEqual([a.type, a.type === "cancel" && a.id], ["cancel", 3n]);
});

test("authority and policy changes are cancelled unless approved", () => {
  const data = c.encode(["address"], [ZERO]); // SetGuardian(0): what a thief would queue first
  assert.equal(decide({ type: "queued", id: 1n, kind: 2, data }, policy).type, "cancel");
  assert.equal(decide({ type: "queued", id: 1n, kind: 5, data: "0x" }, policy).type, "cancel");
  const approved: Policy = { ...policy, approved: [approvalHash(2, data).toUpperCase().replace("0X", "0x")] };
  assert.equal(decide({ type: "queued", id: 1n, kind: 2, data }, approved).type, "none");
});

test("an approval covers that exact payload only", () => {
  const approved: Policy = { ...policy, approved: [approvalHash(0, wd(THIEF))] };
  const other = c.encode(["address", "address", "uint256"], [ZERO, THIEF, 2n * 10n ** 18n]);
  assert.equal(decide({ type: "queued", id: 0n, kind: 0, data: wd(THIEF) }, approved).type, "none");
  assert.equal(decide({ type: "queued", id: 1n, kind: 0, data: other }, approved).type, "cancel");
});

test("undecodable withdrawal payload is cancelled", () => {
  assert.equal(decide({ type: "queued", id: 0n, kind: 0, data: "0x1234" }, policy).type, "cancel");
});

test("instant withdrawal: allowed recipient passes, unknown freezes", () => {
  assert.equal(decide({ type: "instantWithdrawal", token: ZERO, to: SAFE, amount: 1n }, policy).type, "none");
  assert.equal(decide({ type: "instantWithdrawal", token: ZERO, to: THIEF, amount: 1n }, policy).type, "freeze");
});

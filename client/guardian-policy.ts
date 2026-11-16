// Pure decision logic of the guardian agent: what to do about what the vault shows.
// No I/O here, so it is unit-tested (guardian-policy.test.ts).
//
// The guardian's stance is deny-by-default: the owner's ML-DSA-87 key may be in a thief's hands, so
// an owner signature alone proves nothing. Only what the owner approved OUT OF BAND (in the guardian's
// local policy file, which the thief cannot write) is let through.

import { AbiCoder, getAddress, keccak256 } from "ethers";

export const KIND = ["Withdraw", "SetOwner", "SetGuardian", "SetDelay", "SetLimit", "Unfreeze"] as const;
export type KindName = (typeof KIND)[number];

export interface Policy {
  /** Recipients a withdrawal (instant or queued) may go to without further approval. */
  allowedRecipients: string[];
  /** approvalHash(kind, data) of queued operations the owner approved out of band. */
  approved: string[];
}

export type Observation =
  | { type: "queued"; id: bigint; kind: number; data: string }
  | { type: "instantWithdrawal"; token: string; to: string; amount: bigint };

export type Action =
  | { type: "none"; reason: string }
  | { type: "cancel"; id: bigint; reason: string }
  | { type: "freeze"; reason: string };

const coder = AbiCoder.defaultAbiCoder();

/** What the owner puts into `approved` to let one exact queued operation through. */
export function approvalHash(kind: number, data: string): string {
  return keccak256(coder.encode(["uint8", "bytes"], [kind, data]));
}

function allowed(policy: Policy, addr: string): boolean {
  const a = getAddress(addr);
  return policy.allowedRecipients.some((r) => getAddress(r) === a);
}

export function decide(o: Observation, policy: Policy): Action {
  if (o.type === "instantWithdrawal") {
    return allowed(policy, o.to)
      ? { type: "none", reason: `instant withdrawal to allowed recipient ${o.to}` }
      : { type: "freeze", reason: `instant withdrawal of ${o.amount} to unknown recipient ${o.to}` };
  }
  const name = KIND[o.kind] ?? `kind ${o.kind}`;
  if (policy.approved.map((h) => h.toLowerCase()).includes(approvalHash(o.kind, o.data).toLowerCase())) {
    return { type: "none", reason: `#${o.id} ${name}: approved out of band` };
  }
  if (o.kind === 0) {
    let to: string;
    try {
      to = coder.decode(["address", "address", "uint256"], o.data)[1] as string;
    } catch {
      return { type: "cancel", id: o.id, reason: `#${o.id} Withdraw: undecodable payload` };
    }
    return allowed(policy, to)
      ? { type: "none", reason: `#${o.id} Withdraw to allowed recipient ${to}` }
      : { type: "cancel", id: o.id, reason: `#${o.id} Withdraw to unknown recipient ${to}` };
  }
  return { type: "cancel", id: o.id, reason: `#${o.id} ${name}: not approved` };
}

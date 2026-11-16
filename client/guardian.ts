// guardian.ts — the guardian agent for QVaultV2.
//
//   npm run guardian -- <vault> [fromBlock]          DRY_RUN=1 to log decisions without acting
//
// Holds its OWN account and ML-DSA-87 key (secrets/guardian.mnemonic, or GUARDIAN_MNEMONIC_FILE);
// it can freeze the vault and cancel queued operations, and nothing else. Every POLL_MS it:
//   1. reads every queued operation and decides (guardian-policy.ts): unknown → cancel;
//   2. reads new instant withdrawals: unknown recipient → freeze.
// The policy file (guardian-policy.json next to this script, or GUARDIAN_POLICY) is re-read each
// round, so the owner approves an operation by editing it BEFORE queueing:
//   { "allowedRecipients": ["0x…"], "approved": ["<npm run v2 -- approval …>"] }
// A missing policy file means: nothing is allowed.
//
// Set up once:  MNEMONIC_FILE=../secrets/guardian.mnemonic npm run drill new   (fund it)  … drill register
// The agent opens its own EVM window, scoped to the vault, when it has to act.

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mldsa } from "@qorechain/pqc";
import { AbiCoder, Contract, Interface, JsonRpcProvider, Wallet, getBytes, hexlify, isAddress } from "ethers";
import { NET, TX, accountFrom, ensureVaultWindow } from "./lib.js";
import { decide, type Action, type Observation, type Policy } from "./guardian-policy.js";
import { OP, V2_ABI } from "./v2.js";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const MNEMONIC = process.env.GUARDIAN_MNEMONIC_FILE ?? here("../secrets/guardian.mnemonic");
const POLICY = process.env.GUARDIAN_POLICY ?? here("./guardian-policy.json");
const LOG_DIR = here("../guardian-log/");
const POLL_MS = Number(process.env.POLL_MS ?? "3000");
const DRY = process.env.DRY_RUN === "1";
const iface = new Interface(V2_ABI);
const coder = AbiCoder.defaultAbiCoder();

mkdirSync(LOG_DIR, { recursive: true });
function log(kind: string, line: string, data: Record<string, unknown> = {}): void {
  const t = new Date().toISOString();
  appendFileSync(`${LOG_DIR}${t.slice(0, 10)}.jsonl`, JSON.stringify({ t, kind, line, ...data }, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) + "\n");
  console.log(`${t.slice(11, 19)} ${kind.padEnd(7)} ${line}`);
}

function loadPolicy(): Policy {
  if (!existsSync(POLICY)) return { allowedRecipients: [], approved: [] };
  const p = JSON.parse(readFileSync(POLICY, "utf8")) as Partial<Policy>;
  return { allowedRecipients: p.allowedRecipients ?? [], approved: p.approved ?? [] };
}

async function main() {
  const vaultAddr = process.argv[2];
  if (!vaultAddr || !isAddress(vaultAddr)) throw new Error("usage: npm run guardian -- <vault> [fromBlock]");
  const acc = await accountFrom(MNEMONIC);
  const rpc = new JsonRpcProvider(NET.evm);
  const wallet = new Wallet(acc.privateKey, rpc);
  const vault = new Contract(vaultAddr, V2_ABI, wallet);
  const sign = (d: string) => hexlify(mldsa.sign(acc.pqc.secretKey, getBytes(d)));

  const onChain: string = await vault.guardian();
  if (onChain.toLowerCase() !== acc.evm.toLowerCase()) {
    log("warn", `vault guardian is ${onChain}, this agent is ${acc.evm}: it can observe but its signatures will be refused`);
  }

  async function ensureWindow(): Promise<void> {
    const opened = await ensureVaultWindow(acc, vaultAddr!);
    if (opened) log("window", `opening vault-only window: ${opened}`);
  }

  async function act(a: Action): Promise<void> {
    if (a.type === "none") return;
    if (DRY) return log("dry-run", `would ${a.type}: ${a.reason}`);
    await ensureWindow();
    const dl = BigInt(Math.floor(Date.now() / 1000) + 600);
    const nonce: bigint = await vault.guardianNonce();
    const tx = a.type === "freeze"
      ? await vault.guardianFreeze(dl, sign(await vault.digest(OP.Freeze, nonce, dl, "0x")), TX)
      : await vault.cancel(a.id, dl, sign(await vault.digest(OP.Cancel, nonce, dl, coder.encode(["uint256"], [a.id]))), TX);
    const rc = await tx.wait();
    log(a.type.toUpperCase(), `${a.reason} → ${tx.hash} status ${rc?.status}`, { hash: tx.hash, status: rc?.status });
  }

  let next = process.argv[3] ? BigInt(process.argv[3]) : BigInt(await rpc.send("eth_blockNumber", []));
  const settled = new Set<number>(); // executed or cancelled: final
  const passed = new Set<number>(); // reviewed and let through under the policy at that time
  log("start", `vault ${vaultAddr} guardian ${acc.evm} from block ${next}${DRY ? " (DRY RUN)" : ""}`);

  for (;;) {
    try {
      const policy = loadPolicy();

      // 1. queued operations: state, not events, so nothing queued before start-up is missed
      const n = Number(await vault.nextId());
      for (let id = 0; id < n; id++) {
        if (settled.has(id) || passed.has(id)) continue;
        const [kind, eta, data] = (await vault.pending(id)) as [bigint, bigint, string];
        if (eta === 0n) {
          settled.add(id);
          continue;
        }
        const a = decide({ type: "queued", id: BigInt(id), kind: Number(kind), data }, policy);
        if (a.type === "none") {
          passed.add(id);
          log("pass", a.reason);
        } else {
          await act(a);
          if (!DRY) settled.add(id);
          else passed.add(id);
        }
      }

      // 2. instant withdrawals since the last round
      const head = BigInt(await rpc.send("eth_blockNumber", []));
      if (head >= next) {
        const logs = (await rpc.send("eth_getLogs", [
          { address: vaultAddr, fromBlock: "0x" + next.toString(16), toBlock: "0x" + head.toString(16), topics: [iface.getEvent("Withdrawn")!.topicHash] },
        ])) as { topics: string[]; data: string; transactionHash: string }[];
        for (const l of logs) {
          const ev = iface.parseLog({ topics: l.topics, data: l.data })!;
          if (!ev.args.instant) continue; // queued ones were reviewed above
          const o: Observation = { type: "instantWithdrawal", token: ev.args.token, to: ev.args.to, amount: ev.args.amount };
          const a = decide(o, policy);
          if (a.type === "none") log("pass", a.reason, { hash: l.transactionHash });
          else if (await vault.frozen()) log("pass", `already frozen; ${a.reason}`);
          else await act(a);
        }
        next = head + 1n;
      }
    } catch (e) {
      log("error", e instanceof Error ? e.message : String(e));
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});

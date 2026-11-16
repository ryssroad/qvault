// watch.ts — record everything that happens to the drill account and the vault (Q-Day Drill log).
//
//   npm run watch -- <vault> [fromBlock]
//
// Writes one JSON object per line to ../drill-log/<UTC date>.jsonl and prints a short line for each:
//   tx       an EVM tx that landed, sent by the drill account or to the vault (status, selector, value)
//   event    a vault event (Withdrawn, OwnerChanged, GuardianChanged, Frozen, Unfrozen, Deposited)
//   state    vault/account state whenever it changes (balances, owner, guardian, nonces, frozen, window)
//   ALERT    the vault lost value, changed owner/guardian, froze, or a window opened
//
// Transactions refused at broadcast (no window, target not allowed, bad hybrid signature) never reach
// a block, so they cannot be seen here: what is logged is what the chain accepted.
// This loop is also the observation half of the planned guardian agent.

import { appendFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Interface, JsonRpcProvider, formatEther, isAddress } from "ethers";
import { evmWindowStatus } from "@qorechain/evm";
import { NET, account } from "./lib.js";

const VAULT_ABI = [
  "event Deposited(address indexed from, uint256 amount)",
  "event Withdrawn(address indexed token, address indexed to, uint256 amount, uint256 nonce)",
  "event OwnerChanged(address indexed previousOwner, address indexed newOwner)",
  "event GuardianChanged(address indexed previousGuardian, address indexed newGuardian)",
  "event Frozen(address indexed by)",
  "event Unfrozen()",
  "function owner() view returns (address)",
  "function guardian() view returns (address)",
  "function ownerNonce() view returns (uint256)",
  "function guardianNonce() view returns (uint256)",
  "function frozen() view returns (bool)",
];
const iface = new Interface(VAULT_ABI);
const POLL_MS = Number(process.env.POLL_MS ?? "3000");
const MAX_BLOCKS_PER_TICK = 40;

const LOG_DIR = fileURLToPath(new URL("../drill-log/", import.meta.url));
mkdirSync(LOG_DIR, { recursive: true });
const logFile = () => `${LOG_DIR}${new Date().toISOString().slice(0, 10)}.jsonl`;

function record(kind: string, data: Record<string, unknown>, line: string): void {
  const entry = { t: new Date().toISOString(), kind, ...data };
  appendFileSync(logFile(), JSON.stringify(entry, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) + "\n");
  console.log(`${entry.t.slice(11, 19)} ${kind.padEnd(6)} ${line}`);
}

type RpcTx = { hash: string; from: string; to: string | null; value: string; input: string };
type RpcBlock = { number: string; timestamp: string; transactions: RpcTx[] };
type RpcLog = { topics: string[]; data: string; transactionHash: string; blockNumber: string };

async function main() {
  const vault = process.argv[2];
  if (!vault || !isAddress(vault)) throw new Error("usage: npm run watch -- <vault> [fromBlock]");
  const acc = await account();
  const me = acc.evm.toLowerCase();
  const v = vault.toLowerCase();
  const rpc = new JsonRpcProvider(NET.evm);
  const call = (fn: string) => rpc.call({ to: vault, data: iface.encodeFunctionData(fn) }).then((r) => iface.decodeFunctionResult(fn, r)[0]);

  let next = process.argv[3] ? BigInt(process.argv[3]) : BigInt(await rpc.send("eth_blockNumber", []));
  let last = "";
  let lastVaultBal: bigint | undefined;
  record("start", { vault, account: acc.evm, qor: acc.cosmos, fromBlock: next }, `vault ${vault}  account ${acc.evm}  from block ${next}`);

  for (;;) {
    try {
      const head = BigInt(await rpc.send("eth_blockNumber", []));
      const to = head < next + BigInt(MAX_BLOCKS_PER_TICK) ? head : next + BigInt(MAX_BLOCKS_PER_TICK) - 1n;

      for (let n = next; n <= to; n++) {
        const b = (await rpc.send("eth_getBlockByNumber", ["0x" + n.toString(16), true])) as RpcBlock | null;
        for (const tx of b?.transactions ?? []) {
          const from = tx.from?.toLowerCase();
          const dest = tx.to?.toLowerCase() ?? null;
          if (from !== me && dest !== v) continue;
          const rc = (await rpc.send("eth_getTransactionReceipt", [tx.hash])) as { status?: string; gasUsed?: string } | null;
          const status = rc?.status === "0x1" ? 1 : 0;
          const selector = tx.input && tx.input.length >= 10 ? tx.input.slice(0, 10) : "";
          let fn = selector;
          try {
            if (selector) fn = iface.getFunction(selector)?.name ?? selector;
          } catch { /* not a vault function */ }
          record(
            "tx",
            { block: n, hash: tx.hash, from: tx.from, to: tx.to, value: BigInt(tx.value), selector, fn, status, gasUsed: rc?.gasUsed },
            `#${n} ${status ? "OK  " : "FAIL"} ${tx.from.slice(0, 10)}→${(tx.to ?? "create").slice(0, 10)} ${fn || "transfer"} ${formatEther(BigInt(tx.value))} QOR ${tx.hash}`,
          );
        }
      }

      if (to >= next) {
        const logs = (await rpc.send("eth_getLogs", [
          { address: vault, fromBlock: "0x" + next.toString(16), toBlock: "0x" + to.toString(16) },
        ])) as RpcLog[];
        for (const l of logs) {
          const ev = iface.parseLog({ topics: l.topics, data: l.data });
          if (!ev) continue;
          const args = Object.fromEntries(ev.fragment.inputs.map((i, k) => [i.name, ev.args[k]]));
          record("event", { block: BigInt(l.blockNumber), hash: l.transactionHash, name: ev.name, args }, `${ev.name} ${JSON.stringify(args, (_k, x) => (typeof x === "bigint" ? x.toString() : x))}`);
        }
        next = to + 1n;
      }

      const [vaultBal, accBal, owner, guardian, ownerNonce, guardianNonce, frozen, w] = await Promise.all([
        rpc.getBalance(vault),
        rpc.getBalance(acc.evm),
        call("owner"),
        call("guardian"),
        call("ownerNonce"),
        call("guardianNonce"),
        call("frozen"),
        evmWindowStatus({ rest: NET.rest, address: acc.cosmos }),
      ]);
      const state = {
        vaultQOR: formatEther(vaultBal),
        accountQOR: formatEther(accBal),
        owner,
        guardian,
        ownerNonce: ownerNonce.toString(),
        guardianNonce: guardianNonce.toString(),
        frozen,
        window: w.found
          ? { live: w.live, remainingTxs: w.remainingTxs.toString(), remainingUqor: w.remainingValue.toString(), targets: w.allowedTargets }
          : null,
      };
      const key = JSON.stringify(state);
      if (key !== last) {
        const prev = last ? (JSON.parse(last) as typeof state) : undefined;
        record("state", { block: head, ...state }, `vault ${state.vaultQOR} QOR | account ${state.accountQOR} QOR | nonce ${state.ownerNonce} | frozen ${frozen} | window ${w.found && w.live ? "LIVE" : "none"}`);
        const alerts: string[] = [];
        if (lastVaultBal !== undefined && vaultBal < lastVaultBal) alerts.push(`vault balance dropped ${formatEther(lastVaultBal - vaultBal)} QOR`);
        if (prev && prev.owner !== owner) alerts.push(`owner changed ${prev.owner} → ${owner}`);
        if (prev && prev.guardian !== guardian) alerts.push(`guardian changed ${prev.guardian} → ${guardian}`);
        if (prev && !prev.frozen && frozen) alerts.push("vault frozen");
        if (prev && !prev.window?.live && w.found && w.live) alerts.push("EVM window opened");
        for (const a of alerts) record("ALERT", { block: head, alert: a }, a);
        last = key;
        lastVaultBal = vaultBal;
      }
    } catch (e) {
      record("error", { error: e instanceof Error ? e.message : String(e) }, e instanceof Error ? e.message : String(e));
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});

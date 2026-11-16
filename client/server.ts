// server.ts — local dashboard + signer for QVault (v1 and v2).
//
//   npm run dashboard                       → http://127.0.0.1:8787
//   npm run dashboard -- --record [name]    same, and record the session for a video replay
//
// The page never sees a key. This process holds the owner keys (like a hardware-wallet bridge), signs
// with ML-DSA-87, relays on the EVM lane, and serves the state of both vaults. It binds to 127.0.0.1
// only, and every POST needs the `x-qvault: 1` header (a cross-origin page cannot send it without a
// CORS preflight, which this server never answers).
//
// The guardian is NOT part of this process: run `npm run guardian -- <v2 vault>` separately. The
// dashboard only reads its log (guardian-log/), so the video shows an independent agent reacting.
//
// env: V1_VAULT, V2_VAULT (defaults: the testnet deployments), V1_FROM_BLOCK, V2_FROM_BLOCK,
//      OWNER_MNEMONIC_FILE (v2 owner, default ../secrets/owner.mnemonic), MNEMONIC_FILE (v1 owner =
//      drill account, default ../secrets/drill.mnemonic), GUARDIAN_POLICY, PORT.
//
// Recording (--record): every second the server snapshots the same state the page shows and appends
// it to ../video/sessions/<UTC time>[-name].jsonl, together with every button press (request and
// result, with tx hash) and optional scene marks. The page shows ● REC. Nothing secret is recorded:
// the state holds addresses, balances and logs only. video/ is gitignored.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mldsa } from "@qorechain/pqc";
import { closeEvmWindowMsg, openEvmWindowMsg } from "@qorechain/sdk";
import { evmWindowCost, evmWindowStatus } from "@qorechain/evm";
import { AbiCoder, Contract, Interface, JsonRpcProvider, Wallet, ZeroAddress, formatEther, getBytes, hexlify, isAddress, parseEther } from "ethers";
import { FEE_CAP_WEI, NET, TX, account, accountFrom, broadcast, ensureVaultWindow } from "./lib.js";
import { KIND, approvalHash } from "./guardian-policy.js";
import { V2_ABI } from "./v2.js";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const PORT = Number(process.env.PORT ?? "8787");
const V1 = process.env.V1_VAULT ?? "0x5a7f65d0573be384f64351f30a616ed48dca3015";
const V2 = process.env.V2_VAULT ?? "0x032d58891efDdBa939bC349Ebb32B8A37191DE0f";
const V1_FROM = BigInt(process.env.V1_FROM_BLOCK ?? "10030000");
const V2_FROM = BigInt(process.env.V2_FROM_BLOCK ?? "10081000");
const OWNER_FILE = process.env.OWNER_MNEMONIC_FILE ?? here("../secrets/owner.mnemonic");
const POLICY = process.env.GUARDIAN_POLICY ?? here("./guardian-policy.json");
const THIEF_SINK = "0x000000000000000000000000000000000000dEaD";

const V1_ABI = [
  "function owner() view returns (address)",
  "function guardian() view returns (address)",
  "function ownerNonce() view returns (uint256)",
  "function frozen() view returns (bool)",
  "function withdrawDigest(address token, address to, uint256 amount, uint256 deadline) view returns (bytes32)",
  "function withdraw(address token, address to, uint256 amount, uint256 deadline, bytes sig)",
  "event Deposited(address indexed from, uint256 amount)",
  "event Withdrawn(address indexed token, address indexed to, uint256 amount, uint256 nonce)",
  "event OwnerChanged(address indexed previousOwner, address indexed newOwner)",
  "event GuardianChanged(address indexed previousGuardian, address indexed newGuardian)",
  "event Frozen(address indexed by)",
  "event Unfrozen()",
];
const V2_EVENTS = [
  ...V2_ABI,
  "event Deposited(address indexed from, uint256 amount)",
  "event OwnerChanged(address indexed previousOwner, address indexed newOwner)",
  "event GuardianChanged(address indexed previousGuardian, address indexed newGuardian)",
  "event DelayChanged(uint64 previousDelay, uint64 newDelay)",
  "event LimitChanged(address indexed token, uint256 limitPerPeriod)",
  "event Unfrozen()",
];
const ifaceV1 = new Interface(V1_ABI);
const ifaceV2 = new Interface(V2_EVENTS);
const coder = AbiCoder.defaultAbiCoder();
const rpc = new JsonRpcProvider(NET.evm);

// ------------------------------------------------------------------ accounts (lazy)

const v1Owner = account(); // drill account
const v2Owner = existsSync(OWNER_FILE) ? accountFrom(OWNER_FILE) : undefined;
v1Owner.catch(() => {});
v2Owner?.catch(() => {});

async function v2Ctx() {
  if (!v2Owner) throw new Error(`no v2 owner key: ${OWNER_FILE} not found`);
  const acc = await v2Owner;
  const wallet = new Wallet(acc.privateKey, rpc);
  return { acc, vault: new Contract(V2, V2_ABI, wallet), sign: (d: string) => hexlify(mldsa.sign(acc.pqc.secretKey, getBytes(d))) };
}
const deadline = () => BigInt(Math.floor(Date.now() / 1000) + 600);

// ------------------------------------------------------------------ event history (incremental)

type Ev = { vault: "v1" | "v2"; block: number; time?: number; hash: string; name: string; args: Record<string, string> };
const history: Ev[] = [];
const cursor = { v1: V1_FROM, v2: V2_FROM };
let chunk = 5000n;
const blockTime = new Map<number, number>();

async function scan(which: "v1" | "v2", head: bigint): Promise<void> {
  const address = which === "v1" ? V1 : V2;
  const iface = which === "v1" ? ifaceV1 : ifaceV2;
  while (cursor[which] <= head) {
    const to = cursor[which] + chunk - 1n < head ? cursor[which] + chunk - 1n : head;
    let logs: { topics: string[]; data: string; transactionHash: string; blockNumber: string }[];
    try {
      logs = await rpc.send("eth_getLogs", [{ address, fromBlock: "0x" + cursor[which].toString(16), toBlock: "0x" + to.toString(16) }]);
    } catch (e) {
      if (chunk > 100n) { chunk /= 2n; continue; } // the node limits ranges: shrink and retry
      throw e;
    }
    for (const l of logs) {
      const ev = iface.parseLog({ topics: l.topics, data: l.data });
      if (!ev) continue;
      const args = Object.fromEntries(ev.fragment.inputs.map((i, k) => [i.name, String(ev.args[k])]));
      const block = Number(BigInt(l.blockNumber));
      if (!blockTime.has(block)) {
        const b = (await rpc.send("eth_getBlockByNumber", [l.blockNumber, false])) as { timestamp: string } | null;
        if (b) blockTime.set(block, Number(BigInt(b.timestamp)));
      }
      history.push({ vault: which, block, time: blockTime.get(block), hash: l.transactionHash, name: ev.name, args });
    }
    cursor[which] = to + 1n;
  }
}

// ------------------------------------------------------------------ state

function tailJsonl(dir: string, n: number): unknown[] {
  if (!existsSync(dir)) return [];
  const files = readdirSync(dir).filter((f) => f.endsWith(".jsonl")).sort();
  const out: unknown[] = [];
  for (let i = files.length - 1; i >= 0 && out.length < n; i--) {
    const lines = readFileSync(dir + files[i], "utf8").trim().split("\n").filter(Boolean).reverse();
    for (const l of lines) {
      if (out.length >= n) break;
      try { out.push(JSON.parse(l)); } catch { /* partial line */ }
    }
  }
  return out;
}

async function windowOf(address: string) {
  const w = await evmWindowStatus({ rest: NET.rest, address });
  return w.found && w.live
    ? { live: true, remainingTxs: Number(w.remainingTxs), remainingQOR: Number(w.remainingValue) / 1e6, targets: w.allowedTargets }
    : { live: false };
}

let cache: { at: number; body: unknown } | undefined;
async function state(): Promise<unknown> {
  if (cache && Date.now() - cache.at < 1500) return cache.body;
  const head = BigInt(await rpc.send("eth_blockNumber", []));
  await Promise.all([scan("v1", head), scan("v2", head)]);
  const now = Math.floor(Date.now() / 1000);

  const r1 = new Contract(V1, V1_ABI, rpc);
  const a1 = await v1Owner.catch(() => undefined);
  const [b1, o1, g1, n1, f1] = await Promise.all([rpc.getBalance(V1), r1.owner(), r1.guardian(), r1.ownerNonce(), r1.frozen()]);
  const v1 = {
    address: V1, balance: formatEther(b1), owner: o1, guardian: g1, nonce: Number(n1), frozen: f1,
    ownerAccount: a1 ? { evm: a1.evm, qor: a1.cosmos, balance: formatEther(await rpc.getBalance(a1.evm)), window: await windowOf(a1.cosmos) } : null,
  };

  const r2 = new Contract(V2, V2_ABI, rpc);
  const a2 = await v2Owner?.catch(() => undefined);
  const [b2, o2, g2, n2, gn2, f2, d2, rem, next] = await Promise.all([
    rpc.getBalance(V2), r2.owner(), r2.guardian(), r2.ownerNonce(), r2.guardianNonce(), r2.frozen(), r2.delay(), r2.instantRemaining(ZeroAddress), r2.nextId(),
  ]);
  const limit = (await new Contract(V2, ["function budget(address) view returns (uint256 limit, uint256 spent, uint64 periodStart)"], rpc).budget(ZeroAddress)).limit as bigint;
  const pending = [];
  for (let id = 0; id < Number(next); id++) {
    const [kind, eta, data] = await r2.pending(id);
    if (eta === 0n) continue;
    pending.push({ id, kind: KIND[Number(kind)], eta: Number(eta), secondsLeft: Math.max(0, Number(eta) - now), summary: describe(Number(kind), data) });
  }
  const v2 = {
    address: V2, balance: formatEther(b2), owner: o2, guardian: g2, ownerNonce: Number(n2), guardianNonce: Number(gn2),
    frozen: f2, delay: Number(d2), instantLimit: formatEther(limit), instantRemaining: formatEther(rem), pending,
    ownerAccount: a2 ? { evm: a2.evm, qor: a2.cosmos, balance: formatEther(await rpc.getBalance(a2.evm)), window: await windowOf(a2.cosmos) } : null,
  };

  const events = history.slice(-60).reverse();
  const body = { head: Number(head), now, v1, v2, events, guardian: tailJsonl(here("../guardian-log/"), 40), drill: tailJsonl(here("../drill-log/"), 40), actions: actions.slice(-30).reverse() };
  cache = { at: Date.now(), body };
  return body;
}

function describe(kind: number, data: string): string {
  try {
    if (kind === 0) {
      const [token, to, amount] = coder.decode(["address", "address", "uint256"], data);
      return `${formatEther(amount)} ${token === ZeroAddress ? "QOR" : token} → ${to}`;
    }
    if (kind === 1 || kind === 2) return String(coder.decode(["address"], data)[0]);
    if (kind === 3) return `${coder.decode(["uint64"], data)[0]} s`;
    if (kind === 4) { const [t, l] = coder.decode(["address", "uint256"], data); return `${formatEther(l)} / 24h for ${t === ZeroAddress ? "QOR" : t}`; }
    return "";
  } catch { return data; }
}

// ------------------------------------------------------------------ actions (serialised)

type ActionLog = { t: string; action: string; ok: boolean; detail: string; hash?: string };
const actions: ActionLog[] = [];
let busy: Promise<unknown> = Promise.resolve();

async function sendV2(fn: (c: Awaited<ReturnType<typeof v2Ctx>>) => Promise<{ hash: string; wait(): Promise<{ status?: number | null } | null> }>) {
  const c = await v2Ctx();
  const opened = await ensureVaultWindow(c.acc, V2);
  const tx = await fn(c);
  const rc = await tx.wait();
  if (rc?.status !== 1) throw new Error(`tx ${tx.hash} reverted`);
  return { hash: tx.hash, note: opened ? `opened owner window ${opened.slice(0, 10)}… first` : "" };
}

function addPolicyApproval(hash: string): void {
  const p = existsSync(POLICY) ? JSON.parse(readFileSync(POLICY, "utf8")) : { allowedRecipients: [], approved: [] };
  p.approved = Array.from(new Set([...(p.approved ?? []), hash]));
  writeFileSync(POLICY, JSON.stringify(p, null, 2) + "\n");
}

const handlers: Record<string, (b: Record<string, string>) => Promise<{ hash?: string; detail: string }>> = {
  // ---- v2, owner
  async "v2-withdraw"({ to, amount }) {
    const wei = parseEther(amount); const dest = to || (await v2Ctx()).acc.evm;
    const r = await sendV2(async ({ vault, sign }) => { const dl = deadline(); return vault.withdraw(ZeroAddress, dest, wei, dl, sign(await vault.withdrawDigest(ZeroAddress, dest, wei, dl)), TX); });
    return { hash: r.hash, detail: `instant ${amount} QOR → ${dest} ${r.note}` };
  },
  async "v2-queue-withdraw"({ to, amount }) {
    const dest = to || (await v2Ctx()).acc.evm;
    return queueOp(0, coder.encode(["address", "address", "uint256"], [ZeroAddress, dest, parseEther(amount)]), `withdraw ${amount} QOR → ${dest}`);
  },
  async "v2-approve-unfreeze"() {
    // Out-of-band approval: the owner edits the guardian's policy file, then queues.
    addPolicyApproval(approvalHash(5, "0x"));
    return queueOp(5, "0x", "unfreeze (approved in guardian policy first)");
  },
  async "v2-execute"({ id }) {
    const r = await sendV2(({ vault }) => vault.execute(BigInt(id), TX));
    return { hash: r.hash, detail: `execute #${id} ${r.note}` };
  },
  async "v2-fund"({ amount }) {
    const c = await v2Ctx();
    await ensureVaultWindow(c.acc, V2);
    const tx = await new Wallet(c.acc.privateKey, rpc).sendTransaction({ to: V2, value: parseEther(amount), ...TX, gasLimit: 100_000n });
    await tx.wait();
    return { hash: tx.hash, detail: `fund ${amount} QOR` };
  },
  // ---- v2, "stolen owner key": signed with the real owner key, sent to a sink the guardian does not know
  async "thief-withdraw"({ amount }) {
    const wei = parseEther(amount || "0.5");
    const r = await sendV2(async ({ vault, sign }) => { const dl = deadline(); return vault.withdraw(ZeroAddress, THIEF_SINK, wei, dl, sign(await vault.withdrawDigest(ZeroAddress, THIEF_SINK, wei, dl)), TX); });
    return { hash: r.hash, detail: `THIEF instant ${formatEther(wei)} QOR → ${THIEF_SINK}` };
  },
  async "thief-queue-withdraw"({ amount }) {
    return queueOp(0, coder.encode(["address", "address", "uint256"], [ZeroAddress, THIEF_SINK, parseEther(amount || "10")]), `THIEF queue ${amount || "10"} QOR → ${THIEF_SINK}`);
  },
  async "thief-remove-guardian"() {
    return queueOp(2, coder.encode(["address"], [ZeroAddress]), "THIEF queue setGuardian(0)");
  },
  async "v2-open-window"() {
    const c = await v2Ctx();
    const opened = await ensureVaultWindow(c.acc, V2);
    return { hash: opened, detail: opened ? "owner window opened: vault only, 20 calls" : "owner window already live" };
  },
  async "v2-close-window"() {
    const c = await v2Ctx();
    return { hash: await broadcast(c.acc, "hybrid", [closeEvmWindowMsg(c.acc.cosmos)]), detail: "owner window closed" };
  },
  // ---- v1: the Q-Day Drill "normal transaction" in one step: scoped window → PQ withdrawal → close
  async "v1-normal-tx"({ amount }) {
    const acc = await v1Owner;
    const wei = parseEther(amount || "1");
    const maxValue = evmWindowCost({ gas: 600_000n, maxFeePerGas: FEE_CAP_WEI }) * 2n;
    const opened = await broadcast(acc, "hybrid", [openEvmWindowMsg({ sender: acc.cosmos, blocks: 300n, maxTxs: 2n, maxValue, allowedTargets: [V1] })]);
    try {
      for (let i = 0; i < 20 && !(await evmWindowStatus({ rest: NET.rest, address: acc.cosmos })).live; i++) await new Promise((r) => setTimeout(r, 1500));
      const vault = new Contract(V1, V1_ABI, new Wallet(acc.privateKey, rpc));
      const dl = deadline();
      const sig = hexlify(mldsa.sign(acc.pqc.secretKey, getBytes(await vault.withdrawDigest(ZeroAddress, acc.evm, wei, dl))));
      const tx = await vault.withdraw(ZeroAddress, acc.evm, wei, dl, sig, { gasLimit: 600_000n, maxFeePerGas: FEE_CAP_WEI, maxPriorityFeePerGas: 1_000_000_000n });
      const rc = await tx.wait();
      if (rc?.status !== 1) throw new Error(`tx ${tx.hash} reverted`);
      return { hash: tx.hash, detail: `v1 PQ withdrawal ${formatEther(wei)} QOR → owner (window ${opened.slice(0, 10)}… opened and closed)` };
    } finally {
      await broadcast(acc, "hybrid", [closeEvmWindowMsg(acc.cosmos)]);
    }
  },
};

async function queueOp(kind: number, data: string, label: string) {
  const r = await sendV2(async ({ vault, sign }) => { const dl = deadline(); return vault.queue(kind, data, dl, sign(await vault.queueDigest(kind, data, dl)), TX); });
  return { hash: r.hash, detail: `queue ${KIND[kind]}: ${label} ${r.note}` };
}

// ------------------------------------------------------------------ session recording

const recArg = process.argv.indexOf("--record");
const RECORD = recArg >= 0 || process.env.RECORD === "1";
const recName = recArg >= 0 && process.argv[recArg + 1] && !process.argv[recArg + 1]!.startsWith("-") ? process.argv[recArg + 1] : process.env.RECORD_NAME;
const recStarted = Date.now();
const recFile = RECORD
  ? here(`../video/sessions/${new Date(recStarted).toISOString().replace(/[:.]/g, "-")}${recName ? "-" + recName.replace(/[^\w-]/g, "_") : ""}.jsonl`)
  : undefined;
let marks = 0;

function rec(type: string, data: Record<string, unknown>): void {
  if (!recFile) return;
  appendFileSync(recFile, JSON.stringify({ t: Date.now(), type, ...data }, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) + "\n");
}

if (recFile) {
  mkdirSync(here("../video/sessions/"), { recursive: true });
  rec("meta", { v1: V1, v2: V2, chainId: NET.chainId, started: new Date(recStarted).toISOString(), name: recName ?? null });
  let lastKey = "";
  let snapping = false;
  const snap = async () => {
    if (snapping) return; // a slow round (first history scan) must not pile up
    snapping = true;
    try {
      const body = (await state()) as Record<string, unknown> & { head: number; now: number; v2: { pending: { secondsLeft?: number }[] } };
      // Ticks every second; full state only when something besides the clock changed.
      rec("tick", { head: body.head, now: body.now });
      const key = JSON.stringify({ ...body, head: 0, now: 0, v2: { ...body.v2, pending: body.v2.pending.map((p) => ({ ...p, secondsLeft: 0 })) } });
      if (key !== lastKey) {
        lastKey = key;
        rec("state", { state: body });
      }
    } catch (e) {
      rec("error", { error: e instanceof Error ? e.message : String(e) });
    } finally {
      snapping = false;
    }
  };
  void snap();
  setInterval(snap, 1000);
}

// ------------------------------------------------------------------ http

const json = (res: ServerResponse, code: number, body: unknown) => {
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
};

async function readBody(req: IncomingMessage): Promise<Record<string, string>> {
  let s = "";
  for await (const c of req) { s += c; if (s.length > 10_000) throw new Error("body too large"); }
  return s ? JSON.parse(s) : {};
}

createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(readFileSync(here("./web/index.html")));
    }
    if (req.method === "GET" && req.url === "/api/state") return json(res, 200, await state());
    if (req.method === "GET" && req.url === "/api/recording") {
      return json(res, 200, recFile ? { recording: true, file: recFile, startedAt: recStarted, marks } : { recording: false });
    }
    if (req.method === "POST" && req.url === "/api/mark") {
      if (req.headers["x-qvault"] !== "1") return json(res, 403, { error: "missing x-qvault header" });
      if (!recFile) return json(res, 409, { error: "not recording" });
      const label = String((await readBody(req)).label ?? "").slice(0, 120) || `scene ${marks + 1}`;
      marks++;
      rec("mark", { label, n: marks });
      return json(res, 200, { ok: true, label, n: marks });
    }
    if (req.method === "POST" && req.url === "/api/action") {
      if (req.headers["x-qvault"] !== "1") return json(res, 403, { error: "missing x-qvault header" });
      const body = await readBody(req);
      const h = handlers[body.action ?? ""];
      if (!h) return json(res, 400, { error: `unknown action ${body.action}` });
      if (body.to && !isAddress(body.to)) return json(res, 400, { error: "bad address" });
      rec("action-start", { action: body.action, body });
      const run = busy.then(() => h(body));
      busy = run.catch(() => {});
      const t = new Date().toISOString();
      try {
        const r = await run;
        actions.push({ t, action: body.action!, ok: true, detail: r.detail, hash: r.hash });
        rec("action-end", { action: body.action, ok: true, detail: r.detail, hash: r.hash });
        cache = undefined;
        return json(res, 200, { ok: true, ...r });
      } catch (e) {
        const msg = e instanceof Error ? (e as { shortMessage?: string }).shortMessage ?? e.message : String(e);
        actions.push({ t, action: body.action!, ok: false, detail: msg });
        rec("action-end", { action: body.action, ok: false, error: msg });
        return json(res, 200, { ok: false, error: msg });
      }
    }
    json(res, 404, { error: "not found" });
  } catch (e) {
    json(res, 500, { error: e instanceof Error ? e.message : String(e) });
  }
}).listen(PORT, "127.0.0.1", () => {
  console.log(`QVault dashboard → http://127.0.0.1:${PORT}`);
  console.log(`v1 ${V1}   v2 ${V2}`);
  console.log(v2Owner ? `v2 owner key: ${OWNER_FILE}` : `v2 owner key missing (${OWNER_FILE}): v2 actions disabled`);
  if (recFile) console.log(`● REC → ${recFile}`);
});

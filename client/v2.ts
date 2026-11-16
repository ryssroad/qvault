// v2.ts — owner-side CLI for QVaultV2 (timelock + guardian veto).
//
//   npm run v2 -- deploy <guardian|0x0> <delaySeconds> <nativeInstantLimitWei>
//   npm run v2 -- fund <vault> <amountWei>                            plain QOR transfer into the vault
//   npm run v2 -- status <vault>
//   npm run v2 -- withdraw <vault> <to> <amountWei> [token]          instant, inside the 24h budget
//   npm run v2 -- queue <vault> withdraw <to> <amountWei> [token]    timelocked
//   npm run v2 -- queue <vault> set-owner <address>
//   npm run v2 -- queue <vault> set-guardian <address|0x0>
//   npm run v2 -- queue <vault> set-delay <seconds>
//   npm run v2 -- queue <vault> set-limit <token|0x0> <weiPer24h>
//   npm run v2 -- queue <vault> unfreeze
//   npm run v2 -- approval <same arguments as queue, without the vault>   hash for the guardian policy
//   npm run v2 -- execute <vault> <id>
//
// Signs with the owner's ML-DSA-87 key (secrets/drill.mnemonic or MNEMONIC_FILE) and relays from the
// same account, which needs a live EVM window (deploy: `npm run drill open-deploy`, calls:
// `npm run drill open-drill <vault>`).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mldsa } from "@qorechain/pqc";
import { AbiCoder, Contract, ContractFactory, JsonRpcProvider, Wallet, ZeroAddress, formatEther, getBytes, getCreateAddress, hexlify, isAddress } from "ethers";
import { NET, TX, account } from "./lib.js";
import { KIND, approvalHash } from "./guardian-policy.js";

export const V2_ABI = [
  "function owner() view returns (address)",
  "function guardian() view returns (address)",
  "function ownerNonce() view returns (uint256)",
  "function guardianNonce() view returns (uint256)",
  "function frozen() view returns (bool)",
  "function delay() view returns (uint64)",
  "function nextId() view returns (uint256)",
  "function instantRemaining(address token) view returns (uint256)",
  "function pending(uint256 id) view returns (uint8 kind, uint64 eta, bytes data)",
  "function digest(uint8 op, uint256 nonce, uint256 deadline, bytes payload) view returns (bytes32)",
  "function withdrawDigest(address token, address to, uint256 amount, uint256 deadline) view returns (bytes32)",
  "function queueDigest(uint8 kind, bytes data, uint256 deadline) view returns (bytes32)",
  "function withdraw(address token, address to, uint256 amount, uint256 deadline, bytes sig)",
  "function queue(uint8 kind, bytes data, uint256 deadline, bytes sig) returns (uint256)",
  "function execute(uint256 id)",
  "function cancel(uint256 id, uint256 deadline, bytes sig)",
  "function guardianFreeze(uint256 deadline, bytes sig)",
  "event Withdrawn(address indexed token, address indexed to, uint256 amount, bool instant)",
  "event Queued(uint256 indexed id, uint8 kind, bytes data, uint64 eta)",
  "event Executed(uint256 indexed id, uint8 kind)",
  "event Cancelled(uint256 indexed id, address indexed by)",
  "event Frozen(address indexed by)",
];
export const OP = { Withdraw: 0, Queue: 1, Freeze: 2, Cancel: 3 } as const;
const coder = AbiCoder.defaultAbiCoder();
const addr = (s: string | undefined, what: string): string => {
  const a = s === "0x0" ? ZeroAddress : s;
  if (!a || !isAddress(a)) throw new Error(`${what}: expected an address, got ${s}`);
  return a;
};
const deadline = () => BigInt(Math.floor(Date.now() / 1000) + Number(process.env.TTL ?? "600"));

/** Parse `withdraw <to> <amount> [token]`, `set-owner <a>`, … into (kind, data). */
export function parseOperation(args: string[]): { kind: number; data: string } {
  const [name, a, b, c] = args;
  switch (name) {
    case "withdraw":
      return { kind: 0, data: coder.encode(["address", "address", "uint256"], [addr(c ?? "0x0", "token"), addr(a, "to"), BigInt(b ?? "x")]) };
    case "set-owner":
      return { kind: 1, data: coder.encode(["address"], [addr(a, "owner")]) };
    case "set-guardian":
      return { kind: 2, data: coder.encode(["address"], [addr(a, "guardian")]) };
    case "set-delay":
      return { kind: 3, data: coder.encode(["uint64"], [BigInt(a ?? "x")]) };
    case "set-limit":
      return { kind: 4, data: coder.encode(["address", "uint256"], [addr(a, "token"), BigInt(b ?? "x")]) };
    case "unfreeze":
      return { kind: 5, data: "0x" };
    default:
      throw new Error(`unknown operation "${name}": withdraw | set-owner | set-guardian | set-delay | set-limit | unfreeze`);
  }
}

async function ctx(vaultAddr: string | undefined) {
  const acc = await account();
  const wallet = new Wallet(acc.privateKey, new JsonRpcProvider(NET.evm));
  const vault = new Contract(addr(vaultAddr, "vault"), V2_ABI, wallet);
  const sign = (digest: string) => hexlify(mldsa.sign(acc.pqc.secretKey, getBytes(digest)));
  return { acc, wallet, vault, sign };
}

async function report(tx: { hash: string; wait(): Promise<{ status?: number | null; gasUsed?: bigint } | null> }) {
  console.log(`tx      ${tx.hash}`);
  const rc = await tx.wait();
  console.log(`status  ${rc?.status}  gas ${rc?.gasUsed}`);
}

const commands: Record<string, (a: string[]) => Promise<void>> = {
  async deploy([guardian, delaySec, limit]) {
    if (!delaySec || !limit) throw new Error("usage: deploy <guardian|0x0> <delaySeconds> <nativeInstantLimitWei>");
    const artifact = JSON.parse(readFileSync(fileURLToPath(new URL("../out/QVaultV2.sol/QVaultV2.json", import.meta.url)), "utf8"));
    const acc = await account();
    const wallet = new Wallet(acc.privateKey, new JsonRpcProvider(NET.evm));
    const nonce = await wallet.getNonce();
    console.log(`expected  ${getCreateAddress({ from: acc.evm, nonce })} (nonce ${nonce})`);
    const c = await new ContractFactory(artifact.abi, artifact.bytecode.object, wallet).deploy(
      acc.evm, addr(guardian, "guardian"), BigInt(delaySec), BigInt(limit),
      { ...TX, nonce, gasLimit: 4_000_000n },
    );
    console.log(`tx        ${c.deploymentTransaction()?.hash}`);
    await c.waitForDeployment();
    console.log(`deployed  ${await c.getAddress()}`);
  },

  async fund([v, amount]) {
    const { wallet, vault } = await ctx(v);
    await report(await wallet.sendTransaction({ to: await vault.getAddress(), value: BigInt(amount ?? "x"), ...TX, gasLimit: 100_000n }));
  },

  async status([v]) {
    const { vault, wallet } = await ctx(v);
    const n = Number(await vault.nextId());
    console.log(`owner     ${await vault.owner()}`);
    console.log(`guardian  ${await vault.guardian()}`);
    console.log(`balance   ${formatEther(await wallet.provider!.getBalance(await vault.getAddress()))} QOR`);
    console.log(`frozen    ${await vault.frozen()}   delay ${await vault.delay()}s   instant left ${formatEther(await vault.instantRemaining(ZeroAddress))} QOR`);
    for (let id = 0; id < n; id++) {
      const [kind, eta, data] = await vault.pending(id);
      if (eta === 0n) continue;
      console.log(`pending   #${id} ${KIND[Number(kind)]} eta ${new Date(Number(eta) * 1000).toISOString()} approval ${approvalHash(Number(kind), data)}`);
    }
  },

  async withdraw([v, to, amount, token]) {
    const { vault, sign } = await ctx(v);
    const dl = deadline();
    const t = addr(token ?? "0x0", "token");
    const d: string = await vault.withdrawDigest(t, addr(to, "to"), BigInt(amount ?? "x"), dl);
    await report(await vault.withdraw(t, to, BigInt(amount), dl, sign(d), TX));
  },

  async queue([v, ...rest]) {
    const { vault, sign } = await ctx(v);
    const { kind, data } = parseOperation(rest);
    const dl = deadline();
    const id = await vault.nextId();
    console.log(`queueing #${id} ${KIND[kind]}  approval ${approvalHash(kind, data)}`);
    await report(await vault.queue(kind, data, dl, sign(await vault.queueDigest(kind, data, dl)), TX));
    const [, eta] = await vault.pending(id);
    console.log(`eta     ${new Date(Number(eta) * 1000).toISOString()}  → npm run v2 -- execute ${v} ${id}`);
  },

  async approval(rest) {
    const { kind, data } = parseOperation(rest);
    console.log(approvalHash(kind, data));
  },

  async execute([v, id]) {
    const { vault } = await ctx(v);
    await report(await vault.execute(BigInt(id ?? "x"), TX));
  },
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const run = commands[process.argv[2] ?? ""];
  if (!run) {
    console.error(`Use: ${Object.keys(commands).join(" | ")}`);
    process.exit(1);
  }
  run(process.argv.slice(3)).catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  });
}

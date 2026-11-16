// Shared testnet config and drill-account helpers.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { StargateClient } from "@cosmjs/stargate";
import { EthNativeSigner, deriveUnifiedAccount, openEvmWindowMsg, type UnifiedAccount } from "@qorechain/sdk";
import { evmWindowCost, evmWindowStatus } from "@qorechain/evm";

export const NET = {
  chainId: "qorechain-diana",
  rest: "https://api-testnet.qore.host",
  rpc: "https://rpc-testnet.qore.host",
  evm: "https://evm-testnet.qore.host",
} as const;

export const MNEMONIC_FILE = resolve(process.env.MNEMONIC_FILE ?? fileURLToPath(new URL("../secrets/drill.mnemonic", import.meta.url)));
/** Native-lane fee: hybrid txs carry a 4,627-byte signature, so the gas limit is generous. */
const FEE = { amount: [{ denom: "uqor", amount: "100000" }], gas: "800000" };
/** EVM fee cap used to size windows; tools usually cap near 2x the ~100 gwei base fee. */
export const FEE_CAP_WEI = 250_000_000_000n;

export async function accountFrom(file: string): Promise<UnifiedAccount> {
  if (!existsSync(file)) throw new Error(`${file} not found — create it with: MNEMONIC_FILE=${file} npm run drill new`);
  return deriveUnifiedAccount(readFileSync(file, "utf8").trim(), 0);
}

/** The drill / owner account (secrets/drill.mnemonic or MNEMONIC_FILE). */
export async function account(): Promise<UnifiedAccount> {
  return accountFrom(MNEMONIC_FILE);
}

/** EVM overrides sized for one vault call: the window charges gasLimit x maxFeePerGas up front. */
export const TX = { gasLimit: 700_000n, maxFeePerGas: 250_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n } as const;

export async function accountSequence(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
  const res = await fetch(`${NET.rest}/cosmos/auth/v1beta1/accounts/${address}`);
  if (res.status === 404) throw new Error(`${address} is not on chain yet: fund it from the faucet first`);
  if (!res.ok) throw new Error(`account query failed: HTTP ${res.status}`);
  const body = (await res.json()) as { account?: Record<string, unknown> };
  const acc = (body.account?.base_account ?? body.account ?? {}) as Record<string, string>;
  return { accountNumber: BigInt(acc.account_number ?? "0"), sequence: BigInt(acc.sequence ?? "0") };
}

export async function balanceUqor(address: string): Promise<string> {
  const res = await fetch(`${NET.rest}/cosmos/bank/v1beta1/balances/${address}/by_denom?denom=uqor`);
  if (!res.ok) return "?";
  const b = (await res.json()) as { balance?: { amount?: string } };
  return b.balance?.amount ?? "0";
}

export async function broadcast(
  acc: UnifiedAccount,
  mode: "hybrid" | "classical",
  messages: Parameters<EthNativeSigner["sign"]>[0]["messages"],
): Promise<string> {
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: NET.rest });
  const transport = await StargateClient.connect(NET.rpc);
  try {
    const res = await signer.signAndBroadcast(transport, {
      chainId: NET.chainId,
      accountNumber,
      sequence,
      fee: FEE,
      messages,
    });
    return res.transactionHash;
  } finally {
    transport.disconnect();
  }
}


/**
 * Make sure `acc` has a live EVM window that lists `vault` and has room for one more call at TX
 * sizing; open a vault-only one (20 calls, max blocks) if not. Returns the open tx hash, if any.
 */
export async function ensureVaultWindow(acc: UnifiedAccount, vault: string): Promise<string | undefined> {
  const need = evmWindowCost({ gas: TX.gasLimit, maxFeePerGas: TX.maxFeePerGas });
  const ok = (w: Awaited<ReturnType<typeof evmWindowStatus>>) =>
    w.found && w.live && w.remainingTxs >= 1n && w.remainingValue >= need &&
    w.allowedTargets.some((t) => t.toLowerCase() === vault.toLowerCase());
  if (ok(await evmWindowStatus({ rest: NET.rest, address: acc.cosmos }))) return undefined;
  const msg = openEvmWindowMsg({ sender: acc.cosmos, blocks: 17280n, maxTxs: 20n, maxValue: need * 20n, allowedTargets: [vault] });
  const hash = await broadcast(acc, "hybrid", [msg]);
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    if (ok(await evmWindowStatus({ rest: NET.rest, address: acc.cosmos }))) return hash;
  }
  throw new Error("window did not become live");
}

// Shared testnet config and drill-account helpers.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { StargateClient } from "@cosmjs/stargate";
import { EthNativeSigner, deriveUnifiedAccount, type UnifiedAccount } from "@qorechain/sdk";

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

export async function account(): Promise<UnifiedAccount> {
  if (!existsSync(MNEMONIC_FILE)) throw new Error(`${MNEMONIC_FILE} not found — run: npm run drill new`);
  return deriveUnifiedAccount(readFileSync(MNEMONIC_FILE, "utf8").trim(), 0);
}

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


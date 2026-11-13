// Sign a QVault operation with the owner's ML-DSA-87 key and relay it on the EVM lane.
//
//   npm run withdraw -- <vault> <to> <amount-wei> [token]     token omitted = native QOR
//
// The owner is the drill account (secrets/drill.mnemonic); its ML-DSA-87 key comes from the mnemonic.
// The relayer defaults to the same account (needs a live window that lists the vault:
// `npm run drill open-drill <vault>`); set RELAYER_KEY to relay from any other funded account.
// The PQ signature — not msg.sender — authorises the withdrawal.

import { mldsa } from "@qorechain/pqc";
import { Contract, JsonRpcProvider, Wallet, getBytes, hexlify, isAddress } from "ethers";
import { FEE_CAP_WEI, NET, account } from "./lib.js";

const ABI = [
  "function owner() view returns (address)",
  "function ownerNonce() view returns (uint256)",
  "function withdrawDigest(address token, address to, uint256 amount, uint256 deadline) view returns (bytes32)",
  "function withdraw(address token, address to, uint256 amount, uint256 deadline, bytes sig)",
];
const ZERO = "0x0000000000000000000000000000000000000000";

async function main() {
  const [vaultAddr, to, amountStr, token = ZERO] = process.argv.slice(2);
  if (!isAddress(vaultAddr) || !isAddress(to) || !amountStr || !isAddress(token)) {
    throw new Error("usage: npm run withdraw -- <vault> <to> <amount-wei> [token]");
  }
  const acc = await account();
  const provider = new JsonRpcProvider(NET.evm);
  const relayer = new Wallet(process.env.RELAYER_KEY ?? acc.privateKey, provider);
  const vault = new Contract(vaultAddr, ABI, relayer);

  const owner: string = await vault.owner();
  if (owner.toLowerCase() !== acc.evm.toLowerCase()) throw new Error(`vault owner is ${owner}, not ${acc.evm}`);

  const amount = BigInt(amountStr);
  const deadline = BigInt(Math.floor(Date.now() / 1000) + Number(process.env.TTL ?? "600"));
  // The vault computes the digest itself (domain, chain id, its address, nonce): no re-implementation.
  const digest: string = await vault.withdrawDigest(token, to, amount, deadline);
  const sig = mldsa.sign(acc.pqc.secretKey, getBytes(digest)); // deterministic ML-DSA-87, 4,627 bytes
  if (!mldsa.verify(acc.pqc.publicKey, getBytes(digest), sig)) throw new Error("local verify failed");

  console.log(`vault   ${vaultAddr}  nonce ${await vault.ownerNonce()}`);
  console.log(`digest  ${digest}`);
  // Fixed gas limit and fee cap: the window charges gasLimit x maxFeePerGas up front.
  const tx = await vault.withdraw(token, to, amount, deadline, hexlify(sig), {
    gasLimit: 600_000n,
    maxFeePerGas: FEE_CAP_WEI,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  console.log(`tx      ${tx.hash}`);
  const rcpt = await tx.wait();
  console.log(`status  ${rcpt?.status}  gas ${rcpt?.gasUsed}`);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});

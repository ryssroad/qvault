// Sign a QVault withdrawal with the owner's ML-DSA-87 key and relay it.
//
// The relayer can be ANY funded EVM account with an open EVM window that lists the vault —
// it does not need to be the owner. The PQ signature, not msg.sender, authorises the withdrawal.
//
// env:
//   RPC            default https://evm-testnet.qore.host
//   VAULT          QVault address
//   RELAYER_KEY    0x… secp256k1 key of the relaying account
//   PQ_SECRET_FILE file with the owner's ML-DSA-87 secret key, hex (4896 bytes)
//   TOKEN          0x0 for native QOR, else ERC-20 address
//   TO             recipient
//   AMOUNT         in base units (wei for native QOR on the EVM side)
//   TTL            seconds until the signature expires, default 600
//
// Status: compiles against @qorechain/pqc 0.2.3 + ethers 6; not yet run against testnet.

import { readFileSync } from "node:fs";
import { mldsa } from "@qorechain/pqc";
import { Contract, JsonRpcProvider, Wallet, getBytes, hexlify } from "ethers";

const ABI = [
  "function owner() view returns (address)",
  "function withdrawDigest(address token, address to, uint256 amount, uint256 deadline) view returns (bytes32)",
  "function withdraw(address token, address to, uint256 amount, uint256 deadline, bytes sig)",
];

function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") throw new Error(`missing env ${name}`);
  return v;
}

async function main() {
  const provider = new JsonRpcProvider(env("RPC", "https://evm-testnet.qore.host"));
  const relayer = new Wallet(env("RELAYER_KEY"), provider);
  const vault = new Contract(env("VAULT"), ABI, relayer);

  const secretKey = getBytes("0x" + readFileSync(env("PQ_SECRET_FILE"), "utf8").trim().replace(/^0x/, ""));
  const token = env("TOKEN", "0x0000000000000000000000000000000000000000");
  const to = env("TO");
  const amount = BigInt(env("AMOUNT"));
  const deadline = BigInt(Math.floor(Date.now() / 1000) + Number(env("TTL", "600")));

  // The vault computes the digest itself (domain, chain id, its address, nonce) — no re-implementation.
  const digest: string = await vault.withdrawDigest(token, to, amount, deadline);
  const sig = mldsa.sign(secretKey, getBytes(digest)); // deterministic ML-DSA-87, 4627 bytes
  console.log("owner   ", await vault.owner());
  console.log("digest  ", digest);
  console.log("sig len ", sig.length);

  const tx = await vault.withdraw(token, to, amount, deadline, hexlify(sig));
  console.log("tx      ", tx.hash);
  const rcpt = await tx.wait();
  console.log("status  ", rcpt?.status, "gas", rcpt?.gasUsed?.toString());
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

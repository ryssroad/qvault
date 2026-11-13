// Deploy QVault from the drill account with ethers.
//
//   forge build && npm run deploy -- [guardian]        guardian omitted = none
//
// Why not `forge create`: QoreChain receipts carry a non-standard field (feePayer) that forge/alloy
// fails to deserialize, so forge reports "contract was not deployed" for a deploy that succeeded,
// and retrying leaves stray copies on chain. ethers parses the receipt fine.
// Needs a live window without target restrictions: `npm run drill open-deploy`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ContractFactory, JsonRpcProvider, Wallet, ZeroAddress, getCreateAddress, isAddress } from "ethers";
import { FEE_CAP_WEI, NET, account } from "./lib.js";

const ARTIFACT = fileURLToPath(new URL("../out/QVault.sol/QVault.json", import.meta.url));

async function main() {
  const guardian = process.argv[2] ?? ZeroAddress;
  if (!isAddress(guardian)) throw new Error("usage: npm run deploy -- [guardian 0x…]");
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as { abi: unknown[]; bytecode: { object: string } };

  const acc = await account();
  const wallet = new Wallet(acc.privateKey, new JsonRpcProvider(NET.evm));
  const nonce = await wallet.getNonce();
  const expected = getCreateAddress({ from: acc.evm, nonce });
  console.log(`owner     ${acc.evm}`);
  console.log(`guardian  ${guardian}`);
  console.log(`expected  ${expected} (nonce ${nonce})`);

  const factory = new ContractFactory(artifact.abi as never, artifact.bytecode.object, wallet);
  const vault = await factory.deploy(acc.evm, guardian, {
    nonce,
    gasLimit: 3_000_000n,
    maxFeePerGas: FEE_CAP_WEI,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  const tx = vault.deploymentTransaction();
  console.log(`tx        ${tx?.hash}`);
  await vault.waitForDeployment();
  const address = await vault.getAddress();
  console.log(`deployed  ${address}`);
  console.log(`owner()   ${await (vault as unknown as { owner(): Promise<string> }).owner()}`);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});

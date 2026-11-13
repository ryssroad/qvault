/**
 * drill.ts — set up and operate the QVault drill account on testnet (qorechain-diana).
 *
 * The account is eth-native (m/44'/60'/0'/0/0): one secp256k1 key = 0x… on the EVM lane and
 * qor1… on the native lane. Its ML-DSA-87 key is derived from the same MNEMONIC, so handing
 * the private key to the Q-Day Drill bot does NOT reveal the post-quantum key.
 *
 *   npm run drill new                 create secrets/drill.mnemonic (refuses to overwrite)
 *   npm run drill status              addresses, balance, PQC key (+ possession), window
 *   npm run drill register            register the ML-DSA-87 key WITH proof of possession
 *   npm run drill open-deploy         unscoped window, a few txs: deploy + fund the vault
 *   npm run drill open-drill <vault>  scoped window: only <vault>, budget for 2 txs
 *   npm run drill close               close the window (hybrid-signed)
 *   npm run drill key                 print the ECDSA private key (for the drill form ONLY)
 *
 * MNEMONIC_FILE overrides secrets/drill.mnemonic.
 */
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  buildRegisterPqcKeyMsg,
  closeEvmWindowMsg,
  fetchPqcStatus,
  generateMnemonic,
  isRegisteredPqcKey,
  openEvmWindowMsg,
  signProofOfPossession,
} from "@qorechain/sdk";
import { evmWindowCost, evmWindowStatus } from "@qorechain/evm";
import { FEE_CAP_WEI, MNEMONIC_FILE, NET, account, balanceUqor, broadcast } from "./lib.js";

// ------------------------------------------------------------------ commands

async function cmdNew(): Promise<void> {
  if (existsSync(MNEMONIC_FILE)) throw new Error(`${MNEMONIC_FILE} exists — refusing to overwrite`);
  mkdirSync(dirname(MNEMONIC_FILE), { recursive: true });
  writeFileSync(MNEMONIC_FILE, generateMnemonic(256) + "\n", { mode: 0o600 });
  chmodSync(MNEMONIC_FILE, 0o600);
  const acc = await account();
  console.log(`mnemonic -> ${MNEMONIC_FILE} (0600, gitignored)`);
  console.log(`evm:   ${acc.evm}`);
  console.log(`qor:   ${acc.cosmos}`);
  console.log("Next: fund the qor1 address from https://dashboard.qorechain.io/faucet, then `npm run drill register`.");
}

async function cmdStatus(): Promise<void> {
  const acc = await account();
  console.log(`evm:      ${acc.evm}`);
  console.log(`qor:      ${acc.cosmos}`);
  console.log(`balance:  ${await balanceUqor(acc.cosmos)} uqor`);
  const pqc = await fetchPqcStatus({ rest: NET.rest, address: acc.cosmos });
  if (!pqc.registered) {
    console.log("PQC key:  not registered (run: npm run drill register)");
  } else {
    const mine = isRegisteredPqcKey(pqc, acc.pqc.publicKey);
    console.log(
      `PQC key:  registered${mine === false ? " — NOT this key!" : ""}; possession proven: ${pqc.possessionProven}`,
    );
  }
  const w = await evmWindowStatus({ rest: NET.rest, address: acc.cosmos });
  if (!w.found) {
    console.log("window:   none");
  } else {
    console.log(
      `window:   ${w.live ? "LIVE" : "not usable"}; ${w.remainingBlocks} blocks, ${w.remainingTxs} txs, ` +
        `${w.remainingValue} uqor left; targets: ${w.allowedTargets.length ? w.allowedTargets.join(",") : "ANY"}`,
    );
  }
}

async function cmdRegister(): Promise<void> {
  const acc = await account();
  const pqc = await fetchPqcStatus({ rest: NET.rest, address: acc.cosmos });
  if (pqc.registered) {
    console.log(`Already registered; possession proven: ${pqc.possessionProven}`);
    return;
  }
  // The one message the chain accepts signed classically; the proof makes possessionProven = true,
  // which QVault requires (a key registered without it could be someone else's copied public key).
  const proofOfPossession = signProofOfPossession({ chainId: NET.chainId, account: acc.cosmos, keypair: acc.pqc });
  const msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession });
  console.log(`registered: ${await broadcast(acc, "classical", [msg])}`);
}

async function cmdOpenDeploy(): Promise<void> {
  const acc = await account();
  const blocks = 600n; // ~10 min on testnet
  const maxTxs = 4n; // deploy + fund + 2 spare
  const maxValue = evmWindowCost({ gas: 3_000_000n, maxFeePerGas: FEE_CAP_WEI }) * maxTxs +
    BigInt(process.env.FUND_UQOR ?? "0"); // + value you plan to send into the vault
  const msg = openEvmWindowMsg({ sender: acc.cosmos, blocks, maxTxs, maxValue });
  console.log(`opened: ${await broadcast(acc, "hybrid", [msg])}`);
  console.log(`window: ${blocks} blocks, ${maxTxs} txs, ${maxValue} uqor, targets ANY (deploy needs it)`);
  console.log("Nonce advanced; deploy now. Close it afterwards: npm run drill close");
}

async function cmdOpenDrill(vault: string | undefined): Promise<void> {
  if (!vault || !/^0x[0-9a-fA-F]{40}$/.test(vault)) throw new Error("usage: npm run drill open-drill <vault 0x…>");
  const acc = await account();
  const blocks = BigInt(process.env.DRILL_WINDOW_BLOCKS ?? "300"); // ~5 min: open, send, close
  const maxTxs = 2n;
  // Budget = fees for 2 withdrawals only. This is all an attacker holding the ECDSA key can burn.
  const maxValue = evmWindowCost({ gas: 600_000n, maxFeePerGas: FEE_CAP_WEI }) * maxTxs;
  const msg = openEvmWindowMsg({ sender: acc.cosmos, blocks, maxTxs, maxValue, allowedTargets: [vault] });
  console.log(`opened: ${await broadcast(acc, "hybrid", [msg])}`);
  console.log(`window: ${blocks} blocks, ${maxTxs} txs, ${maxValue} uqor, target ${vault} only`);
}

async function cmdClose(): Promise<void> {
  const acc = await account();
  console.log(`closed: ${await broadcast(acc, "hybrid", [closeEvmWindowMsg(acc.cosmos)])}`);
}

async function cmdKey(): Promise<void> {
  const acc = await account();
  console.error("ECDSA key of the DRILL account. It will be published after the drill. Never reuse this account.");
  console.log(acc.privateKey.replace(/^0x/, ""));
}

const commands: Record<string, (arg?: string) => Promise<void>> = {
  new: cmdNew,
  status: cmdStatus,
  register: cmdRegister,
  "open-deploy": cmdOpenDeploy,
  "open-drill": cmdOpenDrill,
  close: cmdClose,
  key: cmdKey,
};

const run = commands[process.argv[2] ?? "status"];
if (!run) {
  console.error(`Unknown command. Use: ${Object.keys(commands).join(" | ")}`);
  process.exit(1);
}
run(process.argv[3]).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});

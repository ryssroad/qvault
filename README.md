# QVault

![QVault](assets/cover.png)

**A vault that a leaked ECDSA key cannot drain.**

Built for [Build Before Q-Day](https://build.qorechain.io) — category **Post-Quantum dApp**, entered in the **Q-Day Drill**.

On Q-Day, every secp256k1 key on every chain becomes public. QoreChain already protects its Cosmos lane with mandatory hybrid (secp256k1 + ML-DSA-87) signatures, but an EVM transaction is still signed with secp256k1 alone: whoever holds the classical key can spend inside any open EVM window, and any contract that authorises by `msg.sender` belongs to them. QVault removes that path. Every operation that moves value or changes authority needs an **ML-DSA-87 signature by the key the chain itself holds for the owner**, verified on chain through the `pqcVerify` precompile. The classical key grants nothing.

## Threat model

| Attacker has | Can do against QVault |
|---|---|
| Owner's secp256k1 key (the Q-Day / drill scenario) | Send EVM txs as the owner **inside an open window** → no effect: no function trusts `msg.sender`. Burn at most the window's fee budget. |
| Their own valid ML-DSA-87 key | Nothing: signatures are checked against `pqcKeyStatus(owner)`, not a caller-supplied key. |
| Owner's **public** ML-DSA key registered on their own account | Nothing: QVault requires `possessionProven`, so a copied public key does not pass. |
| A valid owner signature seen in the mempool | Front-run the relay → same effect as the owner's intent: recipient, amount, token, nonce, deadline, chain id and vault address are all inside the signed digest. |
| Guardian's ML-DSA-87 key | Freeze withdrawals. Nothing else (cannot withdraw, unfreeze or change authority). |
| Owner's ML-DSA-87 key | Everything — the root of trust is the PQ key. Mitigation path: guardian freeze + timelocked large withdrawals (roadmap). |

Fail-closed: if the PQC precompiles are inactive (as on mainnet today), calls return empty data and every operation reverts.

## Design

```
            ML-DSA-87 sig over digest                    pqcKeyStatus(owner)  0x0A02
 owner ───────────────────────────────► any relayer ──► QVault ──────────────────────► chain PQC registry
 (PQ key off-chain)                     (any account)    │      pqcVerify(pub,sig,d) 0x0A01
                                                         └────────────────────────────► precompile
```

- `digest = keccak256(abi.encode("QVault.v1" domain, chainid, vault, op, nonce, deadline, payload))`, signed as its 32 raw bytes.
- Ops: `withdraw` (native QOR or ERC-20), `setOwner`, `setGuardian`, `freeze`, `unfreeze` — owner; `guardianFreeze` — guardian.
- Separate owner / guardian nonces: a guardian freeze never invalidates a pending owner signature.
- `setOwner` / `setGuardian` refuse accounts without a registered, possession-proven ML-DSA-87 key, so the vault cannot be bricked by a typo.
- Rotating the owner's key on chain (`MsgRotatePQCKey`) rotates it for the vault automatically — the vault never stores a key.

Gas: one `pqcVerify` is ~85k inside the precompile; a withdrawal tx is ~0.3M gas, dominated by the 4,627-byte signature in calldata.

## Q-Day Drill configuration

1. Fresh drill account (never held mainnet funds), ML-DSA-87 key registered **with proof of possession** (`possession_proven = true`).
2. Funds live in the vault; the drill account itself holds only fees.
3. The EVM window used during the drill is opened with `--allowed-targets <QVault>` and a `max-value` equal to a small fee budget. That bounds the only loss the attacker can cause (fees).
4. The required "normal transaction" during the drill is a PQ-signed withdrawal relayed through that window.

## Run

```sh
forge install foundry-rs/forge-std
forge test -vv         # 19 tests: leaked-ECDSA, replay, binding, guardian, fail-closed, fuzz
```

Testnet runbook (`qorechain-diana`, EVM chain id 9800):

```sh
cd client && npm install
npm run drill new                       # fresh eth-native account -> secrets/drill.mnemonic (gitignored)
# fund the printed qor1 address from https://dashboard.qorechain.io/faucet
npm run drill register                  # ML-DSA-87 key WITH proof of possession
npm run drill status                    # must say: possession proven: true

FUND_UQOR=5000000 npm run drill open-deploy   # unscoped window (deploy needs it) + 5 QOR budget to fund
# deploy with ethers (client/deploy.ts): forge script simulates without the 0x0A02 precompile, and
# forge create misreads QoreChain receipts (missing field feePayer) and reports a successful deploy as failed.
forge build && cd client && npm run deploy && cd ..
cast send <vault> --value 5ether --rpc-url qore_testnet --private-key 0x$(cd client && npm run -s drill key 2>/dev/null)
cd client && npm run drill close        # no window left open: the ECDSA key alone can do nothing

# during the drill: the one "normal transaction"
npm run drill open-drill <vault>        # target = vault only, budget = fees of 2 txs
npm run withdraw -- <vault> <to> 1000000000000000000
npm run drill close
```

## Status

- [x] Contract + tests against precompile mocks (real ABI from qorechain-core `docs/EVM_PRECOMPILES.md`)
- [x] Withdraw client (`client/withdraw.ts`) and drill-account tool (`client/drill.ts`: key registration with proof of possession, deploy window, vault-only drill window, close) — run against testnet
- [x] Testnet deployment: QVault `0x5a7f65d0573be384f64351f30a616ed48dca3015`, funded, first ML-DSA-87-authorised withdrawal `status 1`
- [ ] Q-Day Drill registration
- [ ] Guardian agent: watches the vault and the owner account, freezes on anomaly
- [ ] Timelock for withdrawals above a threshold, cancellable by guardian
- [ ] Web UI

## Credits

- [`forge-std`](https://github.com/foundry-rs/forge-std) — Foundry test library (MIT/Apache-2.0)
- [`@qorechain/pqc`](https://www.npmjs.com/package/@qorechain/pqc) — ML-DSA-87 signing (Apache-2.0)
- [`@qorechain/sdk`](https://www.npmjs.com/package/@qorechain/sdk), [`@qorechain/evm`](https://www.npmjs.com/package/@qorechain/evm) — eth-native account, hybrid signing, EVM window (Apache-2.0)
- `client/drill.ts` follows the window helper of [build-before-qday](https://github.com/qorechain/build-before-qday) workshop 1 (`scripts/window.ts`)
- [`@cosmjs/stargate`](https://github.com/cosmos/cosmjs) — native-lane transport (Apache-2.0)
- [`ethers`](https://github.com/ethers-io/ethers.js) — EVM client (MIT)
- `IQorePQC` interface follows [qorechain-core](https://github.com/qorechain/qorechain-core) `contracts/interfaces/IQorePQC.sol` (Apache-2.0)

Built with AI coding assistants; see `AI_USAGE.md` (to be added).

## License

Apache-2.0

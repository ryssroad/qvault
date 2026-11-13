// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {QVault} from "../src/QVault.sol";

/// forge script script/DeployQVault.s.sol --rpc-url qore_testnet --broadcast \
///   --private-key $DEPLOYER_KEY
/// env: QVAULT_OWNER (EVM address with a registered, possession-proven ML-DSA-87 key)
///      QVAULT_GUARDIAN (same requirement, or 0x0 for none)
/// The deployer needs an open EVM window; it does not need to be the owner.
/// NOTE: on QoreChain use `npm run deploy` in client/ instead: forge script first runs the script in a
/// local EVM that has no 0x0A02 precompile, so the constructor's key check reverts there, and
/// forge create misreads QoreChain receipts (see README).
contract DeployQVault is Script {
    function run() external returns (QVault vault) {
        address owner = vm.envAddress("QVAULT_OWNER");
        address guardian = vm.envOr("QVAULT_GUARDIAN", address(0));
        vm.startBroadcast();
        vault = new QVault(owner, guardian);
        vm.stopBroadcast();
        console2.log("QVault", address(vault));
    }
}

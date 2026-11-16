// The hand-written V2_ABI must match the compiled contract (run `forge build` first).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Interface } from "ethers";
import { V2_ABI } from "./v2.js";

const artifact = fileURLToPath(new URL("../out/QVaultV2.sol/QVaultV2.json", import.meta.url));

test("V2_ABI functions and events exist in the compiled QVaultV2 with the same signatures", { skip: !existsSync(artifact) }, () => {
  const compiled = new Interface(JSON.parse(readFileSync(artifact, "utf8")).abi);
  const mine = new Interface(V2_ABI);
  mine.forEachFunction((f) => {
    const c = compiled.getFunction(f.selector);
    assert.ok(c, `function ${f.format()} is not in the contract`);
    assert.equal(c.outputs.map((o) => o.type).join(), f.outputs.map((o) => o.type).join(), `outputs of ${f.name}`);
  });
  mine.forEachEvent((e) => {
    const c = compiled.getEvent(e.topicHash);
    assert.ok(c, `event ${e.format()} is not in the contract`);
    assert.equal(c.inputs.map((i) => !!i.indexed).join(), e.inputs.map((i) => !!i.indexed).join(), `indexed of ${e.name}`);
  });
});

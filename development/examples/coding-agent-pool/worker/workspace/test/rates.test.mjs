import { test } from "node:test";
import assert from "node:assert/strict";
import { applyRate } from "../src/rates.mjs";

test("applyRate treats the rate as a percentage", () => {
  assert.equal(applyRate(100, 15), 15);
  assert.equal(applyRate(250, 8), 20);
});

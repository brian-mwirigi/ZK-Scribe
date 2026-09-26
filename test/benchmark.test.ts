import assert from "node:assert/strict";
import { test } from "node:test";
import { rangeBenchmark } from "../src/crypto/benchmark.ts";

test("range benchmark returns a finite duration", () => {
  const result = rangeBenchmark();
  assert.equal(Number.isFinite(result.milliseconds), true);
  assert.equal(result.milliseconds >= 0, true);
  assert.equal(result.low, 0);
  assert.equal(result.high, 15);
  assert.equal(result.bits > 0, true);
});

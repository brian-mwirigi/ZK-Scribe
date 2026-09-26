import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalHash } from "../src/canon.ts";

const FIXTURE = "b60b53dd3093986a638a05318f33cf3f476d5a136895fc0aa02ea25dd3015ac5";

test("canonical hash of a fixed object stays stable across key order", () => {
  const left = canonicalHash({ b: 1, a: { z: true, y: [2, 1] } });
  const right = canonicalHash({ a: { y: [2, 1], z: true }, b: 1 });
  assert.equal(left, FIXTURE);
  assert.equal(right, FIXTURE);
});

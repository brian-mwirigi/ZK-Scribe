import assert from "node:assert/strict";
import { test } from "node:test";
import { isRevoked, parseRevocationList } from "../src/cva/revocation.ts";

test("revocation matching ignores case, 0x, and spaces", () => {
  const key = "abcd".repeat(16);
  assert.equal(isRevoked(`0x${key.toUpperCase()}`, [key.slice(0, 8) + " " + key.slice(8)]), true);
  assert.equal(isRevoked(key, ["ff".repeat(32)]), false);
  assert.deepEqual(parseRevocationList({ publicKeys: [key] }), [key]);
  assert.throws(() => parseRevocationList({ publicKeys: [1] }));
});

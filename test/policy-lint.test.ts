import assert from "node:assert/strict";
import { test } from "node:test";
import { lintPolicy } from "../src/cva/lint.ts";
import { defaultPolicy } from "../src/cva/policy.ts";

test("the default policy passes lint and a leaky policy does not", () => {
  assert.equal(lintPolicy(defaultPolicy()).ok, true);
  const leaky = defaultPolicy();
  leaky.deny = leaky.deny.filter((action) => action !== "export.witness");
  const lint = lintPolicy(leaky);
  assert.equal(lint.ok, false);
  assert.match(lint.findings.join(" "), /export\.witness/);
});

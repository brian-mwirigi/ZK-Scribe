import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLedger } from "../src/ledger/combine.ts";
import type { PublisherSummary } from "../src/manifest/summary.ts";

test("a ledger counts distinct role bindings for one manuscript", () => {
  const writing = entry("process-proven", "writing-original-draft");
  const funding = entry("signed-assertion", "funding-acquisition");
  const ledger = buildLedger([writing, writing, funding]);
  assert.equal(ledger.entries.length, 2);
  assert.equal(ledger.counts.processProven, 1);
  assert.equal(ledger.counts.signedAssertion, 1);
});

function entry(binding: string, role: string): PublisherSummary {
  return {
    version: "zk-scribe-summary/0.1.0",
    sessionId: "s",
    contentHash: "ab".repeat(32),
    swfHead: "cd".repeat(32),
    label: "composition",
    role,
    binding,
    feasibility: "high",
    action: "attest.process",
    agentPublicKey: "ee".repeat(32),
  };
}

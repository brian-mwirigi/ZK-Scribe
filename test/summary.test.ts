import assert from "node:assert/strict";
import { test } from "node:test";
import { toSummary } from "../src/manifest/summary.ts";
import type { Attestation } from "../src/pop/attest.ts";

test("the publisher summary omits proofs, commitments, and the policy body", () => {
  const summary = toSummary(sample());
  const encoded = JSON.stringify(summary);
  assert.equal(encoded.includes("rangeProofs"), false);
  assert.equal(encoded.includes("openings"), false);
  assert.equal(summary.binding, "process-proven");
  assert.equal(summary.contentHash, "ab".repeat(32));
});

function sample(): Attestation {
  return {
    version: "zk-scribe/0.1.0",
    statement: {
      version: "zk-scribe/0.1.0",
      sessionId: "example",
      contentHash: "ab".repeat(32),
      swfHead: "cd".repeat(32),
      label: "composition",
      assertion: "",
      counts: { eventCount: 1, durationMs: 9000, insertChars: 30, deleteChars: 2, bulkInsertEvents: 0 },
      role: {
        id: "writing-original-draft",
        name: "Writing – original draft",
        feasibility: "high",
        binding: "process-proven",
        detail: "Human composition bounds hold.",
      },
      context: { environment: "local", revision: "uncommitted", subject: "draft.md" },
      proofSystem: {
        commitments: "pedersen-secp256k1-v1",
        range: "sigma-bit-or-v1",
        sequentialWork: "hash-chain-v1",
        agentAuthorization: "ed25519-cva-v1",
      },
    },
    policy: {
      version: "zk-scribe-policy/0.1.0",
      id: "local-author",
      allow: ["attest.process"],
      deny: ["export.witness"],
      note: "test",
    },
    commitments: { medianIkiMs: "02" + "11".repeat(32) },
    rangeProofs: null,
    cva: { action: "attest.process", agentPublicKey: "ee".repeat(32), signature: "ff".repeat(64) },
  };
}

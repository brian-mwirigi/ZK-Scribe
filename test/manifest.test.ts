import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalHash } from "../src/canon.ts";
import { defaultPolicy } from "../src/cva/policy.ts";
import { toProvenanceManifest } from "../src/manifest/export.ts";
import { PROOF_SYSTEM, type Attestation } from "../src/pop/attest.ts";

test("manifest envelope repeats the content and statement hashes", () => {
  const attestation = {
    version: "zk-scribe/0.1.0",
    statement: {
      version: "zk-scribe/0.1.0",
      sessionId: "s",
      contentHash: "ab".repeat(32),
      swfHead: "cd".repeat(32),
      label: "indeterminate",
      assertion: "I contributed the idea.",
      counts: { eventCount: 0, durationMs: 0, insertChars: 0, deleteChars: 0, bulkInsertEvents: 0 },
      role: {
        id: "conceptualization",
        name: "Conceptualization",
        feasibility: "unobserved",
        binding: "signed-assertion",
        detail: "signed",
      },
      context: { environment: "local", revision: "uncommitted", subject: "note.md" },
      proofSystem: PROOF_SYSTEM,
    },
    policy: defaultPolicy(),
    commitments: {},
    rangeProofs: null,
    cva: {
      action: "attest.assert",
      agentPublicKey: "ee".repeat(32),
      signature: "11".repeat(64),
    },
  } satisfies Attestation;
  const manifest = toProvenanceManifest(attestation);
  assert.equal(manifest.contentHash, attestation.statement.contentHash);
  assert.equal(manifest.statementHash, canonicalHash(attestation.statement));
  assert.equal(manifest.assertions.some((item) => item.label === "c2pa.ai-disclosure"), true);
  const nested = manifest.assertions.find((item) => item.label === "zk-scribe.process-attestation") as
    | { label: string; data: { statementHash: string } }
    | undefined;
  assert.ok(nested);
  assert.equal(nested.data.statementHash, manifest.statementHash);
});

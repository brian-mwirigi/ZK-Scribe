import assert from "node:assert/strict";
import { test } from "node:test";
import { escapeHtml, toHtmlReport } from "../src/manifest/html.ts";
import type { Attestation } from "../src/pop/attest.ts";

test("the html report escapes markup and shows the binding", () => {
  assert.equal(escapeHtml(`a<b>&"'`), "a&lt;b&gt;&amp;&quot;'");
  const html = toHtmlReport(sample());
  assert.match(html, /process-proven/);
  assert.match(html, new RegExp("ab".repeat(32)));
  assert.equal(html.includes("<script>"), false);
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
      counts: { eventCount: 1, durationMs: 9000, insertChars: 30, deleteChars: 1, bulkInsertEvents: 0 },
      role: {
        id: "writing-original-draft",
        name: "Writing – original draft",
        feasibility: "high",
        binding: "process-proven",
        detail: "ok",
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
      allow: ["export.manifest"],
      deny: ["export.witness"],
      note: "test",
    },
    commitments: {},
    rangeProofs: null,
    cva: { action: "attest.process", agentPublicKey: "ee".repeat(32), signature: "ff".repeat(64) },
  };
}

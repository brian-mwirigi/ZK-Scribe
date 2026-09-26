import assert from "node:assert/strict";
import { test } from "node:test";
import { isRevoked, parseRevocationList } from "../src/cva/revocation.ts";
import { defaultPolicy } from "../src/cva/policy.ts";
import { encodeKey, generateAgentKey } from "../src/keys.ts";
import { PROOF_SYSTEM, verify, type Attestation } from "../src/pop/attest.ts";

test("revocation matching ignores case, 0x, and spaces", () => {
  const key = "abcd".repeat(16);
  assert.equal(isRevoked(`0x${key.toUpperCase()}`, [key.slice(0, 8) + " " + key.slice(8)]), true);
  assert.equal(isRevoked(key, ["ff".repeat(32)]), false);
  assert.deepEqual(parseRevocationList({ publicKeys: [key] }), [key]);
  assert.throws(() => parseRevocationList({ publicKeys: [1] }));
});

test("verify reports a revoked agent key", () => {
  const key = generateAgentKey();
  const hex = encodeKey(key.publicKey);
  const policy = defaultPolicy();
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
    policy,
    commitments: {},
    rangeProofs: null,
    cva: {
      action: "attest.assert",
      agentPublicKey: hex,
      signature: "11".repeat(64),
    },
  } satisfies Attestation;
  const result = verify(attestation, {
    trustedAgentKey: hex,
    expectedPolicy: policy,
    revokedKeys: [`0x${hex.toUpperCase()}`],
  });
  assert.equal(result.reasons.includes("Agent key is revoked."), true);
  assert.equal(result.ok, false);
});


import assert from "node:assert/strict";
import { test } from "node:test";
import { authorEndorsementValid, endorseStatement } from "../src/author/endorse.ts";
import { defaultPolicy } from "../src/cva/policy.ts";
import { encodeKey, generateAgentKey } from "../src/keys.ts";
import { attest, verify } from "../src/pop/attest.ts";
import { sha256Hex, utf8 } from "../src/canon.ts";

test("an author endorsement binds one statement hash", () => {
  const author = generateAgentKey();
  const hash = "ab".repeat(32);
  const endorsement = endorseStatement(hash, author.secretKey);
  assert.equal(authorEndorsementValid(hash, endorsement), true);
  assert.equal(authorEndorsementValid("cd".repeat(32), endorsement), false);
  const tampered = { ...endorsement, signature: "00".repeat(64) };
  assert.equal(authorEndorsementValid(hash, tampered), false);
});

test("verify requires the author endorsement when the agent signature covers it", () => {
  const agent = generateAgentKey();
  const author = generateAgentKey();
  const policy = defaultPolicy();
  const { attestation } = attest({
    role: "funding-acquisition",
    contentHash: sha256Hex(utf8("grant")),
    context: { environment: "local", revision: "uncommitted", subject: "grant.md" },
    policy,
    agentSecretKey: agent.secretKey,
    authorSecretKey: author.secretKey,
    assertion: "The named grant paid for the study.",
  });
  const options = {
    trustedAgentKey: encodeKey(agent.publicKey),
    expectedPolicy: policy,
    requireAuthor: true,
  };
  assert.equal(verify(attestation, options).ok, true);
  const stripped = { ...attestation };
  delete stripped.author;
  assert.equal(verify(stripped, options).signatureValid, false);
});

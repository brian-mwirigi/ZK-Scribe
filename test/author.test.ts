import assert from "node:assert/strict";
import { test } from "node:test";
import { authorEndorsementValid, endorseStatement } from "../src/author/endorse.ts";
import { generateAgentKey } from "../src/keys.ts";

test("an author endorsement binds one statement hash", () => {
  const author = generateAgentKey();
  const hash = "ab".repeat(32);
  const endorsement = endorseStatement(hash, author.secretKey);
  assert.equal(authorEndorsementValid(hash, endorsement), true);
  assert.equal(authorEndorsementValid("cd".repeat(32), endorsement), false);
  const tampered = { ...endorsement, signature: "00".repeat(64) };
  assert.equal(authorEndorsementValid(hash, tampered), false);
});

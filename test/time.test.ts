import assert from "node:assert/strict";
import { test } from "node:test";
import { sha256Hex, utf8 } from "../src/canon.ts";
import { defaultPolicy } from "../src/cva/policy.ts";
import { generateAgentKey } from "../src/keys.ts";
import { attest } from "../src/pop/attest.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";
import { sequentialWorkHead } from "../src/pop/swf.ts";
import { QUICKNET, chainDomain, coverageProblem, fetchLatest, roundUnix, verifyRound } from "../src/time/drand.ts";

const context = {
  environment: "local" as const,
  revision: "uncommitted",
  subject: "examples/manuscript.md",
};

test("a beacon window must cover the session duration", () => {
  const startedAt = new Date(roundUnix(1_000) * 1000).toISOString();
  assert.equal(coverageProblem(1_000, 1_000, 1, startedAt), "Time beacon window is empty.");
  assert.equal(coverageProblem(1_000, 1_001, 20_000, startedAt), "Time beacon window is shorter than the session.");
  assert.equal(coverageProblem(1_000, 1_010, 1_000, "2020-01-01T00:00:00.000Z"), "Session start is outside the time beacon window.");
  assert.equal(coverageProblem(1_000, 1_010, 1_000, startedAt), null);
});

test("a time beacon changes the hash-chain head", () => {
  const session = synthesizeSession("transcription");
  const hash = "ab".repeat(32);
  const plain = sequentialWorkHead(session, hash);
  const domain = chainDomain({
    scheme: "drand-quicknet-v1",
    startedAt: session.startedAt,
    start: { chain: QUICKNET.hash, round: 3, signature: "aa".repeat(48) },
    end: { chain: QUICKNET.hash, round: 9, signature: "bb".repeat(48) },
  });
  assert.notEqual(sequentialWorkHead(session, hash, domain), plain);
});

test("a bad beacon signature is refused before a proof is issued", () => {
  const session = synthesizeSession("paste");
  session.timeAnchor = {
    scheme: "drand-quicknet-v1",
    startedAt: session.startedAt,
    start: { chain: QUICKNET.hash, round: 1, signature: "ab".repeat(48) },
    end: { chain: QUICKNET.hash, round: 2, signature: "cd".repeat(48) },
  };
  assert.throws(
    () =>
      attest({
        role: "writing-original-draft",
        contentHash: sha256Hex(utf8("fixture\n")),
        context,
        policy: defaultPolicy(),
        agentSecretKey: generateAgentKey().secretKey,
        session,
      }),
    /Time beacon signature is invalid/,
  );
});

test("quicknet latest round verifies locally", { timeout: 20_000 }, async () => {
  const round = await fetchLatest();
  assert.equal(round.chain, QUICKNET.hash);
  assert.equal(verifyRound(round), true);
  const flipped = round.signature.endsWith("a") ? "b" : "a";
  const broken = { ...round, signature: `${round.signature.slice(0, -1)}${flipped}` };
  assert.equal(verifyRound(broken), false);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { commit, randomScalar } from "../src/crypto/group.ts";
import { bitsForSpan, proveInterval, verifyInterval } from "../src/crypto/range.ts";
import { Transcript } from "../src/crypto/transcript.ts";

test("pedersen commitments hide the message and bind the opening", () => {
  const message = 42n;
  const first = randomScalar();
  const second = randomScalar();
  const committed = commit(message, first);
  assert.equal(committed.equals(commit(message, first)), true);
  assert.equal(committed.equals(commit(message, second)), false);
  assert.equal(committed.equals(commit(43n, first)), false);
});

test("sigma range proof accepts an in-range value and rejects tampering", () => {
  const value = 7n;
  const blinding = randomScalar();
  const transcript = new Transcript("range-ok");
  const proof = proveInterval({
    value,
    blinding,
    low: 3n,
    high: 20n,
    transcript,
  });
  const check = new Transcript("range-ok");
  assert.equal(
    verifyInterval({
      commitment: commit(value, blinding),
      low: 3n,
      high: 20n,
      proof,
      transcript: check,
    }),
    true,
  );

  const tampered = structuredClone(proof);
  tampered.low[0].z0 = tampered.low[0].z0.replace(/[0-9a-f]/i, (digit) => (digit === "a" ? "b" : "a"));
  const rejected = new Transcript("range-ok");
  assert.equal(
    verifyInterval({
      commitment: commit(value, blinding),
      low: 3n,
      high: 20n,
      proof: tampered,
      transcript: rejected,
    }),
    false,
  );
});

test("range proof refuses a witness outside the interval", () => {
  assert.throws(() =>
    proveInterval({
      value: 4n,
      blinding: randomScalar(),
      low: 10n,
      high: 12n,
      transcript: new Transcript("outside"),
    }),
  );
});

test("a proof for one interval does not verify against another", () => {
  const value = 7n;
  const blinding = randomScalar();
  const proof = proveInterval({
    value,
    blinding,
    low: 0n,
    high: 15n,
    transcript: new Transcript("bound"),
  });
  assert.equal(
    verifyInterval({
      commitment: commit(value, blinding),
      low: 0n,
      high: 8n,
      proof,
      transcript: new Transcript("bound"),
    }),
    false,
  );
});

test("zero-width ranges and span bit counts are stable", () => {
  assert.equal(bitsForSpan(0n), 0);
  assert.equal(bitsForSpan(1n), 1);
  assert.equal(bitsForSpan(2n), 2);
  const blinding = randomScalar();
  const proof = proveInterval({
    value: 5n,
    blinding,
    low: 5n,
    high: 5n,
    transcript: new Transcript("point"),
  });
  assert.equal(proof.bits, 0);
  assert.equal(proof.low.length, 0);
  assert.equal(
    verifyInterval({
      commitment: commit(5n, blinding),
      low: 5n,
      high: 5n,
      proof,
      transcript: new Transcript("point"),
    }),
    true,
  );
});

test("swapped commitments fail verification", () => {
  const blinding = randomScalar();
  const proof = proveInterval({
    value: 9n,
    blinding,
    low: 0n,
    high: 16n,
    transcript: new Transcript("swap"),
  });
  assert.equal(
    verifyInterval({
      commitment: commit(8n, blinding),
      low: 0n,
      high: 16n,
      proof,
      transcript: new Transcript("swap"),
    }),
    false,
  );
});

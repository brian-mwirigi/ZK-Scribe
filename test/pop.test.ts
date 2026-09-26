import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Hex, utf8 } from "../src/canon.ts";
import { eventFromKey } from "../src/capture/keys.ts";
import { CREDIT_ROLES } from "../src/credit/taxonomy.ts";
import { assertActionAllowed, defaultPolicy } from "../src/cva/policy.ts";
import { encodeKey, generateAgentKey } from "../src/keys.ts";
import { toJats, toProvenanceManifest } from "../src/manifest/export.ts";
import { attest, audit, verify } from "../src/pop/attest.ts";
import { extract } from "../src/pop/extract.ts";
import { regionsOverlap, REGIONS } from "../src/pop/regions.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";
import { sequentialWorkHead } from "../src/pop/swf.ts";

const context = {
  environment: "local" as const,
  revision: "uncommitted",
  subject: "examples/manuscript.md",
};

test("acceptance regions do not overlap", () => {
  assert.equal(regionsOverlap(REGIONS.composition, REGIONS.transcription), false);
  assert.equal(regionsOverlap(REGIONS.composition, REGIONS.automated), false);
  assert.equal(regionsOverlap(REGIONS.transcription, REGIONS.automated), false);
});

test("synthetic sessions land in the expected regions", () => {
  assert.equal(extract(synthesizeSession("composition")).label, "composition");
  assert.equal(extract(synthesizeSession("transcription")).label, "transcription");
  assert.equal(extract(synthesizeSession("automated")).label, "automated");
  assert.equal(extract(synthesizeSession("paste")).label, "automated");
  assert.equal(extract(synthesizeSession("paste")).bulkInsertEvents, 1);
});

test("sequential work head changes when event order changes", () => {
  const session = synthesizeSession("transcription");
  const hash = "ab".repeat(32);
  const head = sequentialWorkHead(session, hash);
  const swapped = {
    ...session,
    events: [session.events[1], session.events[0], ...session.events.slice(2)],
  };
  assert.notEqual(sequentialWorkHead(swapped, hash), head);
  assert.notEqual(sequentialWorkHead(session, "cd".repeat(32)), head);
});

test("capture keeps characters out of the timing event", () => {
  const step = eventFromKey({ name: "a", sequence: "a" }, 120);
  assert.equal(step.kind, "event");
  if (step.kind !== "event") return;
  assert.deepEqual(step.event, { t: 120, op: "insert", len: 1, boundary: false });
  assert.equal(step.textDelta, "a");
  assert.equal(eventFromKey({ ctrl: true, name: "d" }, 1).kind, "finish");
  assert.equal(eventFromKey({ ctrl: true, name: "c" }, 1).kind, "abort");
  const pasted = eventFromKey({ sequence: "x".repeat(20) }, 5);
  assert.equal(pasted.kind, "event");
  if (pasted.kind === "event") assert.equal(pasted.event.op, "paste");
});

test("policy refuses raw export", () => {
  assert.throws(() => assertActionAllowed(defaultPolicy(), "export.raw-events"));
  assert.throws(() => assertActionAllowed(defaultPolicy(), "export.witness"));
});

test("composition attestation verifies, audits, and hides the witness", () => {
  const key = generateAgentKey();
  const policy = defaultPolicy();
  const session = synthesizeSession("composition");
  const contentHash = sha256Hex(utf8("A short methods paragraph for the fixture.\n"));
  const { attestation, witness } = attest({
    role: "writing-original-draft",
    contentHash,
    context,
    policy,
    agentSecretKey: key.secretKey,
    session,
  });
  assert.ok(witness);
  assert.equal(attestation.statement.role.binding, "process-proven");
  assert.equal(JSON.stringify(attestation).includes("\"events\""), false);
  assert.equal(JSON.stringify(attestation).includes(witness.openings.medianIkiMs?.blinding ?? "missing"), false);

  const options = { trustedAgentKey: encodeKey(key.publicKey), expectedPolicy: policy };
  const restored = JSON.parse(JSON.stringify(attestation));
  const result = verify(restored, options);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.ok, true);

  const audited = audit(attestation, session, witness);
  assert.deepEqual(audited.reasons, []);
  assert.equal(audited.ok, true);
  assert.equal(audit(attestation, synthesizeSession("transcription"), witness).ok, false);

  const untrusted = verify(restored, {
    trustedAgentKey: encodeKey(generateAgentKey().publicKey),
    expectedPolicy: policy,
  });
  assert.equal(untrusted.identityTrusted, false);
  assert.equal(untrusted.ok, false);

  const tampered = structuredClone(restored);
  tampered.statement.role.binding = "process-proven";
  tampered.cva.signature = "ab".repeat(64);
  const broken = verify(tampered, options);
  assert.equal(broken.signatureValid, false);
  assert.equal(broken.ok, false);

  const manifest = toProvenanceManifest(attestation);
  assert.equal(manifest.assertions.some((assertion) => assertion.label === "c2pa.ai-disclosure"), true);
  assert.match(toJats(attestation), /writing-original-draft/);
  assert.match(toJats(attestation), new RegExp(contentHash));
});

test("typed code is not upgraded into a writing proof", () => {
  const key = generateAgentKey();
  const session = synthesizeSession("composition");
  const { attestation } = attest({
    role: "software",
    contentHash: sha256Hex(utf8("code fixture\n")),
    context,
    policy: defaultPolicy(),
    agentSecretKey: key.secretKey,
    session,
  });
  assert.equal(attestation.statement.role.binding, "typed-artifact");
  const result = verify(attestation, {
    trustedAgentKey: encodeKey(key.publicKey),
    expectedPolicy: defaultPolicy(),
    require: "process-proven",
  });
  assert.equal(result.ok, false);
  assert.equal(result.proofsValid, true);
});

test("steady transcription and bulk paste cannot prove a writing role", () => {
  const key = generateAgentKey();
  const policy = defaultPolicy();
  for (const kind of ["transcription", "automated", "paste"] as const) {
    const { attestation } = attest({
      role: "writing-review-editing",
      contentHash: sha256Hex(utf8(kind)),
      context,
      policy,
      agentSecretKey: key.secretKey,
      session: synthesizeSession(kind),
    });
    assert.equal(attestation.statement.role.binding, "unsupported");
    assert.equal(attestation.rangeProofs, null);
    const result = verify(attestation, {
      trustedAgentKey: encodeKey(key.publicKey),
      expectedPolicy: policy,
    });
    assert.equal(result.ok, false);
    assert.equal(result.signatureValid, true);
  }
});

test("unobserved roles are signed claims, not process proofs", () => {
  const key = generateAgentKey();
  const policy = defaultPolicy();
  assert.throws(() =>
    attest({
      role: "funding-acquisition",
      contentHash: sha256Hex(utf8("grant")),
      context,
      policy,
      agentSecretKey: key.secretKey,
      session: synthesizeSession("composition"),
    }),
  );
  const { attestation, witness } = attest({
    role: "funding-acquisition",
    contentHash: sha256Hex(utf8("grant")),
    context,
    policy,
    agentSecretKey: key.secretKey,
    assertion: "The named grant paid for the study.",
  });
  assert.equal(witness, null);
  assert.equal(attestation.statement.role.binding, "signed-assertion");
  const accepted = verify(attestation, {
    trustedAgentKey: encodeKey(key.publicKey),
    expectedPolicy: policy,
  });
  assert.equal(accepted.ok, true);
  const required = verify(attestation, {
    trustedAgentKey: encodeKey(key.publicKey),
    expectedPolicy: policy,
    require: "process",
  });
  assert.equal(required.ok, false);
});

test("the vocabulary covers the fourteen CRediT roles", () => {
  assert.equal(CREDIT_ROLES.length, 14);
  assert.equal(new Set(CREDIT_ROLES.map((role) => role.id)).size, 14);
});

test("cli init and example write a local project", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-"));
  const init = run(["init", "--dir", dir], dir);
  assert.equal(init.status, 0, init.stderr);
  assert.equal(fs.existsSync(path.join(dir, ".zk-scribe", "private", "agent.seed")), true);
  assert.equal(fs.existsSync(path.join(dir, ".zk-scribe", "agent.public.json")), true);
  const sessionPath = path.join(dir, "composition.json");
  const example = run(["example", "--kind", "composition", "--out", sessionPath], dir);
  assert.equal(example.status, 0, example.stderr);
  assert.equal(extract(JSON.parse(fs.readFileSync(sessionPath, "utf8"))).label, "composition");
  fs.writeFileSync(path.join(dir, "manuscript.md"), "A short methods paragraph for the fixture.\n");
  const attested = run(
    ["attest", "--dir", dir, "--session", "composition.json", "--file", "manuscript.md", "--role", "writing-original-draft"],
    dir,
  );
  assert.equal(attested.status, 0, `${attested.stdout}\n${attested.stderr}`);
  const verified = run(["verify", "attestation.json", "--dir", dir, "--require", "process-proven"], dir);
  assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
  assert.match(verified.stdout, /"ok": true/);
  const credit = run(["credit"], dir);
  assert.match(credit.stdout, /writing-original-draft/);
});

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function run(args: string[], cwd: string) {
  return spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args], {
    cwd,
    encoding: "utf8",
  });
}

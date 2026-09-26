import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { govern } from "../src/cva/govern.ts";
import { hashGrant, issueGrant } from "../src/cva/grant.ts";
import { appendJournal, auditJournal } from "../src/cva/journal.ts";
import { defaultPolicy } from "../src/cva/policy.ts";
import { encodeKey, generateAgentKey } from "../src/keys.ts";
import { attest, verify } from "../src/pop/attest.ts";

test("a grant cannot widen the policy or move onto another manuscript", () => {
  const agent = generateAgentKey();
  const author = generateAgentKey();
  const policy = defaultPolicy();
  const agentPublicKey = encodeKey(agent.publicKey);
  const contentHash = "ab".repeat(32);
  const grant = issueGrant({
    agentPublicKey,
    policy,
    actions: ["attest.assert", "export.raw-events"],
    contentHash,
    authorSecretKey: author.secretKey,
  });
  const widened = govern({
    action: "export.raw-events",
    agentPublicKey,
    policy,
    contentHash,
    grant,
  });
  assert.equal(widened.allow, false);
  const moved = govern({
    action: "attest.assert",
    agentPublicKey,
    policy,
    contentHash: "cd".repeat(32),
    grant,
  });
  assert.equal(moved.reasons.includes("Grant is for a different manuscript."), true);

  const { attestation } = attest({
    role: "conceptualization",
    contentHash,
    context: { environment: "local", revision: "uncommitted", subject: "note.md" },
    policy,
    agentSecretKey: agent.secretKey,
    assertion: "I contributed the idea.",
    grantHash: hashGrant(grant),
  });
  const checked = verify(attestation, {
    trustedAgentKey: agentPublicKey,
    expectedPolicy: policy,
    grant,
  });
  assert.equal(checked.ok, true, checked.reasons.join("\n"));
  const stripped = { ...attestation };
  delete stripped.grantHash;
  const required = verify(stripped, {
    trustedAgentKey: agentPublicKey,
    expectedPolicy: policy,
    requireGrant: true,
  });
  assert.equal(required.ok, false);
  assert.equal(required.reasons.includes("A grant binding is required."), true);
});

test("an edited journal entry fails the chain", () => {
  const agent = generateAgentKey();
  const draft = {
    action: "attest.assert",
    agentPublicKey: encodeKey(agent.publicKey),
    contentHash: "ab".repeat(32),
    policyHash: "11".repeat(32),
    grantHash: null as string | null,
    allow: true,
    reasons: [] as string[],
    agentSecretKey: agent.secretKey,
  };
  const entries = appendJournal(appendJournal([], draft), { ...draft, action: "export.manifest" });
  assert.equal(auditJournal(entries).ok, true);
  const edited = entries.map((entry, index) => (index === 0 ? { ...entry, allow: false } : entry));
  assert.equal(auditJournal(edited).ok, false);
});

test("a project grant blocks a changed manuscript and keeps a valid journal", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-grant-"));
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const run = (args: string[]) =>
    spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args, "--dir", dir], {
      cwd: dir,
      encoding: "utf8",
    });
  const initialized = run(["init"]);
  assert.equal(initialized.status, 0, initialized.stderr);
  fs.writeFileSync(path.join(dir, "note.md"), "idea\n");
  fs.writeFileSync(path.join(dir, "author.seed"), `${encodeKey(generateAgentKey().secretKey)}\n`);
  const granted = run(["grant", "--file", "note.md", "--actions", "attest.assert", "--author-seed", "author.seed"]);
  assert.equal(granted.status, 0, granted.stderr);
  const attested = run([
    "attest",
    "--file",
    "note.md",
    "--role",
    "conceptualization",
    "--assert",
    "I contributed the idea.",
  ]);
  assert.equal(attested.status, 0, attested.stderr);
  const verified = run(["verify", "attestation.json", "--grant", path.join(".zk-scribe", "grant.json")]);
  assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
  fs.writeFileSync(path.join(dir, "note.md"), "different idea\n");
  const blocked = run([
    "attest",
    "--file",
    "note.md",
    "--role",
    "conceptualization",
    "--assert",
    "I contributed the idea.",
  ]);
  assert.notEqual(blocked.status, 0);
  assert.match(blocked.stderr, /different manuscript/);
  const journal = run(["journal"]);
  assert.equal(journal.status, 0, journal.stderr);
});

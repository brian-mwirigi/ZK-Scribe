import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { bundleId } from "../src/pop/bundle-id.ts";
import { PROOF_SYSTEM, type Attestation } from "../src/pop/attest.ts";
import { defaultPolicy } from "../src/cva/policy.ts";

function sample(agentPublicKey: string): Attestation {
  return {
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
      agentPublicKey,
      signature: "11".repeat(64),
    },
  };
}

test("bundle id follows the statement and the agent key", () => {
  const first = bundleId(sample("aa".repeat(32)));
  assert.equal(bundleId(sample("aa".repeat(32))), first);
  assert.notEqual(bundleId(sample("bb".repeat(32))), first);
  assert.match(first, /^[0-9a-f]{64}$/);
});

test("id command prints the bundle id", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-id-"));
  const attestation = sample("aa".repeat(32));
  fs.writeFileSync(path.join(dir, "attestation.json"), `${JSON.stringify(attestation)}\n`);
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const result = spawnSync(process.execPath, ["--experimental-strip-types", cli, "id", "attestation.json", "--dir", dir], {
    cwd: dir,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), bundleId(attestation));
});


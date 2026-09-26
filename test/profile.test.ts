import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { localProfile } from "../src/pop/profile.ts";
import type { SessionLog } from "../src/pop/session.ts";

function session(times: number[]): SessionLog {
  return {
    sessionId: "local",
    startedAt: "2026-01-01T00:00:00.000Z",
    events: times.map((t) => ({ t, op: "insert", len: 1 })),
  };
}

test("local timing profile reports pause percentiles and omits events", () => {
  const flat = localProfile(session([0, 100, 200, 300, 400]));
  assert.equal(flat.samples, 4);
  assert.equal(flat.p10, 100);
  assert.equal(flat.p50, 100);
  assert.equal(flat.p90, 100);
  const empty = localProfile(session([0]));
  assert.deepEqual(empty, { samples: 0, p10: null, p50: null, p90: null });
  assert.equal(JSON.stringify(flat).includes("\"op\""), false);
});

test("profile command prints percentiles and does not write a file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-profile-"));
  const sessionPath = path.join(dir, "session.json");
  const log: SessionLog = session([0, 100, 200, 300, 400]);
  fs.writeFileSync(sessionPath, `${JSON.stringify(log)}\n`);
  const before = fs.readdirSync(dir).sort();
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const result = spawnSync(process.execPath, ["--experimental-strip-types", cli, "profile", "--session", "session.json", "--dir", dir], {
    cwd: dir,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"p50": 100/);
  assert.deepEqual(fs.readdirSync(dir).sort(), before);
});


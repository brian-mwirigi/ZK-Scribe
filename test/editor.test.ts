import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { eventsFromTextChange } from "../src/capture/document.ts";
import { recordEditorChange, scanOnce } from "../src/capture/watch.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

test("an editor change keeps the length and drops the characters", () => {
  const typed = eventsFromTextChange({ removed: 0, inserted: "a" }, 40);
  assert.deepEqual(typed, [{ t: 40, op: "insert", len: 1 }]);
  const word = eventsFromTextChange({ removed: 0, inserted: "midnight " }, 80);
  assert.equal(word[0].op, "insert");
  assert.equal(word[0].len, 9);
  assert.equal(word[0].boundary, true);
  assert.equal(JSON.stringify(word).includes("midnight"), false);
  const pasted = eventsFromTextChange({ removed: 0, inserted: "a paragraph arrived at once" }, 100);
  assert.equal(pasted.length, 1);
  assert.equal(pasted[0].op, "paste");
  assert.equal(pasted[0].len, "a paragraph arrived at once".length);
  const replaced = eventsFromTextChange({ removed: 3, inserted: "x" }, 120);
  assert.deepEqual(
    replaced.map((event) => event.op),
    ["delete", "insert"],
  );
  assert.equal(eventsFromTextChange({ removed: 0, inserted: "" }, 0).length, 0);
});

test("editor timing is not recorded again when the file is saved", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-editor-"));
  fs.mkdirSync(path.join(dir, "content"));
  const manuscript = "Methods were written by hand.\n";
  fs.writeFileSync(path.join(dir, "content", "01.md"), manuscript);
  assert.equal(scanOnce(dir), 0);
  const wrote = recordEditorChange(dir, "content/01.md", [{ removed: 0, inserted: "a" }], manuscript, 1_700_000_000_000);
  assert.equal(wrote, 1);
  assert.equal(scanOnce(dir), 0);
  const session = fs.readFileSync(path.join(dir, ".zk-scribe", "private", "session.json"), "utf8");
  assert.match(session, /"op": "insert"/);
  assert.equal(session.includes("Methods"), false);
  assert.equal(session.includes(manuscript.trim()), false);
});

test("a VS Code composition session certifies through the commit hook", () => {
  const dir = repo();
  assert.equal(run(dir, ["init", "--dir", dir]).status, 0);
  fs.mkdirSync(path.join(dir, "content"));
  const manuscript = "Methods were written by hand.\n";
  const file = path.join(dir, "content", "01.md");
  fs.writeFileSync(file, manuscript);
  scanOnce(dir);
  const sample = synthesizeSession("composition");
  const started = Date.parse(sample.startedAt);
  for (const event of sample.events) {
    const inserted = event.op === "delete" ? "" : (event.boundary ? "." : "a").repeat(event.len);
    const removed = event.op === "delete" ? event.len : 0;
    recordEditorChange(dir, "content/01.md", [{ removed, inserted }], manuscript, started + event.t);
  }
  git(dir, ["add", "content/01.md"]);
  assert.equal(run(dir, ["hook", "--dir", dir]).status, 0);
  const verified = run(dir, ["verify", "attestation.json", "--dir", dir, "--require", "process-proven"]);
  assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
  const sessionFile = path.join(dir, ".zk-scribe", "private", "session.json");
  assert.equal(fs.existsSync(sessionFile), false);
});

function repo(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-editor-hook-"));
  git(dir, ["init"]);
  git(dir, ["config", "user.email", "zk-scribe@example.com"]);
  git(dir, ["config", "user.name", "ZK-Scribe"]);
  return dir;
}

function git(dir: string, args: string[]): string {
  return execFileSync("git", args, { cwd: dir, encoding: "utf8" });
}

function run(dir: string, args: string[]) {
  return spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args], {
    cwd: dir,
    encoding: "utf8",
  });
}

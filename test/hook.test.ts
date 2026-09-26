import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { scanOnce } from "../src/capture/watch.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

test("init installs a commit hook and the next commit is attested", () => {
  const dir = repo();
  const first = run(dir, ["init", "--dir", dir]);
  assert.equal(first.status, 0, first.stderr);
  const again = run(dir, ["init", "--dir", dir]);
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, /Agent key is on this machine/);
  const hook = fs.readFileSync(path.join(dir, ".git", "hooks", "pre-commit"), "utf8");
  assert.match(hook, /zk-scribe-hook/);
  assert.match(fs.readFileSync(path.join(dir, ".gitignore"), "utf8"), /\.zk-scribe\/private\//);

  fs.mkdirSync(path.join(dir, "content"));
  fs.writeFileSync(path.join(dir, "content", "01.md"), "A manuscript paragraph that arrived in one save.\n");
  git(dir, ["add", "content/01.md", ".gitignore"]);
  git(dir, ["commit", "-m", "draft"]);
  const status = run(dir, ["status", "--dir", dir]);
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, /1 session attested, ledger building/);
  assert.match(status.stdout, /1 refused/);
  assert.equal(fs.existsSync(path.join(dir, "attestation.json")), true);
  const cached = git(dir, ["ls-files"]);
  assert.equal(cached.includes(".zk-scribe/private/agent.seed"), false);
  assert.equal(cached.includes("attestation.json"), true);
});

test("a watched composition session certifies through the commit hook", () => {
  const dir = repo();
  assert.equal(run(dir, ["init", "--dir", dir]).status, 0);
  fs.mkdirSync(path.join(dir, "content"));
  const manuscript = path.join(dir, "content", "01.md");
  fs.writeFileSync(manuscript, "Methods were written by hand.\n");
  scanOnce(dir);
  fs.writeFileSync(manuscript, "Methods were written by hand, then revised.\n");
  assert.equal(scanOnce(dir) > 0, true);
  const sessionFile = path.join(dir, ".zk-scribe", "private", "session.json");
  fs.writeFileSync(sessionFile, `${JSON.stringify(synthesizeSession("composition"), null, 2)}\n`);
  git(dir, ["add", "content/01.md"]);
  const hook = run(dir, ["hook", "--dir", dir]);
  assert.equal(hook.status, 0, `${hook.stdout}\n${hook.stderr}`);
  const verified = run(dir, ["verify", "attestation.json", "--dir", dir, "--require", "process-proven"]);
  assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
  const status = run(dir, ["status", "--dir", dir]);
  assert.match(status.stdout, /1 session attested, ledger building/);
  assert.match(status.stdout, /1 process-proven/);
  assert.equal(fs.existsSync(sessionFile), false);
});

function repo(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-hook-"));
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

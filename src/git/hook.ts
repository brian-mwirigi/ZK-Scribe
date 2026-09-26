import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { eventsFromEdit } from "../capture/edits.ts";
import { cliArgs } from "../entry.ts";
import {
  isManuscriptRelative,
  readSession,
  rotateSession,
  scanOnce,
  sessionPath,
} from "../capture/watch.ts";
import type { Attestation } from "../pop/attest.ts";
import type { SessionLog } from "../pop/session.ts";

const BEGIN = "# zk-scribe-hook";
const END = "# zk-scribe-hook-end";
const IGNORE = [".zk-scribe/private/", "*.witness.json"];

export function ensureLocalIgnore(dir: string): void {
  const file = path.join(dir, ".gitignore");
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const missing = IGNORE.filter((line) => !current.split(/\r?\n/).includes(line));
  if (missing.length === 0) return;
  const prefix = current.length === 0 || current.endsWith("\n") ? current : `${current}\n`;
  fs.writeFileSync(file, `${prefix}${missing.join("\n")}\n`);
}

export function installCommitHook(dir: string): boolean {
  const hooks = hooksDirectory(dir);
  if (!hooks) return false;
  fs.mkdirSync(hooks, { recursive: true });
  const target = path.join(hooks, "pre-commit");
  const block = hookBlock(dir);
  const existing = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
  const next = existing.includes(BEGIN) ? existing.replace(hookPattern(), block) : joinHook(existing, block);
  fs.writeFileSync(target, next);
  fs.chmodSync(target, 0o755);
  return true;
}

export function runCommitHook(dir: string): void {
  try {
    if (!hooksDirectory(dir)) return;
    scanOnce(dir);
    const staged = stagedManuscripts(dir);
    if (staged.length === 0) return;
    const watched = readSession(dir);
    let wrote = 0;
    for (const relative of staged) {
      const sessionFile = watched ? sessionPath(dir) : writeCommitSession(dir, relative);
      if (!sessionFile) continue;
      if (attestFile(dir, relative, sessionFile)) wrote += 1;
    }
    if (wrote === 0) return;
    stagePublic(dir);
    if (watched) rotateSession(dir);
    log(dir, `attested ${wrote}`);
  } catch (error) {
    log(dir, error instanceof Error ? error.message : String(error));
  }
}

function attestFile(dir: string, relative: string, sessionFile: string): boolean {
  const privateOut = path.join(dir, ".zk-scribe", "private", "last-attestation.json");
  const privateWitness = path.join(dir, ".zk-scribe", "private", "last-attestation.witness.json");
  if (fs.existsSync(privateOut)) fs.rmSync(privateOut);
  if (fs.existsSync(privateWitness)) fs.rmSync(privateWitness);
  spawnSync(
    process.execPath,
    [
      ...cliArgs(),
      "attest",
      "--dir",
      dir,
      "--file",
      relative,
      "--session",
      path.relative(dir, sessionFile),
      "--out",
      path.join(".zk-scribe", "private", "last-attestation.json"),
    ],
    { cwd: dir, encoding: "utf8" },
  );
  if (!fs.existsSync(privateOut)) return false;
  const attestation = JSON.parse(fs.readFileSync(privateOut, "utf8")) as Attestation;
  const subject = attestation.statement.context.subject.replaceAll("\\", "/");
  if (subject !== relative.replaceAll("\\", "/")) return false;
  const output = path.join(dir, "attestation.json");
  fs.copyFileSync(privateOut, output);
  const name = ledgerName(attestation);
  const ledger = path.join(dir, ".zk-scribe", "ledger", name);
  fs.mkdirSync(path.dirname(ledger), { recursive: true });
  fs.copyFileSync(privateOut, ledger);
  return true;
}

function writeCommitSession(dir: string, relative: string): string | null {
  const after = gitText(dir, [`show`, `:${relative}`]);
  if (after === null) return null;
  const before = gitText(dir, ["show", `HEAD:${relative}`]) ?? "";
  const events = eventsFromEdit(before, after, 0);
  if (events.length === 0) return null;
  const session: SessionLog = {
    sessionId: `commit-${relative.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 40)}`,
    startedAt: new Date().toISOString(),
    events,
  };
  const file = path.join(dir, ".zk-scribe", "private", "commit-session.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(session, null, 2)}\n`);
  return file;
}

function stagePublic(dir: string): void {
  const ledger = path.join(dir, ".zk-scribe", "ledger");
  const paths = [
    ".gitignore",
    "attestation.json",
    path.join(".zk-scribe", "agent.public.json"),
    path.join(".zk-scribe", "policy.json"),
    path.join(".zk-scribe", "config.json"),
  ];
  if (fs.existsSync(ledger)) {
    for (const name of fs.readdirSync(ledger)) {
      if (name.endsWith(".json")) paths.push(path.join(".zk-scribe", "ledger", name));
    }
  }
  const present = paths.filter((file) => fs.existsSync(path.join(dir, file)));
  if (present.length === 0) return;
  try {
    execFileSync("git", ["add", "--", ...present], { cwd: dir, stdio: "ignore" });
  } catch (error) {
    log(dir, error instanceof Error ? error.message : String(error));
  }
}

function stagedManuscripts(dir: string): string[] {
  let out = "";
  try {
    out = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return [];
  }
  return out
    .split(/\r?\n/)
    .map((line) => line.trim().replaceAll("\\", "/"))
    .filter((line) => line && isManuscriptRelative(dir, line));
}

function hooksDirectory(dir: string): string | null {
  try {
    const relative = execFileSync("git", ["rev-parse", "--git-path", "hooks"], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (!relative) return null;
    return path.resolve(dir, relative);
  } catch {
    return null;
  }
}

function hookBlock(dir: string): string {
  const node = process.execPath.replaceAll("\\", "/");
  const args = cliArgs().map((arg) => `"${arg.replaceAll("\\", "/")}"`).join(" ");
  const root = path.resolve(dir).replaceAll("\\", "/");
  return `${BEGIN}
"${node}" ${args} hook --dir "${root}" >/dev/null 2>&1 || true
${END}
`;
}

function hookPattern(): RegExp {
  return new RegExp(`${BEGIN}[\\s\\S]*?${END}\\n?`);
}

function joinHook(existing: string, block: string): string {
  if (existing.trim() === "") return `#!/bin/sh\n${block}`;
  const base = existing.endsWith("\n") ? existing : `${existing}\n`;
  return `${base}${block}`;
}

function gitText(dir: string, args: string[]): string | null {
  const result = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  if (result.status !== 0) return null;
  return result.stdout;
}

function ledgerName(attestation: Attestation): string {
  const hash = attestation.statement.contentHash.slice(0, 16);
  const session = attestation.statement.sessionId.replace(/[^a-z0-9_-]/gi, "").slice(0, 24);
  return `${hash}-${session}.json`;
}

function log(dir: string, line: string): void {
  const file = path.join(dir, ".zk-scribe", "private", "hook.log");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${new Date().toISOString()} ${line}\n`);
}

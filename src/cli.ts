#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { sha256Hex, utf8 } from "./canon.ts";
import { applyTextDelta, eventFromKey, type KeyInfo } from "./capture/keys.ts";
import { CREDIT_ROLES } from "./credit/taxonomy.ts";
import { suggestRole } from "./credit/suggest.ts";
import { defaultPolicy, type Policy } from "./cva/policy.ts";
import { detectContext, type ExecutionContext } from "./git/context.ts";
import { parseDiffStat, reviewNote } from "./git/diffstat.ts";
import { hashTree, ignoredTreePath, type TreeFile } from "./hash/tree.ts";
import { doctorReport } from "./doctor.ts";
import { decodeSecretKey, encodeKey, generateAgentKey } from "./keys.ts";
import { toJats, toProvenanceManifest } from "./manifest/export.ts";
import { toSummary } from "./manifest/summary.ts";
import { buildLedger } from "./ledger/combine.ts";
import { attest, audit, verify, type Attestation, type Witness } from "./pop/attest.ts";
import { extract } from "./pop/extract.ts";
import { explainFeatures } from "./pop/explain.ts";
import { pauseHistogram } from "./pop/histogram.ts";
import type { SessionLog } from "./pop/session.ts";
import { synthesizeSession } from "./pop/synthesize.ts";
import { VERSION } from "./version.ts";

type Flags = Record<string, string | boolean>;

const HELP = `ZK-Scribe ${VERSION}
Cryptographic authorship and contribution attestation.

Usage:
  zk-scribe init [--dir .] [--force]
  zk-scribe example --kind composition|transcription|automated|paste --out session.json
  zk-scribe record --out session.json
  zk-scribe attest --file manuscript.md --role <credit-role> [--session session.json] [--assert "claim"] [--author-seed author.seed] [--out attestation.json]
  zk-scribe verify <attestation.json> [--require process|process-proven] [--require-author] [--agent-key hex] [--policy policy.json]
  zk-scribe audit --attestation attestation.json --session session.json --witness attestation.witness.json
  zk-scribe export <attestation.json> --format c2pa|jats|summary [--out file]
  zk-scribe explain --session session.json
  zk-scribe doctor [--dir .]
  zk-scribe hash <file-or-directory>
  zk-scribe suggest <file>
  zk-scribe summary <attestation.json>
  zk-scribe histogram --session session.json
  zk-scribe ledger <attestation.json>...
  zk-scribe diffstat <changes.diff> [--content-hash hex]
  zk-scribe credit
`;

function main(argv: string[]): void {
  const { command, flags, positionals } = parseArgs(argv);
  if (!command || flags.help === true || command === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (command === "init") return init(String(flags.dir ?? "."), flags.force === true);
  if (command === "example") return example(flags);
  if (command === "record") return void record(String(flags.out ?? "session.json")).catch(fail);
  if (command === "attest") return attestCommand(flags);
  if (command === "verify") return verifyCommand(flags, positionals);
  if (command === "audit") return auditCommand(flags);
  if (command === "export") return exportCommand(flags, positionals);
  if (command === "explain") return explainCommand(flags);
  if (command === "doctor") return doctorCommand(flags);
  if (command === "hash") return hashCommand(flags, positionals);
  if (command === "suggest") return suggestCommand(flags, positionals);
  if (command === "summary") return summaryCommand(flags, positionals);
  if (command === "histogram") return histogramCommand(flags);
  if (command === "ledger") return ledgerCommand(flags, positionals);
  if (command === "diffstat") return diffstatCommand(flags, positionals);
  if (command === "credit") return credit();
  throw new Error(`Unknown command "${command}".\n\n${HELP}`);
}

function init(dir: string, force: boolean): void {
  const root = path.join(dir, ".zk-scribe");
  const seedPath = path.join(root, "private", "agent.seed");
  fs.mkdirSync(path.dirname(seedPath), { recursive: true });
  if (fs.existsSync(seedPath) && !force) {
    throw new Error("An agent seed already exists. Pass --force to replace it.");
  }
  const key = generateAgentKey();
  fs.writeFileSync(seedPath, `${encodeKey(key.secretKey)}\n`);
  fs.writeFileSync(
    path.join(root, "agent.public.json"),
    `${JSON.stringify({ version: "zk-scribe-agent/0.1.0", algorithm: "ed25519", publicKey: encodeKey(key.publicKey) }, null, 2)}\n`,
  );
  fs.writeFileSync(path.join(root, "policy.json"), `${JSON.stringify(defaultPolicy(), null, 2)}\n`);
  process.stdout.write(`Initialized ${root}\n`);
  process.stdout.write("The seed in .zk-scribe/private/ stays local. Commit agent.public.json and policy.json.\n");
}

function example(flags: Flags): void {
  const kind = String(flags.kind ?? "");
  if (kind !== "composition" && kind !== "transcription" && kind !== "automated" && kind !== "paste") {
    throw new Error("Pass --kind composition|transcription|automated|paste.");
  }
  const out = String(flags.out ?? "");
  if (!out) throw new Error("Pass --out for the session log.");
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(synthesizeSession(kind), null, 2)}\n`);
  process.stdout.write(`Wrote ${out}\n`);
}

function attestCommand(flags: Flags): void {
  const dir = projectDir(flags);
  const file = resolveIn(dir, required(flags, "file"));
  const role = required(flags, "role");
  const out = resolveIn(dir, String(flags.out ?? "attestation.json"));
  const policy = loadPolicy(dir, flags.policy);
  const secret = loadSecret(dir);
  const contentHash = sha256Hex(fs.readFileSync(file));
  const assertion = flags.assert === undefined ? undefined : String(flags.assert);
  const session = flags.session ? readJson<SessionLog>(resolveIn(dir, String(flags.session))) : undefined;
  const context = contextFrom(flags, dir, file);
  const { attestation, witness } = attest({
    role,
    contentHash,
    context,
    policy,
    agentSecretKey: secret,
    session,
    assertion,
    authorSecretKey: authorSeed(dir, flags["author-seed"]),
  });
  writeJson(out, attestation);
  if (witness) writeJson(witnessPathFor(out), witness);
  const binding = attestation.statement.role.binding;
  process.stdout.write(`${binding}: ${attestation.statement.role.detail}\n`);
  process.stdout.write(`Wrote ${out}\n`);
  if (witness) process.stdout.write(`Wrote ${witnessPathFor(out)} (keep this local)\n`);
  if (binding === "unsupported") process.exitCode = 1;
}

function authorSeed(dir: string, value: string | boolean | undefined): Uint8Array | undefined {
  if (typeof value !== "string") return undefined;
  return decodeSecretKey(fs.readFileSync(resolveIn(dir, value), "utf8").trim());
}

function verifyCommand(flags: Flags, positionals: string[]): void {
  const project = projectDir(flags);
  const raw = positionals[0] ?? (flags.attestation === undefined ? "" : String(flags.attestation));
  if (!raw) throw new Error("Pass the attestation file to verify.");
  const file = resolveIn(project, raw);
  const attestation = readJson<Attestation>(file);
  const requireFlag = flags.require === undefined ? undefined : String(flags.require);
  if (requireFlag !== undefined && requireFlag !== "process" && requireFlag !== "process-proven") {
    throw new Error("--require must be process or process-proven.");
  }
  const result = verify(attestation, {
    trustedAgentKey: loadTrustedKey(project, flags["agent-key"]),
    expectedPolicy: loadPolicy(project, flags.policy),
    require: requireFlag,
    requireAuthor: flags["require-author"] === true,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}

function auditCommand(flags: Flags): void {
  const attestation = readJson<Attestation>(required(flags, "attestation"));
  const session = readJson<SessionLog>(required(flags, "session"));
  const witness = readJson<Witness>(required(flags, "witness"));
  const result = audit(attestation, session, witness);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}

function exportCommand(flags: Flags, positionals: string[]): void {
  const file = positionals[0] ?? "";
  if (!file) throw new Error("Pass the attestation file to export.");
  const format = String(flags.format ?? "");
  const attestation = readJson<Attestation>(file);
  const policy = loadPolicy(projectDir(flags), flags.policy);
  if (format === "c2pa") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "manifest.c2pa.json");
    writeJson(out, toProvenanceManifest(attestation));
    process.stdout.write(`Wrote ${out}\n`);
    return;
  }
  if (format === "jats") {
    if (!policy.allow.includes("export.jats") || policy.deny.includes("export.jats")) {
      throw new Error("Policy does not allow export.jats.");
    }
    const out = String(flags.out ?? "attestation.jats.xml");
    fs.writeFileSync(out, toJats(attestation));
    process.stdout.write(`Wrote ${out}\n`);
    return;
  }
  if (format === "summary") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "summary.json");
    writeJson(out, toSummary(attestation));
    process.stdout.write(`Wrote ${out}\n`);
    return;
  }
  throw new Error("Pass --format c2pa, jats, or summary.");
}

function diffstatCommand(flags: Flags, positionals: string[]): void {
  const target = positionals[0];
  if (!target) throw new Error("Pass a unified diff file.");
  const diff = fs.readFileSync(resolveIn(projectDir(flags), target), "utf8");
  const stat = parseDiffStat(diff);
  const contentHash = flags["content-hash"];
  const body = typeof contentHash === "string" ? reviewNote(contentHash, stat) : stat;
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
}

function ledgerCommand(flags: Flags, positionals: string[]): void {
  if (positionals.length === 0) throw new Error("Pass one or more attestation files.");
  const dir = projectDir(flags);
  const entries = positionals.map((file) => toSummary(readJson<Attestation>(resolveIn(dir, file))));
  const out = flags.out === undefined ? "" : String(flags.out);
  const ledger = buildLedger(entries);
  if (out) writeJson(resolveIn(dir, out), ledger);
  else process.stdout.write(`${JSON.stringify(ledger, null, 2)}\n`);
}

function histogramCommand(flags: Flags): void {
  const session = readJson<SessionLog>(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(pauseHistogram(session.events), null, 2)}\n`);
}

function summaryCommand(flags: Flags, positionals: string[]): void {
  const target = positionals[0];
  if (!target) throw new Error("Pass an attestation file to summarize.");
  const attestation = readJson<Attestation>(resolveIn(projectDir(flags), target));
  process.stdout.write(`${JSON.stringify(toSummary(attestation), null, 2)}\n`);
}

function suggestCommand(flags: Flags, positionals: string[]): void {
  const target = positionals[0];
  if (!target) throw new Error("Pass a manuscript path to suggest a role.");
  process.stdout.write(`${JSON.stringify(suggestRole(resolveIn(projectDir(flags), target)), null, 2)}\n`);
}

function hashCommand(flags: Flags, positionals: string[]): void {
  const target = positionals[0];
  if (!target) throw new Error("Pass a file or directory to hash.");
  const full = resolveIn(projectDir(flags), target);
  if (!fs.existsSync(full)) throw new Error(`Nothing found at ${full}.`);
  const stat = fs.statSync(full);
  const files: TreeFile[] = stat.isDirectory()
    ? collectTree(full)
    : [{ path: path.basename(full), bytes: fs.readFileSync(full) }];
  process.stdout.write(`${hashTree(files)}\n`);
}

function collectTree(root: string): TreeFile[] {
  const files: TreeFile[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const relative = path.relative(root, full);
      if (ignoredTreePath(relative)) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files.push({ path: relative, bytes: fs.readFileSync(full) });
    }
  };
  walk(root);
  return files;
}

function doctorCommand(flags: Flags): void {
  const dir = projectDir(flags);
  const root = path.join(dir, ".zk-scribe");
  const major = Number(process.versions.node.split(".")[0]);
  const report = doctorReport({
    nodeMajor: major,
    minimumMajor: 22,
    policyExists: fs.existsSync(path.join(root, "policy.json")),
    publicKeyExists: fs.existsSync(path.join(root, "agent.public.json")),
    seedExists: fs.existsSync(path.join(root, "private", "agent.seed")),
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok) process.exitCode = 1;
}

function explainCommand(flags: Flags): void {
  const session = readJson<SessionLog>(resolveIn(projectDir(flags), required(flags, "session")));
  const extraction = extract(session);
  const explanation = explainFeatures(extraction.features, extraction.bulkInsertEvents);
  process.stdout.write(`${JSON.stringify({
    label: explanation.label,
    note: explanation.note,
    durationMs: extraction.durationMs,
    insertChars: extraction.insertChars,
    checks: explanation.checks,
  }, null, 2)}\n`);
}

function credit(): void {
  for (const role of CREDIT_ROLES) {
    process.stdout.write(`${role.feasibility.padEnd(12)} ${role.id.padEnd(28)} ${role.observes}\n`);
  }
}

function record(out: string): Promise<void> {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    return Promise.reject(new Error("record needs an interactive terminal."));
  }
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin });
    readline.emitKeypressEvents(process.stdin, rl);
    process.stdin.setRawMode(true);
    const started = Date.now();
    const events: SessionLog["events"] = [];
    let text = "";
    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.off("keypress", onKey);
      rl.close();
    };
    const onKey = (str: string, key: KeyInfo) => {
      const step = eventFromKey({ ...key, sequence: key.sequence || str }, Date.now() - started);
      if (step.kind === "abort") {
        cleanup();
        process.stdout.write("\nDiscarded. Nothing was written.\n");
        process.exitCode = 1;
        resolve();
        return;
      }
      if (step.kind === "finish") {
        cleanup();
        const session: SessionLog = {
          sessionId: `rec-${started.toString(16)}`,
          startedAt: new Date(started).toISOString(),
          events,
        };
        writeJson(out, session);
        process.stdout.write(`\nSaved ${events.length} timing events to ${out}\n`);
        process.stdout.write(`Local buffer hash ${sha256Hex(utf8(text))} (the text was not written)\n`);
        resolve();
        return;
      }
      if (step.kind === "event") {
        text = applyTextDelta(text, step.event, step.textDelta);
        events.push(step.event);
        if (step.event.op === "delete") process.stdout.write("\b \b");
        else if (step.textDelta) process.stdout.write(step.textDelta);
      }
    };
    process.stdin.on("keypress", onKey);
    process.stdout.write("Timing keystrokes. Typed text stays on screen and is not saved.\nCtrl+D writes the timing log. Ctrl+C discards it.\n");
  });
}

function projectDir(flags: Flags): string {
  return path.resolve(typeof flags.dir === "string" ? flags.dir : process.cwd());
}

function resolveIn(dir: string, file: string): string {
  return path.resolve(dir, file);
}

function contextFrom(flags: Flags, cwd: string, file: string): ExecutionContext {
  const detected = detectContext(cwd, path.resolve(file));
  const requested = flags.environment === undefined ? undefined : String(flags.environment);
  if (requested === undefined) return detected;
  if (requested !== "git" && requested !== "overleaf-git" && requested !== "local") {
    throw new Error("--environment must be git, overleaf-git, or local.");
  }
  return { ...detected, environment: requested };
}

function loadPolicy(cwd: string, override: string | boolean | undefined): Policy {
  const file = typeof override === "string" ? override : path.join(cwd, ".zk-scribe", "policy.json");
  if (!fs.existsSync(file)) throw new Error(`Policy not found at ${file}. Run zk-scribe init.`);
  return readJson<Policy>(file);
}

function loadSecret(cwd: string): Uint8Array {
  const file = path.join(cwd, ".zk-scribe", "private", "agent.seed");
  if (!fs.existsSync(file)) throw new Error(`Agent seed not found at ${file}. Run zk-scribe init.`);
  return decodeSecretKey(fs.readFileSync(file, "utf8").trim());
}

function loadTrustedKey(cwd: string, override: string | boolean | undefined): string {
  if (typeof override === "string") return override;
  const file = path.join(cwd, ".zk-scribe", "agent.public.json");
  if (!fs.existsSync(file)) throw new Error(`Trusted agent key not found at ${file}. Pass --agent-key.`);
  const parsed = readJson<{ publicKey: string }>(file);
  if (!parsed.publicKey) throw new Error("agent.public.json is missing publicKey.");
  return parsed.publicKey;
}

function witnessPathFor(out: string): string {
  return out.endsWith(".json") ? `${out.slice(0, -5)}.witness.json` : `${out}.witness.json`;
}

function required(flags: Flags, name: string): string {
  const value = flags[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`Pass --${name}.`);
  return value;
}

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function parseArgs(argv: string[]): { command: string; flags: Flags; positionals: string[] } {
  const [command = "", ...rest] = argv;
  const flags: Flags = {};
  const positionals: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const key = token.slice(2);
    const next = rest[index + 1];
    if (next === undefined || next.startsWith("--")) flags[key] = true;
    else {
      flags[key] = next;
      index += 1;
    }
  }
  return { command, flags, positionals };
}

function fail(error: unknown): never {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}

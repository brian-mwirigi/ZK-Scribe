#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { canonicalHash, sha256Hex, utf8 } from "./canon.ts";
import { rangeBenchmark } from "./crypto/benchmark.ts";
import { applyTextDelta, eventFromKey, type KeyInfo } from "./capture/keys.ts";
import { startOverleafBridge } from "./capture/overleaf.ts";
import { CREDIT_ROLES } from "./credit/taxonomy.ts";
import { suggestRole } from "./credit/suggest.ts";
import { defaultPolicy, policyHash, type Policy } from "./cva/policy.ts";
import { lintPolicy } from "./cva/lint.ts";
import { govern } from "./cva/govern.ts";
import { issueGrant, parseGrant, type AgentGrant } from "./cva/grant.ts";
import { appendJournal, auditJournal, parseJournalEntry, type JournalEntry } from "./cva/journal.ts";
import { detectContext, type ExecutionContext } from "./git/context.ts";
import { parseDiffStat, reviewNote } from "./git/diffstat.ts";
import { hashTree, ignoredTreePath, type TreeFile } from "./hash/tree.ts";
import { doctorReport } from "./doctor.ts";
import { decodeSecretKey, encodeKey, generateAgentKey, publicKeyFromSecret } from "./keys.ts";
import { toJats, toProvenanceManifest } from "./manifest/export.ts";
import { toHtmlReport } from "./manifest/html.ts";
import { toSummary } from "./manifest/summary.ts";
import { buildLedger } from "./ledger/combine.ts";
import { attest, audit, verify, type Attestation, type Witness } from "./pop/attest.ts";
import { extract } from "./pop/extract.ts";
import { explainFeatures } from "./pop/explain.ts";
import { pauseHistogram } from "./pop/histogram.ts";
import { parseRevocationList } from "./cva/revocation.ts";
import { defaultConfig, parseConfig, type ProjectConfig } from "./config.ts";
import { localProfile } from "./pop/profile.ts";
import { bundleId } from "./pop/bundle-id.ts";
import { sessionStats } from "./pop/stats.ts";
import type { SessionLog } from "./pop/session.ts";
import { synthesizeSession } from "./pop/synthesize.ts";
import { scanOnce, startWatcher, watchLabel } from "./capture/watch.ts";
import { ensureAnchor, fetchLatest, needsAnotherRound, QUICKNET, windowProblem, type TimeAnchor, type TimeRound } from "./time/drand.ts";
import { ensureLocalIgnore, installCommitHook, runCommitHook } from "./git/hook.ts";
import { statusCounts, statusText } from "./status.ts";
import { VERSION } from "./version.ts";

type Flags = Record<string, string | boolean>;

const HELP = `ZK-Scribe ${VERSION}
Cryptographic authorship and contribution attestation.

Usage:
  zk-scribe init [--dir .] [--force]
  zk-scribe status [--dir .]
  zk-scribe example --kind composition|transcription|automated|paste --out session.json
  zk-scribe record --out session.json
  zk-scribe overleaf [--dir .]
  zk-scribe attest --file manuscript.md [--role <credit-role>] [--session session.json] [--assert "claim"] [--author-seed author.seed] [--grant grant.json] [--out attestation.json]
  zk-scribe verify <attestation.json> [--require process|process-proven] [--require-author] [--require-grant] [--grant grant.json] [--agent-key hex] [--policy policy.json]
  A .zk-scribe/revoked.json list, when present, refuses those agent keys.
  A .zk-scribe/grant.json file, when present, scopes attest and export to that grant.
  zk-scribe audit --attestation attestation.json --session session.json --witness attestation.witness.json
  zk-scribe export <attestation.json> --format c2pa|jats|summary|html [--out file]
  zk-scribe explain --session session.json
  zk-scribe doctor [--dir .]
  zk-scribe hash <file-or-directory>
  zk-scribe suggest <file>
  zk-scribe summary <attestation.json>
  zk-scribe histogram --session session.json
  zk-scribe ledger <attestation.json>...
  zk-scribe diffstat <changes.diff> [--content-hash hex]
  zk-scribe policy
  zk-scribe grant --file manuscript.md --actions attest.process,export.manifest --author-seed author.seed [--out .zk-scribe/grant.json]
  zk-scribe govern --action attest.process --file manuscript.md [--grant grant.json]
  zk-scribe journal
  zk-scribe stats --session session.json
  zk-scribe profile --session session.json
  zk-scribe id <attestation.json>
  zk-scribe benchmark
  zk-scribe credit
`;

function main(argv: string[]): void {
  const { command, flags, positionals } = parseArgs(argv);
  if (!command || flags.help === true || command === "help" || command === "--help") {
    process.stdout.write(HELP);
    return;
  }
  if (command === "init") return init(String(flags.dir ?? "."), flags.force === true);
  if (command === "status") return statusCommand(flags);
  if (command === "watch") return watchCommand(flags);
  if (command === "hook") return runCommitHook(path.resolve(String(flags.dir ?? ".")));
  if (command === "example") return example(flags);
  if (command === "record") return void record(String(flags.out ?? "session.json")).catch(fail);
  if (command === "overleaf") return void overleafCommand(flags).catch(fail);
  if (command === "attest") return void attestCommand(flags).catch((error) => fail(error, 2));
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
  if (command === "policy") return policyCommand(flags);
  if (command === "grant") return grantCommand(flags);
  if (command === "govern") return governCommand(flags);
  if (command === "journal") return journalCommand(flags);
  if (command === "stats") return statsCommand(flags);
  if (command === "profile") return profileCommand(flags);
  if (command === "id") return idCommand(flags, positionals);
  if (command === "benchmark") return benchmarkCommand();
  if (command === "credit") return credit();
  throw new Error(`Unknown command "${command}".\n\n${HELP}`);
}

function init(dir: string, force: boolean): void {
  const rootDir = path.resolve(dir);
  const root = path.join(rootDir, ".zk-scribe");
  const seedPath = path.join(root, "private", "agent.seed");
  const publicPath = path.join(root, "agent.public.json");
  fs.mkdirSync(path.dirname(seedPath), { recursive: true });
  const kept = fs.existsSync(seedPath) && !force;
  if (!kept) {
    const key = generateAgentKey();
    fs.writeFileSync(seedPath, `${encodeKey(key.secretKey)}\n`);
    fs.writeFileSync(publicPath, publicKeyFile(encodeKey(key.publicKey)));
  } else if (!fs.existsSync(publicPath)) {
    const secret = decodeSecretKey(fs.readFileSync(seedPath, "utf8").trim());
    fs.writeFileSync(publicPath, publicKeyFile(encodeKey(publicKeyFromSecret(secret))));
  }
  const policyPath = path.join(root, "policy.json");
  if (!fs.existsSync(policyPath) || force) {
    fs.writeFileSync(policyPath, `${JSON.stringify(defaultPolicy(), null, 2)}\n`);
  }
  const configPath = path.join(root, "config.json");
  if (!fs.existsSync(configPath) || force) {
    fs.writeFileSync(configPath, `${JSON.stringify(defaultConfig(), null, 2)}\n`);
  }
  ensureLocalIgnore(rootDir);
  const hooked = installCommitHook(rootDir);
  const watching = process.stdout.isTTY === true && startWatcher(rootDir);
  process.stdout.write(kept ? "Agent key is on this machine.\n" : `Initialized ${root}\n`);
  process.stdout.write("The seed in .zk-scribe/private/ stays local.\n");
  if (hooked) process.stdout.write("Commit hook installed.\n");
  if (watching) process.stdout.write(`Watching ${watchLabel(rootDir)}\n`);
  process.stdout.write("zk-scribe status\n");
}

function publicKeyFile(publicKey: string): string {
  return `${JSON.stringify({ version: "zk-scribe-agent/0.1.0", algorithm: "ed25519", publicKey }, null, 2)}\n`;
}

function statusCommand(flags: Flags): void {
  process.stdout.write(statusText(statusCounts(path.resolve(String(flags.dir ?? ".")))));
}

function watchCommand(flags: Flags): void {
  const dir = path.resolve(String(flags.dir ?? "."));
  const pid = path.join(dir, ".zk-scribe", "private", "watch.pid");
  fs.mkdirSync(path.dirname(pid), { recursive: true });
  fs.writeFileSync(pid, `${process.pid}\n`);
  const tick = () => {
    try {
      scanOnce(dir);
    } catch {
      // A bad save stays out of the session. The next one still gets a chance.
    }
  };
  tick();
  const timer = setInterval(tick, 500);
  const stop = () => {
    clearInterval(timer);
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
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

async function attestCommand(flags: Flags): Promise<void> {
  const dir = projectDir(flags);
  const file = resolveIn(dir, required(flags, "file"));
  const role = roleFor(dir, flags);
  const out = resolveIn(dir, String(flags.out ?? "attestation.json"));
  const policy = loadPolicy(dir, flags.policy);
  const secret = loadSecret(dir);
  const contentHash = sha256Hex(fs.readFileSync(file));
  const assertion = flags.assert === undefined ? undefined : String(flags.assert);
  const sessionFile = flags.session ? resolveIn(dir, String(flags.session)) : "";
  let session = sessionFile ? readJson<SessionLog>(sessionFile) : undefined;
  if (session && (session.source === "record" || session.source === "overleaf" || session.source === "editor")) {
    const sealed = await ensureAnchor(session);
    if (canonicalHash(sealed.timeAnchor ?? null) !== canonicalHash(session.timeAnchor ?? null)) {
      writeJson(sessionFile, sealed);
    }
    session = sealed;
  }
  const context = contextFrom(flags, dir, file);
  const grantHash = applyGovernance(dir, flags, policy, assertedAction(flags), contentHash);
  const { attestation, witness } = attest({
    role,
    contentHash,
    context,
    policy,
    agentSecretKey: secret,
    session,
    assertion,
    authorSecretKey: authorSeed(dir, flags["author-seed"]),
    grantHash,
  });
  writeJson(out, attestation);
  if (witness) writeJson(witnessPathFor(out), witness);
  const binding = attestation.statement.role.binding;
  process.stdout.write(`${binding}: ${attestation.statement.role.detail}\n`);
  process.stdout.write(`Wrote ${out}\n`);
  if (witness) process.stdout.write(`Wrote ${witnessPathFor(out)} (keep this local)\n`);
  if (binding === "unsupported") process.exitCode = 1;
}

function roleFor(dir: string, flags: Flags): string {
  if (typeof flags.role === "string" && flags.role.trim() !== "") return flags.role;
  const configPath = path.join(dir, ".zk-scribe", "config.json");
  if (!fs.existsSync(configPath)) throw new Error("Pass --role, or add defaultRole to .zk-scribe/config.json.");
  return parseConfig(JSON.parse(fs.readFileSync(configPath, "utf8")) as ProjectConfig).defaultRole;
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
    requireGrant: flags["require-grant"] === true,
    revokedKeys: loadRevokedKeys(project),
    grant: typeof flags.grant === "string" ? parseGrant(readJson(resolveIn(project, flags.grant))) : undefined,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}

function loadRevokedKeys(dir: string): string[] | undefined {
  const file = path.join(dir, ".zk-scribe", "revoked.json");
  if (!fs.existsSync(file)) return undefined;
  return parseRevocationList(JSON.parse(fs.readFileSync(file, "utf8")) as unknown);
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
  const dir = projectDir(flags);
  const attestation = readJson<Attestation>(file);
  const policy = loadPolicy(dir, flags.policy);
  if (format === "c2pa" || format === "summary" || format === "html" || format === "jats") {
    applyGovernance(dir, flags, policy, format === "jats" ? "export.jats" : "export.manifest", attestation.statement.contentHash);
  }
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
  if (format === "html") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "attestation.html");
    fs.writeFileSync(out, toHtmlReport(attestation));
    process.stdout.write(`Wrote ${out}\n`);
    return;
  }
  throw new Error("Pass --format c2pa, jats, summary, or html.");
}

function statsCommand(flags: Flags): void {
  const session = readJson<SessionLog>(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(sessionStats(session), null, 2)}\n`);
}

function profileCommand(flags: Flags): void {
  const session = readJson<SessionLog>(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(localProfile(session), null, 2)}\n`);
}

function idCommand(flags: Flags, positionals: string[]): void {
  const target = positionals[0];
  if (!target) throw new Error("Pass an attestation file.");
  const attestation = readJson<Attestation>(resolveIn(projectDir(flags), target));
  process.stdout.write(`${bundleId(attestation)}\n`);
}

function benchmarkCommand(): void {
  process.stdout.write(`${JSON.stringify(rangeBenchmark(), null, 2)}\n`);
}

function policyCommand(flags: Flags): void {
  const lint = lintPolicy(loadPolicy(projectDir(flags), flags.policy));
  process.stdout.write(`${JSON.stringify(lint, null, 2)}\n`);
  if (!lint.ok) process.exitCode = 1;
}

function grantCommand(flags: Flags): void {
  const dir = projectDir(flags);
  const author = authorSeed(dir, flags["author-seed"]);
  if (!author) throw new Error("Pass --author-seed for the grant signer.");
  const actions = String(flags.actions ?? "")
    .split(",")
    .map((action) => action.trim())
    .filter((action) => action.length > 0);
  const grant = issueGrant({
    agentPublicKey: loadTrustedKey(dir, flags["agent-key"]),
    policy: loadPolicy(dir, flags.policy),
    actions,
    contentHash: sha256Hex(fs.readFileSync(resolveIn(dir, required(flags, "file")))),
    authorSecretKey: author,
  });
  const out = resolveIn(dir, String(flags.out ?? path.join(".zk-scribe", "grant.json")));
  writeJson(out, grant);
  process.stdout.write(`Wrote ${out}\n`);
}

function governCommand(flags: Flags): void {
  const dir = projectDir(flags);
  const policy = loadPolicy(dir, flags.policy);
  const contentHash = sha256Hex(fs.readFileSync(resolveIn(dir, required(flags, "file"))));
  const decision = decideAndRecord(dir, flags, policy, required(flags, "action"), contentHash);
  process.stdout.write(`${JSON.stringify(decision, null, 2)}\n`);
  if (!decision.allow) process.exitCode = 1;
}

function journalCommand(flags: Flags): void {
  const result = auditJournal(readJournal(projectDir(flags)));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}

function assertedAction(flags: Flags): "attest.assert" | "attest.process" {
  return typeof flags.assert === "string" && flags.assert.trim() !== "" ? "attest.assert" : "attest.process";
}

function applyGovernance(
  dir: string,
  flags: Flags,
  policy: Policy,
  action: string,
  contentHash: string,
): string | undefined {
  if (!readGovernedGrant(dir, flags)) return undefined;
  const decision = decideAndRecord(dir, flags, policy, action, contentHash);
  if (!decision.allow) throw new Error(decision.reasons.join(" "));
  return decision.grantHash;
}

function decideAndRecord(dir: string, flags: Flags, policy: Policy, action: string, contentHash: string) {
  const secret = loadSecret(dir);
  const agentPublicKey = encodeKey(publicKeyFromSecret(secret));
  const decision = govern({
    action,
    agentPublicKey,
    policy,
    contentHash,
    revokedKeys: loadRevokedKeys(dir),
    grant: readGovernedGrant(dir, flags),
  });
  const next = appendJournal(readJournal(dir), {
    action,
    agentPublicKey,
    contentHash,
    policyHash: policyHash(policy),
    grantHash: decision.grantHash ?? null,
    allow: decision.allow,
    reasons: decision.reasons,
    agentSecretKey: secret,
  });
  writeJournal(dir, next);
  return decision;
}

function readGovernedGrant(dir: string, flags: Flags): AgentGrant | undefined {
  if (typeof flags.grant === "string") return parseGrant(readJson(resolveIn(dir, flags.grant)));
  const fallback = path.join(dir, ".zk-scribe", "grant.json");
  if (!fs.existsSync(fallback)) return undefined;
  return parseGrant(readJson(fallback));
}

function journalFile(dir: string): string {
  return path.join(dir, ".zk-scribe", "private", "journal.jsonl");
}

function readJournal(dir: string): JournalEntry[] {
  const file = journalFile(dir);
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "")
    .map((line) => parseJournalEntry(JSON.parse(line) as unknown));
}

function writeJournal(dir: string, entries: JournalEntry[]): void {
  const file = journalFile(dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = entries.map((entry) => JSON.stringify(entry)).join("\n");
  fs.writeFileSync(file, body.length === 0 ? "" : `${body}\n`);
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

async function overleafCommand(flags: Flags): Promise<void> {
  const dir = projectDir(flags);
  if (!fs.existsSync(path.join(dir, ".zk-scribe", "config.json"))) {
    throw new Error("Run zk-scribe init in this repository.");
  }
  const bridge = await startOverleafBridge(dir);
  const folder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "editors", "overleaf");
  process.stdout.write(`Overleaf bridge listening on 127.0.0.1:${bridge.port}\n`);
  process.stdout.write(`Token ${bridge.token}\n`);
  process.stdout.write(`Load the unpacked extension from ${folder}\n`);
  process.stdout.write("Paste the port and token into the extension options. The bridge stores edit lengths only.\n");
  process.stdout.write("Ctrl+C stops the bridge.\n");
  await new Promise<void>((resolve) => {
    const stop = () => {
      void bridge.close().then(() => resolve());
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}

async function record(out: string): Promise<void> {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    throw new Error("record needs an interactive terminal.");
  }
  let beaconStart: TimeRound | null = null;
  try {
    beaconStart = await fetchLatest();
  } catch {
    beaconStart = null;
  }
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const events: SessionLog["events"] = [];
  let text = "";
  const rl = readline.createInterface({ input: process.stdin });
  readline.emitKeypressEvents(process.stdin, rl);
  process.stdin.setRawMode(true);
  process.stdout.write("Timing keystrokes. Typed text stays on screen and is not saved.\nCtrl+D writes the timing log. Ctrl+C discards it.\n");
  const finished = await new Promise<"save" | "discard">((resolve) => {
    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.off("keypress", onKey);
      rl.close();
    };
    const onKey = (str: string, key: KeyInfo) => {
      const step = eventFromKey({ ...key, sequence: key.sequence || str }, Date.now() - started);
      if (step.kind === "abort") {
        cleanup();
        resolve("discard");
        return;
      }
      if (step.kind === "finish") {
        cleanup();
        resolve("save");
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
  });
  if (finished === "discard") {
    process.stdout.write("\nDiscarded. Nothing was written.\n");
    process.exitCode = 1;
    return;
  }
  const session: SessionLog = {
    sessionId: `rec-${started.toString(16)}`,
    startedAt,
    source: "record",
    events,
  };
  const duration = events.length === 0 ? 0 : events[events.length - 1].t - events[0].t;
  if (!beaconStart) {
    process.stdout.write("Time beacon was unavailable. The log was saved without a wall-clock window.\n");
  } else {
    try {
      let end = await fetchLatest();
      const deadline = Date.now() + QUICKNET.period * 1000 * 3 + 500;
      let anchor: TimeAnchor = { scheme: "drand-quicknet-v1", startedAt, start: beaconStart, end };
      while (needsAnotherRound(windowProblem(anchor, duration)) && Date.now() < deadline) {
        await delay(QUICKNET.period * 1000 + 200);
        end = await fetchLatest();
        anchor = { scheme: "drand-quicknet-v1", startedAt, start: beaconStart, end };
      }
      const problem = windowProblem(anchor, duration);
      if (problem) process.stdout.write(`${problem} The log was saved without a time beacon.\n`);
      else session.timeAnchor = anchor;
    } catch {
      process.stdout.write("Time beacon was unavailable. The log was saved without a wall-clock window.\n");
    }
  }
  writeJson(out, session);
  process.stdout.write(`\nSaved ${events.length} timing events to ${out}\n`);
  process.stdout.write(`Local buffer hash ${sha256Hex(utf8(text))} (the text was not written)\n`);
  if (session.timeAnchor) {
    process.stdout.write(`Time window rounds ${session.timeAnchor.start.round}–${session.timeAnchor.end.round}\n`);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function fail(error: unknown, code = 1): never {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(code);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}

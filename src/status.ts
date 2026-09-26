import fs from "node:fs";
import path from "node:path";
import type { Attestation } from "./pop/attest.ts";
import { watcherAlive, watchLabel } from "./capture/watch.ts";

export type StatusCounts = {
  initialized: boolean;
  watching: boolean;
  root: string;
  attested: number;
  processProven: number;
  typedArtifact: number;
  signedAssertion: number;
  refused: number;
};

export function statusCounts(dir: string): StatusCounts {
  const root = path.join(dir, ".zk-scribe");
  const initialized = fs.existsSync(path.join(root, "private", "agent.seed"));
  const counts: StatusCounts = {
    initialized,
    watching: initialized && watcherAlive(dir),
    root: watchLabel(dir),
    attested: 0,
    processProven: 0,
    typedArtifact: 0,
    signedAssertion: 0,
    refused: 0,
  };
  if (!initialized) return counts;
  const seen = new Set<string>();
  for (const attestation of loadAttestations(dir)) {
    const id = `${attestation.statement.contentHash}:${attestation.statement.sessionId}:${attestation.statement.role.id}`;
    if (seen.has(id)) continue;
    seen.add(id);
    counts.attested += 1;
    const binding = attestation.statement.role.binding;
    if (binding === "process-proven") counts.processProven += 1;
    else if (binding === "typed-artifact") counts.typedArtifact += 1;
    else if (binding === "signed-assertion") counts.signedAssertion += 1;
    else counts.refused += 1;
  }
  return counts;
}

export function statusText(counts: StatusCounts): string {
  if (!counts.initialized) return "Run zk-scribe init in this repository.\n";
  const lines: string[] = [];
  if (counts.attested === 0) {
    if (counts.watching) lines.push(`Watching ${counts.root}`);
    lines.push("No sessions attested yet.");
    return `${lines.join("\n")}\n`;
  }
  const noun = counts.attested === 1 ? "session" : "sessions";
  lines.push(`${counts.attested} ${noun} attested, ledger building`);
  const parts: string[] = [];
  if (counts.processProven) parts.push(`${counts.processProven} process-proven`);
  if (counts.typedArtifact) parts.push(`${counts.typedArtifact} typed-artifact`);
  if (counts.signedAssertion) parts.push(`${counts.signedAssertion} signed-assertion`);
  if (counts.refused) parts.push(`${counts.refused} refused`);
  if (parts.length) lines.push(parts.join(" · "));
  if (counts.watching) lines.push(`Watching ${counts.root}`);
  return `${lines.join("\n")}\n`;
}

function loadAttestations(dir: string): Attestation[] {
  const ledger = path.join(dir, ".zk-scribe", "ledger");
  if (!fs.existsSync(ledger)) return [];
  const found: Attestation[] = [];
  for (const name of fs.readdirSync(ledger)) {
    if (!name.endsWith(".json")) continue;
    try {
      found.push(JSON.parse(fs.readFileSync(path.join(ledger, name), "utf8")) as Attestation);
    } catch {
      continue;
    }
  }
  return found;
}

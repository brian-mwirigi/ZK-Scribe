import { canonicalHash, utf8 } from "../canon.ts";
import { decodePublicKey, decodeSignature, encodeKey, sign, verifySignature } from "../keys.ts";

export type JournalEntry = {
  version: "zk-scribe-journal/0.1.0";
  index: number;
  action: string;
  agentPublicKey: string;
  contentHash: string;
  policyHash: string;
  grantHash: string | null;
  allow: boolean;
  reasons: string[];
  prev: string;
  signature: string;
};

export type JournalDraft = {
  action: string;
  agentPublicKey: string;
  contentHash: string;
  policyHash: string;
  grantHash: string | null;
  allow: boolean;
  reasons: string[];
  agentSecretKey: Uint8Array;
};

const GENESIS = "0".repeat(64);

export function appendJournal(entries: readonly JournalEntry[], draft: JournalDraft): JournalEntry[] {
  const previous = entries.length === 0 ? null : entries[entries.length - 1];
  const body = {
    version: "zk-scribe-journal/0.1.0" as const,
    index: previous ? previous.index + 1 : 0,
    action: draft.action,
    agentPublicKey: draft.agentPublicKey,
    contentHash: draft.contentHash,
    policyHash: draft.policyHash,
    grantHash: draft.grantHash,
    allow: draft.allow,
    reasons: draft.reasons,
    prev: previous ? entryHash(previous) : GENESIS,
  };
  const signature = encodeKey(sign(utf8(journalMessage(canonicalHash(body))), draft.agentSecretKey));
  return [...entries, { ...body, signature }];
}

export function entryHash(entry: JournalEntry): string {
  return canonicalHash(entry);
}

export function auditJournal(entries: readonly JournalEntry[]): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  let previous: JournalEntry | null = null;
  for (const [index, entry] of entries.entries()) {
    if (entry.version !== "zk-scribe-journal/0.1.0") reasons.push(`Entry ${index} has an unsupported version.`);
    if (entry.index !== index) reasons.push(`Entry ${index} is out of order.`);
    const expectedPrev = previous ? entryHash(previous) : GENESIS;
    if (entry.prev !== expectedPrev) reasons.push(`Entry ${index} does not follow the previous decision.`);
    if (!entrySignatureValid(entry)) reasons.push(`Entry ${index} signature is invalid.`);
    previous = entry;
  }
  return { ok: reasons.length === 0, reasons };
}

export function parseJournalEntry(value: unknown): JournalEntry {
  if (!value || typeof value !== "object") throw new Error("Journal entry must be an object.");
  const record = value as Record<string, unknown>;
  if (record.version !== "zk-scribe-journal/0.1.0") throw new Error("Unsupported journal version.");
  if (typeof record.index !== "number" || typeof record.action !== "string") {
    throw new Error("Journal entry is missing index or action.");
  }
  if (typeof record.agentPublicKey !== "string" || typeof record.contentHash !== "string" || typeof record.policyHash !== "string") {
    throw new Error("Journal entry is missing a hash.");
  }
  if (record.grantHash !== null && typeof record.grantHash !== "string") throw new Error("Journal grantHash is invalid.");
  if (typeof record.allow !== "boolean" || !Array.isArray(record.reasons) || typeof record.prev !== "string") {
    throw new Error("Journal entry is missing its decision.");
  }
  if (record.reasons.some((reason) => typeof reason !== "string")) throw new Error("Journal reasons must be strings.");
  if (typeof record.signature !== "string") throw new Error("Journal signature is missing.");
  return {
    version: "zk-scribe-journal/0.1.0",
    index: record.index,
    action: record.action,
    agentPublicKey: record.agentPublicKey,
    contentHash: record.contentHash,
    policyHash: record.policyHash,
    grantHash: record.grantHash,
    allow: record.allow,
    reasons: record.reasons as string[],
    prev: record.prev,
    signature: record.signature,
  };
}

function entrySignatureValid(entry: JournalEntry): boolean {
  try {
    const { signature, ...body } = entry;
    return verifySignature(
      decodeSignature(signature),
      utf8(journalMessage(canonicalHash(body))),
      decodePublicKey(entry.agentPublicKey),
    );
  } catch {
    return false;
  }
}

function journalMessage(bodyHash: string): string {
  return `ZK-Scribe/journal/v1:${bodyHash}`;
}

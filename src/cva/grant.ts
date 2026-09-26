import { canonicalHash, utf8 } from "../canon.ts";
import { policyHash, type Policy } from "./policy.ts";
import { normalizeKey } from "./revocation.ts";
import {
  decodePublicKey,
  decodeSignature,
  encodeKey,
  publicKeyFromSecret,
  sign,
  verifySignature,
} from "../keys.ts";

export type GrantSigner = {
  publicKey: string;
  signature: string;
};

export type AgentGrant = {
  version: "zk-scribe-grant/0.1.0";
  agentPublicKey: string;
  policyHash: string;
  actions: string[];
  contentHash: string;
  author: GrantSigner;
};

export type GrantIssue = {
  agentPublicKey: string;
  policy: Policy;
  actions: string[];
  contentHash: string;
  authorSecretKey: Uint8Array;
};

export function issueGrant(input: GrantIssue): AgentGrant {
  const actions = uniqueActions(input.actions);
  assertContentHash(input.contentHash);
  decodePublicKey(input.agentPublicKey);
  const body = {
    version: "zk-scribe-grant/0.1.0" as const,
    agentPublicKey: normalizeKey(input.agentPublicKey),
    policyHash: policyHash(input.policy),
    actions,
    contentHash: input.contentHash,
  };
  return {
    ...body,
    author: {
      publicKey: encodeKey(publicKeyFromSecret(input.authorSecretKey)),
      signature: encodeKey(sign(utf8(grantMessage(canonicalHash(body))), input.authorSecretKey)),
    },
  };
}

export function parseGrant(value: unknown): AgentGrant {
  if (!value || typeof value !== "object") throw new Error("Grant must be an object.");
  const record = value as Record<string, unknown>;
  if (record.version !== "zk-scribe-grant/0.1.0") throw new Error("Unsupported grant version.");
  if (typeof record.agentPublicKey !== "string" || typeof record.policyHash !== "string") {
    throw new Error("Grant is missing the agent or the policy hash.");
  }
  if (typeof record.contentHash !== "string") throw new Error("Grant is missing contentHash.");
  if (!Array.isArray(record.actions) || record.actions.some((action) => typeof action !== "string")) {
    throw new Error("Grant actions must be strings.");
  }
  const author = record.author as Record<string, unknown> | undefined;
  if (!author || typeof author.publicKey !== "string" || typeof author.signature !== "string") {
    throw new Error("Grant author signature is missing.");
  }
  return {
    version: "zk-scribe-grant/0.1.0",
    agentPublicKey: record.agentPublicKey,
    policyHash: record.policyHash,
    actions: record.actions,
    contentHash: record.contentHash,
    author: { publicKey: author.publicKey, signature: author.signature },
  };
}

export function hashGrant(grant: AgentGrant): string {
  return canonicalHash(grant);
}

export function grantSignatureValid(grant: AgentGrant): boolean {
  try {
    const body = {
      version: grant.version,
      agentPublicKey: grant.agentPublicKey,
      policyHash: grant.policyHash,
      actions: grant.actions,
      contentHash: grant.contentHash,
    };
    return verifySignature(
      decodeSignature(grant.author.signature),
      utf8(grantMessage(canonicalHash(body))),
      decodePublicKey(grant.author.publicKey),
    );
  } catch {
    return false;
  }
}

export function grantCovers(
  grant: AgentGrant,
  request: { action: string; agentPublicKey: string; policyHash: string; contentHash: string },
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!grantSignatureValid(grant)) reasons.push("Grant signature is invalid.");
  if (normalizeKey(grant.agentPublicKey) !== normalizeKey(request.agentPublicKey)) {
    reasons.push("Grant is for a different agent.");
  }
  if (grant.policyHash !== request.policyHash) reasons.push("Grant is for a different policy.");
  if (grant.contentHash !== request.contentHash) reasons.push("Grant is for a different manuscript.");
  if (!grant.actions.includes(request.action)) reasons.push(`Grant does not allow ${request.action}.`);
  return { ok: reasons.length === 0, reasons };
}

function grantMessage(bodyHash: string): string {
  return `ZK-Scribe/grant/v1:${bodyHash}`;
}

function uniqueActions(actions: string[]): string[] {
  const cleaned = [...new Set(actions.map((action) => action.trim()).filter((action) => action.length > 0))].sort();
  if (cleaned.length === 0) throw new Error("Grant actions are empty.");
  return cleaned;
}

function assertContentHash(hash: string): void {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("contentHash must be a sha256 hex digest.");
}

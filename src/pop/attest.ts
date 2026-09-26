import { canonicalHash, utf8 } from "../canon.ts";
import { authorEndorsementValid, endorseStatement, type AuthorEndorsement } from "../author/endorse.ts";
import { getRole, type CreditRoleId, type Feasibility } from "../credit/taxonomy.ts";
import { commit, hexToPoint, hexToScalar, pointToHex, randomScalar, scalarToHex } from "../crypto/group.ts";
import { proveInterval, verifyInterval, type IntervalProof } from "../crypto/range.ts";
import { Transcript } from "../crypto/transcript.ts";
import { grantCovers, hashGrant, type AgentGrant } from "../cva/grant.ts";
import { assertActionAllowed, policyHash, type Policy } from "../cva/policy.ts";
import { isRevoked } from "../cva/revocation.ts";
import type { ExecutionContext } from "../git/context.ts";
import {
  decodePublicKey,
  decodeSignature,
  encodeKey,
  publicKeyFromSecret,
  sign,
  verifySignature,
} from "../keys.ts";
import {
  FEATURE_KEYS,
  MIN_COMPOSITION_DURATION_MS,
  MIN_COMPOSITION_INSERTS,
  type FeatureKey,
  type Features,
} from "./constants.ts";
import { extract, type Extraction } from "./extract.ts";
import { REGIONS, type Label } from "./regions.ts";
import type { SessionLog } from "./session.ts";
import { sequentialWorkHead } from "./swf.ts";

export type Binding = "process-proven" | "typed-artifact" | "signed-assertion" | "unsupported";

export const PROOF_SYSTEM = {
  commitments: "pedersen-secp256k1-v1",
  range: "sigma-bit-or-v1",
  sequentialWork: "hash-chain-v1",
  agentAuthorization: "ed25519-cva-v1",
} as const;

export type Statement = {
  version: "zk-scribe/0.1.0";
  sessionId: string;
  contentHash: string;
  swfHead: string;
  label: Label;
  assertion: string;
  counts: {
    eventCount: number;
    durationMs: number;
    insertChars: number;
    deleteChars: number;
    bulkInsertEvents: number;
  };
  role: {
    id: CreditRoleId;
    name: string;
    feasibility: Feasibility;
    binding: Binding;
    detail: string;
  };
  context: ExecutionContext;
  proofSystem: typeof PROOF_SYSTEM;
};

export type Attestation = {
  version: "zk-scribe/0.1.0";
  statement: Statement;
  policy: Policy;
  commitments: Partial<Record<FeatureKey, string>>;
  rangeProofs: Partial<Record<FeatureKey, IntervalProof>> | null;
  cva: {
    action: "attest.process" | "attest.assert";
    agentPublicKey: string;
    signature: string;
  };
  author?: AuthorEndorsement;
  grantHash?: string;
};

export type Witness = {
  version: "zk-scribe-witness/0.1.0";
  sessionId: string;
  features: Features;
  openings: Partial<Record<FeatureKey, { value: string; blinding: string }>>;
};

export type AttestInput = {
  role: string;
  contentHash: string;
  context: ExecutionContext;
  policy: Policy;
  agentSecretKey: Uint8Array;
  session?: SessionLog;
  assertion?: string;
  authorSecretKey?: Uint8Array;
  grantHash?: string;
};

export type VerifyOptions = {
  trustedAgentKey: string;
  expectedPolicy?: Policy;
  require?: "process" | "process-proven";
  requireAuthor?: boolean;
  requireGrant?: boolean;
  revokedKeys?: readonly string[];
  grant?: AgentGrant;
};

export type VerifyResult = {
  ok: boolean;
  signatureValid: boolean;
  proofsValid: boolean;
  policyValid: boolean;
  identityTrusted: boolean;
  binding: Binding | "unknown";
  label: Label | "unknown";
  role: string;
  reasons: string[];
};

const EMPTY_COUNTS: Statement["counts"] = {
  eventCount: 0,
  durationMs: 0,
  insertChars: 0,
  deleteChars: 0,
  bulkInsertEvents: 0,
};

export function attest(input: AttestInput): { attestation: Attestation; witness: Witness | null } {
  assertContentHash(input.contentHash);
  const role = getRole(input.role);
  const assertion = input.assertion?.trim() ?? "";
  const action = assertion ? "attest.assert" : "attest.process";
  assertActionAllowed(input.policy, action);

  if (assertion && input.session) {
    throw new Error("Pass either a writing session or a signed assertion, not both.");
  }

  let label: Label = "indeterminate";
  let binding: Binding = "unsupported";
  let detail = "";
  let extraction: Extraction | undefined;
  let swfHead = "";
  let sessionId = "";
  let counts = EMPTY_COUNTS;

  if (assertion) {
    if (role.feasibility !== "unobserved") {
      throw new Error(`${role.name} is attested from a writing session, not from a bare assertion.`);
    }
    binding = "signed-assertion";
    detail = "Signed claim only. The agent did not observe this contribution.";
    sessionId = `assert-${canonicalHash(assertion).slice(0, 16)}`;
  } else {
    if (!input.session) throw new Error("A session log is required for this role.");
    if (role.feasibility === "unobserved") {
      throw new Error(`${role.name} cannot be process-attested. Pass --assert with the claim text.`);
    }
    extraction = extract(input.session);
    label = extraction.label;
    swfHead = sequentialWorkHead(input.session, input.contentHash);
    sessionId = input.session.sessionId;
    counts = {
      eventCount: extraction.eventCount,
      durationMs: extraction.durationMs,
      insertChars: extraction.insertChars,
      deleteChars: extraction.deleteChars,
      bulkInsertEvents: extraction.bulkInsertEvents,
    };
    const decision = decideBinding(role.feasibility, label, extraction);
    binding = decision.binding;
    detail = decision.detail;
  }

  const statement: Statement = {
    version: "zk-scribe/0.1.0",
    sessionId,
    contentHash: input.contentHash,
    swfHead,
    label,
    assertion,
    counts,
    role: {
      id: role.id,
      name: role.name,
      feasibility: role.feasibility,
      binding,
      detail,
    },
    context: input.context,
    proofSystem: PROOF_SYSTEM,
  };

  const commitments: Attestation["commitments"] = {};
  const openings: Witness["openings"] = {};
  let rangeProofs: Attestation["rangeProofs"] = null;
  if (binding === "process-proven" || binding === "typed-artifact") {
    if (!extraction) throw new Error("Process binding is missing its extraction.");
    rangeProofs = {};
    const transcript = new Transcript("zk-scribe/pop/v1");
    transcript.absorbUtf8("statement-hash", canonicalHash(statement));
    for (const key of FEATURE_KEYS) {
      const value = BigInt(extraction.features[key]);
      const bounds = REGIONS.composition[key];
      const blinding = randomScalar();
      const commitment = commit(value, blinding);
      transcript.absorbUtf8("feature", key);
      transcript.absorb("C", commitment.toBytes(true));
      rangeProofs[key] = proveInterval({
        value,
        blinding,
        low: BigInt(bounds.min),
        high: BigInt(bounds.max),
        transcript,
      });
      commitments[key] = pointToHex(commitment);
      openings[key] = { value: value.toString(), blinding: scalarToHex(blinding) };
    }
  }

  const agentPublicKey = encodeKey(publicKeyFromSecret(input.agentSecretKey));
  const statementHash = canonicalHash(statement);
  const author = input.authorSecretKey ? endorseStatement(statementHash, input.authorSecretKey) : undefined;
  const grantHash = input.grantHash;
  if (grantHash !== undefined && !/^[0-9a-f]{64}$/.test(grantHash)) {
    throw new Error("grantHash must be a sha256 hex digest.");
  }
  const payload = signedPayload({
    action,
    agentPublicKey,
    policyHash: policyHash(input.policy),
    statementHash,
    commitments,
    rangeProofs,
    author,
    grantHash,
  });
  const attestation: Attestation = {
    version: "zk-scribe/0.1.0",
    statement,
    policy: input.policy,
    commitments,
    rangeProofs,
    cva: {
      action,
      agentPublicKey,
      signature: encodeKey(sign(utf8(payload), input.agentSecretKey)),
    },
    ...(author ? { author } : {}),
    ...(grantHash ? { grantHash } : {}),
  };
  const witness: Witness | null = extraction
    ? {
        version: "zk-scribe-witness/0.1.0",
        sessionId,
        features: extraction.features,
        openings,
      }
    : null;
  return { attestation, witness };
}

export function verify(attestation: Attestation, options: VerifyOptions): VerifyResult {
  const reasons: string[] = [];
  const binding = attestation.statement?.role?.binding ?? "unknown";
  const label = attestation.statement?.label ?? "unknown";
  const role = attestation.statement?.role?.id ?? "unknown";
  let signatureValid = false;
  let proofsValid = false;
  let policyValid = false;
  let identityTrusted = false;

  try {
    if (attestation.version !== "zk-scribe/0.1.0" || attestation.statement.version !== "zk-scribe/0.1.0") {
      reasons.push("Unsupported attestation version.");
    }
    if (!sameProofSystem(attestation.statement.proofSystem)) {
      reasons.push("Proof system id does not match sigma-range-v1.");
    }
    const trusted = encodeKey(decodePublicKey(options.trustedAgentKey));
    const presented = encodeKey(decodePublicKey(attestation.cva.agentPublicKey));
    identityTrusted = trusted === presented;
    if (!identityTrusted) reasons.push("Agent key does not match the trusted key.");
    if (isRevoked(presented, options.revokedKeys ?? [])) reasons.push("Agent key is revoked.");

    if (!options.expectedPolicy) {
      reasons.push("No expected policy was provided.");
    }
    const embeddedHash = policyHash(attestation.policy);
    policyValid = options.expectedPolicy !== undefined && policyHash(options.expectedPolicy) === embeddedHash;
    if (options.expectedPolicy && !policyValid) reasons.push("Embedded policy does not match the expected policy.");
    if (attestation.policy.deny.includes(attestation.cva.action) || !attestation.policy.allow.includes(attestation.cva.action)) {
      policyValid = false;
      reasons.push(`Policy does not allow ${attestation.cva.action}.`);
    }

    const statementHash = canonicalHash(attestation.statement);
    const payload = signedPayload({
      action: attestation.cva.action,
      agentPublicKey: attestation.cva.agentPublicKey,
      policyHash: embeddedHash,
      statementHash,
      commitments: attestation.commitments,
      rangeProofs: attestation.rangeProofs,
      author: attestation.author,
      grantHash: attestation.grantHash,
    });
    signatureValid = verifySignature(
      decodeSignature(attestation.cva.signature),
      utf8(payload),
      decodePublicKey(attestation.cva.agentPublicKey),
    );
    if (!signatureValid) reasons.push("Agent signature is invalid.");
    if (attestation.author && !authorEndorsementValid(statementHash, attestation.author)) {
      reasons.push("Author endorsement does not match the statement.");
    }
    if (options.requireAuthor && !attestation.author) reasons.push("Author endorsement is required.");
    if (options.requireGrant && !attestation.grantHash) reasons.push("A grant binding is required.");
    if (options.grant) {
      if (attestation.grantHash !== hashGrant(options.grant)) reasons.push("Grant does not match the attestation.");
      else {
        const cover = grantCovers(options.grant, {
          action: attestation.cva.action,
          agentPublicKey: attestation.cva.agentPublicKey,
          policyHash: embeddedHash,
          contentHash: attestation.statement.contentHash,
        });
        if (!cover.ok) reasons.push(...cover.reasons);
      }
    }

    proofsValid = checkProofs(attestation, reasons);
    checkBinding(attestation, reasons);
    if (options.require === "process" && binding !== "process-proven" && binding !== "typed-artifact") {
      reasons.push("Verifier required process evidence.");
    }
    if (options.require === "process-proven" && binding !== "process-proven") {
      reasons.push("Verifier required a process-proven writing role.");
    }
  } catch (error) {
    reasons.push(error instanceof Error ? error.message : "Verification failed.");
  }

  return {
    ok: reasons.length === 0,
    signatureValid,
    proofsValid,
    policyValid,
    identityTrusted,
    binding,
    label,
    role,
    reasons,
  };
}

export function audit(attestation: Attestation, session: SessionLog, witness: Witness): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const extraction = extract(session);
  if (session.sessionId !== attestation.statement.sessionId || witness.sessionId !== session.sessionId) {
    reasons.push("Session id does not match the attestation.");
  }
  if (sequentialWorkHead(session, attestation.statement.contentHash) !== attestation.statement.swfHead) {
    reasons.push("Sequential work head does not match the session and content hash.");
  }
  if (extraction.label !== attestation.statement.label) reasons.push("Recomputed label does not match.");
  const counts = attestation.statement.counts;
  if (
    extraction.eventCount !== counts.eventCount ||
    extraction.durationMs !== counts.durationMs ||
    extraction.insertChars !== counts.insertChars ||
    extraction.deleteChars !== counts.deleteChars ||
    extraction.bulkInsertEvents !== counts.bulkInsertEvents
  ) {
    reasons.push("Recomputed counts do not match.");
  }
  for (const key of FEATURE_KEYS) {
    if (witness.features[key] !== extraction.features[key]) {
      reasons.push(`Witness feature ${key} does not match the session.`);
    }
    const opening = witness.openings[key];
    const committed = attestation.commitments[key];
    if (opening && committed) {
      const point = commit(BigInt(opening.value), hexToScalar(opening.blinding));
      if (pointToHex(point) !== committed || opening.value !== String(extraction.features[key])) {
        reasons.push(`Opening for ${key} does not match the commitment.`);
      }
    } else if (attestation.statement.role.binding === "process-proven" || attestation.statement.role.binding === "typed-artifact") {
      reasons.push(`Missing opening for ${key}.`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

function decideBinding(
  feasibility: Feasibility,
  label: Label,
  extraction: Extraction,
): { binding: Binding; detail: string } {
  if (label !== "composition") {
    return {
      binding: "unsupported",
      detail: `Timing label is ${label}. This role needs a composition pattern.`,
    };
  }
  if (extraction.bulkInsertEvents > 0) {
    return { binding: "unsupported", detail: "A bulk insert blocks a composition claim." };
  }
  if (extraction.durationMs < MIN_COMPOSITION_DURATION_MS || extraction.insertChars < MIN_COMPOSITION_INSERTS) {
    return { binding: "unsupported", detail: "The session is too short to support a composition claim." };
  }
  if (feasibility === "high") {
    return {
      binding: "process-proven",
      detail: "Human composition bounds hold for this writing. The proof does not establish that the text is true.",
    };
  }
  return {
    binding: "typed-artifact",
    detail: "A human typed this artifact. The scientific result itself was not observed.",
  };
}

function checkProofs(attestation: Attestation, reasons: string[]): boolean {
  const binding = attestation.statement.role.binding;
  const needsProof = binding === "process-proven" || binding === "typed-artifact";
  if (!needsProof) {
    if (attestation.rangeProofs && Object.keys(attestation.rangeProofs).length > 0) {
      reasons.push("A non-process claim is carrying range proofs.");
      return false;
    }
    return true;
  }
  if (attestation.statement.label !== "composition") {
    reasons.push("Process evidence requires the composition label.");
    return false;
  }
  const transcript = new Transcript("zk-scribe/pop/v1");
  transcript.absorbUtf8("statement-hash", canonicalHash(attestation.statement));
  for (const key of FEATURE_KEYS) {
    const encoded = attestation.commitments[key];
    const proof = attestation.rangeProofs?.[key];
    if (!encoded || !proof) {
      reasons.push(`Missing range proof for ${key}.`);
      return false;
    }
    const commitment = hexToPoint(encoded);
    transcript.absorbUtf8("feature", key);
    transcript.absorb("C", commitment.toBytes(true));
    const bounds = REGIONS.composition[key];
    const ok = verifyInterval({
      commitment,
      low: BigInt(bounds.min),
      high: BigInt(bounds.max),
      proof,
      transcript,
    });
    if (!ok) {
      reasons.push(`Range proof for ${key} failed.`);
      return false;
    }
  }
  return true;
}

function checkBinding(attestation: Attestation, reasons: string[]): void {
  const { role, counts, swfHead, assertion, label } = attestation.statement;
  const described = getRole(role.id);
  if (described.feasibility !== role.feasibility || described.name !== role.name) {
    reasons.push("Role metadata does not match the CRediT vocabulary.");
  }
  if (role.binding === "unsupported") reasons.push(role.detail || "Binding is unsupported.");
  if (role.binding === "process-proven" && described.feasibility !== "high") {
    reasons.push("process-proven is only available for high-feasibility writing roles.");
  }
  if (role.binding === "typed-artifact" && described.feasibility !== "moderate") {
    reasons.push("typed-artifact is only available for moderate-feasibility roles.");
  }
  if (role.binding === "signed-assertion") {
    if (described.feasibility !== "unobserved") reasons.push("Signed assertions are for unobserved roles.");
    if (!assertion.trim()) reasons.push("Signed assertion text is empty.");
    if (attestation.cva.action !== "attest.assert") reasons.push("Assertion used the wrong agent action.");
  }
  if (role.binding === "process-proven" || role.binding === "typed-artifact") {
    if (label !== "composition") reasons.push("Process binding is not labeled composition.");
    if (counts.bulkInsertEvents !== 0) reasons.push("Bulk inserts are present.");
    if (counts.durationMs < MIN_COMPOSITION_DURATION_MS || counts.insertChars < MIN_COMPOSITION_INSERTS) {
      reasons.push("Public session counts are below the composition minimum.");
    }
    if (!/^[0-9a-f]{64}$/.test(swfHead)) reasons.push("Sequential work head is missing.");
    if (attestation.cva.action !== "attest.process") reasons.push("Process binding used the wrong agent action.");
  }
}

function signedPayload(body: {
  action: string;
  agentPublicKey: string;
  policyHash: string;
  statementHash: string;
  commitments: Attestation["commitments"];
  rangeProofs: Attestation["rangeProofs"];
  author?: AuthorEndorsement;
  grantHash?: string;
}): string {
  const payload: Record<string, unknown> = {
    action: body.action,
    agentPublicKey: body.agentPublicKey,
    commitments: body.commitments,
    policyHash: body.policyHash,
    rangeProofs: body.rangeProofs,
    statementHash: body.statementHash,
  };
  if (body.author) payload.author = body.author;
  if (body.grantHash) payload.grantHash = body.grantHash;
  return canonicalHash(payload);
}

function sameProofSystem(value: Statement["proofSystem"]): boolean {
  return (
    value?.commitments === PROOF_SYSTEM.commitments &&
    value?.range === PROOF_SYSTEM.range &&
    value?.sequentialWork === PROOF_SYSTEM.sequentialWork &&
    value?.agentAuthorization === PROOF_SYSTEM.agentAuthorization
  );
}

function assertContentHash(hash: string): void {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("contentHash must be a sha256 hex digest.");
}

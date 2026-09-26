import type { Attestation } from "../pop/attest.ts";

export type PublisherSummary = {
  version: "zk-scribe-summary/0.1.0";
  sessionId: string;
  contentHash: string;
  swfHead: string;
  label: string;
  role: string;
  binding: string;
  feasibility: string;
  action: string;
  agentPublicKey: string;
};

export function toSummary(attestation: Attestation): PublisherSummary {
  return {
    version: "zk-scribe-summary/0.1.0",
    sessionId: attestation.statement.sessionId,
    contentHash: attestation.statement.contentHash,
    swfHead: attestation.statement.swfHead,
    label: attestation.statement.label,
    role: attestation.statement.role.id,
    binding: attestation.statement.role.binding,
    feasibility: attestation.statement.role.feasibility,
    action: attestation.cva.action,
    agentPublicKey: attestation.cva.agentPublicKey,
  };
}

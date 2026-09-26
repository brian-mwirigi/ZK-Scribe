import { canonicalHash } from "../canon.ts";
import type { Attestation } from "./attest.ts";

export function bundleId(attestation: Attestation): string {
  return canonicalHash({
    statementHash: canonicalHash(attestation.statement),
    agentPublicKey: attestation.cva.agentPublicKey,
  });
}

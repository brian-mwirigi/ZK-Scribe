import type { Policy } from "./policy.ts";

const REQUIRED_DENIALS = ["export.raw-events", "export.plaintext", "export.witness"] as const;

export type PolicyLint = {
  ok: boolean;
  findings: string[];
};

export function lintPolicy(policy: Policy): PolicyLint {
  const findings: string[] = [];
  if (!policy.allow.includes("attest.process")) {
    findings.push("allow is missing attest.process.");
  }
  for (const action of REQUIRED_DENIALS) {
    if (!policy.deny.includes(action)) findings.push(`deny is missing ${action}.`);
  }
  if (policy.allow.some((action) => policy.deny.includes(action))) {
    findings.push("An action is both allowed and denied.");
  }
  return { ok: findings.length === 0, findings };
}

import { policyHash, actionAllowed, type Policy } from "./policy.ts";
import { lintPolicy } from "./lint.ts";
import { isRevoked } from "./revocation.ts";
import { grantCovers, hashGrant, type AgentGrant } from "./grant.ts";

export type GovernRequest = {
  action: string;
  agentPublicKey: string;
  policy: Policy;
  contentHash: string;
  revokedKeys?: readonly string[];
  grant?: AgentGrant;
};

export type GovernDecision = {
  allow: boolean;
  reasons: string[];
  grantHash?: string;
};

export function govern(request: GovernRequest): GovernDecision {
  const reasons: string[] = [];
  const lint = lintPolicy(request.policy);
  if (!lint.ok) reasons.push(...lint.findings);
  if (!actionAllowed(request.policy, request.action)) reasons.push(`Policy does not allow ${request.action}.`);
  if (isRevoked(request.agentPublicKey, request.revokedKeys ?? [])) reasons.push("Agent key is revoked.");

  let grantHash: string | undefined;
  if (request.grant) {
    grantHash = hashGrant(request.grant);
    const cover = grantCovers(request.grant, {
      action: request.action,
      agentPublicKey: request.agentPublicKey,
      policyHash: policyHash(request.policy),
      contentHash: request.contentHash,
    });
    if (!cover.ok) reasons.push(...cover.reasons);
  }

  return {
    allow: reasons.length === 0,
    reasons,
    ...(grantHash ? { grantHash } : {}),
  };
}

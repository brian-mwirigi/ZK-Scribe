import { canonicalHash } from "../canon.ts";

export type Policy = {
  version: "zk-scribe-policy/0.1.0";
  id: string;
  allow: string[];
  deny: string[];
  note: string;
};

export function defaultPolicy(): Policy {
  return {
    version: "zk-scribe-policy/0.1.0",
    id: "local-author",
    allow: [
      "capture.keystroke-timing",
      "attest.process",
      "attest.assert",
      "export.manifest",
      "export.jats",
    ],
    deny: ["export.raw-events", "export.plaintext", "export.witness"],
    note: "Time keystrokes and publish proofs. Do not publish raw events, manuscript plaintext, or commitment openings.",
  };
}

export function policyHash(policy: Policy): string {
  return canonicalHash(policy);
}

export function actionAllowed(policy: Policy, action: string): boolean {
  return policy.allow.includes(action) && !policy.deny.includes(action);
}

export function assertActionAllowed(policy: Policy, action: string): void {
  if (!actionAllowed(policy, action)) {
    throw new Error(`Policy "${policy.id}" does not allow "${action}".`);
  }
}

export type DoctorCheck = {
  name: string;
  ok: boolean;
  detail: string;
};

export function doctorReport(input: {
  nodeMajor: number;
  minimumMajor: number;
  policyExists: boolean;
  publicKeyExists: boolean;
  seedExists: boolean;
}): { ok: boolean; checks: DoctorCheck[] } {
  const checks: DoctorCheck[] = [
    {
      name: "node",
      ok: input.nodeMajor >= input.minimumMajor,
      detail: `Node ${input.nodeMajor} is ${input.nodeMajor >= input.minimumMajor ? "new enough" : `older than ${input.minimumMajor}`}.`,
    },
    {
      name: "policy",
      ok: input.policyExists,
      detail: input.policyExists ? "Consent policy is present." : "Run zk-scribe init to write .zk-scribe/policy.json.",
    },
    {
      name: "agent-public-key",
      ok: input.publicKeyExists,
      detail: input.publicKeyExists ? "Public agent key is present." : "agent.public.json is missing.",
    },
    {
      name: "agent-seed",
      ok: input.seedExists,
      detail: input.seedExists ? "Local agent seed is present." : "The private seed is missing, so this machine cannot sign.",
    },
  ];
  return { ok: checks.every((check) => check.ok), checks };
}

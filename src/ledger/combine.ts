import type { PublisherSummary } from "../manifest/summary.ts";

export type ContributionLedger = {
  version: "zk-scribe-ledger/0.1.0";
  entries: PublisherSummary[];
  counts: {
    processProven: number;
    typedArtifact: number;
    signedAssertion: number;
    other: number;
  };
};

export function buildLedger(entries: PublisherSummary[]): ContributionLedger {
  const seen = new Set<string>();
  const unique = entries.filter((entry) => {
    const id = `${entry.contentHash}:${entry.role}:${entry.agentPublicKey}:${entry.binding}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  return {
    version: "zk-scribe-ledger/0.1.0",
    entries: unique,
    counts: {
      processProven: unique.filter((entry) => entry.binding === "process-proven").length,
      typedArtifact: unique.filter((entry) => entry.binding === "typed-artifact").length,
      signedAssertion: unique.filter((entry) => entry.binding === "signed-assertion").length,
      other: unique.filter((entry) => !["process-proven", "typed-artifact", "signed-assertion"].includes(entry.binding)).length,
    },
  };
}

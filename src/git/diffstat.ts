export type DiffStat = {
  files: number;
  insertions: number;
  deletions: number;
};

export function parseDiffStat(diff: string): DiffStat {
  const files = new Set<string>();
  let insertions = 0;
  let deletions = 0;
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      const match = / b\/(.+)$/.exec(line);
      files.add(match?.[1] ?? line);
      continue;
    }
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+")) insertions += 1;
    else if (line.startsWith("-")) deletions += 1;
  }
  return { files: files.size, insertions, deletions };
}

export function reviewNote(contentHash: string, stat: DiffStat) {
  return {
    version: "zk-scribe-review-note/0.1.0" as const,
    contentHash,
    stat,
    note: "Counts from a unified diff. The note does not prove who typed the change.",
  };
}

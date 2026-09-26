import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDiffStat, reviewNote } from "../src/git/diffstat.ts";

test("a unified diff yields file and line counts", () => {
  const diff = [
    "diff --git a/draft.md b/draft.md",
    "--- a/draft.md",
    "+++ b/draft.md",
    "@@ -1 +1,2 @@",
    "-old",
    "+new",
    "+extra",
    "diff --git a/notes.md b/notes.md",
    "--- a/notes.md",
    "+++ b/notes.md",
    "+added",
  ].join("\n");
  const stat = parseDiffStat(diff);
  assert.deepEqual(stat, { files: 2, insertions: 3, deletions: 1 });
  assert.equal(reviewNote("ab".repeat(32), stat).stat.files, 2);
});

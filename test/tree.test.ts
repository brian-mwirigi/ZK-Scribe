import assert from "node:assert/strict";
import { test } from "node:test";
import { utf8 } from "../src/canon.ts";
import { hashTree, ignoredTreePath } from "../src/hash/tree.ts";

test("a directory hash ignores path order and skips private material", () => {
  const forward = hashTree([
    { path: "b.txt", bytes: utf8("beta") },
    { path: "a.txt", bytes: utf8("alpha") },
  ]);
  const backward = hashTree([
    { path: "a.txt", bytes: utf8("alpha") },
    { path: "b.txt", bytes: utf8("beta") },
  ]);
  assert.equal(forward, backward);
  assert.notEqual(forward, hashTree([{ path: "a.txt", bytes: utf8("alpha") }]));
  assert.equal(ignoredTreePath(".zk-scribe/private/agent.seed"), true);
  assert.equal(ignoredTreePath("notes\\draft.witness.json"), true);
  assert.equal(ignoredTreePath("manuscript.md"), false);
});

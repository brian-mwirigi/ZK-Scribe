import assert from "node:assert/strict";
import { test } from "node:test";
import { suggestRole } from "../src/credit/suggest.ts";

test("file extensions suggest a CRediT role without upgrading unobserved work", () => {
  assert.equal(suggestRole("stats/model.R").role, "software");
  assert.equal(suggestRole("notes/draft.tex").role, "writing-original-draft");
  assert.equal(suggestRole("figures/plot.svg").role, "visualization");
  assert.equal(suggestRole("README").role, "writing-original-draft");
  assert.match(suggestRole("src/app.ts").reason, /Extension \.ts/);
});

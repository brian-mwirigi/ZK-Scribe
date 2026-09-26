import assert from "node:assert/strict";
import { test } from "node:test";
import { explainFeatures } from "../src/pop/explain.ts";
import { extract } from "../src/pop/extract.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";

test("explanation names the failing composition bounds for a paste", () => {
  const extraction = extract(synthesizeSession("paste"));
  const explanation = explainFeatures(extraction.features, extraction.bulkInsertEvents);
  assert.equal(explanation.label, "automated");
  assert.equal(explanation.checks.composition.every((check) => check.inside), false);
  assert.equal(explanation.checks.automated.every((check) => check.inside), true);
});

test("a composition session passes every composition bound", () => {
  const extraction = extract(synthesizeSession("composition"));
  const explanation = explainFeatures(extraction.features, extraction.bulkInsertEvents);
  assert.equal(explanation.label, "composition");
  assert.equal(explanation.checks.composition.every((check) => check.inside), true);
  assert.match(explanation.note, /composition bound/);
});

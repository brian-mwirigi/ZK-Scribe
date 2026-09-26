import assert from "node:assert/strict";
import { test } from "node:test";
import { pauseHistogram } from "../src/pop/histogram.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";

test("pause bins count gaps and do not echo timestamps", () => {
  const session = synthesizeSession("composition");
  const bins = pauseHistogram(session.events);
  const encoded = JSON.stringify(bins);
  assert.equal(encoded.includes("1400"), false);
  assert.equal(encoded.includes("\"t\""), false);
  const planning = bins.filter((bin) => bin.label === "1000-1999" || bin.label === "2000-5000");
  assert.equal(planning.some((bin) => bin.count > 0), true);
  assert.equal(bins.reduce((sum, bin) => sum + bin.count, 0), session.events.length - 1);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { eventsFromEdit } from "../src/capture/edits.ts";

test("a save is one edit, not a reconstructed keystroke stream", () => {
  const before = "The assay was repeated.";
  const after = "The assay was repeated across three evenings.";
  const events = eventsFromEdit(before, after, 1200);
  assert.equal(events.length, 1);
  assert.equal(events[0].op, "insert");
  assert.equal(events[0].len, after.length - before.length);
  assert.equal(events[0].t, 1200);
  assert.equal(eventsFromEdit(after, before, 1400)[0].op, "delete");
  assert.deepEqual(eventsFromEdit(before, before, 0), []);
});

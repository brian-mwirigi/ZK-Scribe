import assert from "node:assert/strict";
import { test } from "node:test";
import { sessionStats } from "../src/pop/stats.ts";
import { synthesizeSession } from "../src/pop/synthesize.ts";

test("session stats summarize a log without copying events", () => {
  const session = synthesizeSession("transcription");
  const stats = sessionStats(session);
  assert.equal(stats.label, "transcription");
  assert.equal(stats.sessionId, session.sessionId);
  assert.equal(JSON.stringify(stats).includes("\"op\""), false);
});

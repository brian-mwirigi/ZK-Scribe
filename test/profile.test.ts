import assert from "node:assert/strict";
import { test } from "node:test";
import { localProfile } from "../src/pop/profile.ts";
import type { SessionLog } from "../src/pop/session.ts";

function session(times: number[]): SessionLog {
  return {
    sessionId: "local",
    startedAt: "2026-01-01T00:00:00.000Z",
    events: times.map((t) => ({ t, op: "insert", len: 1 })),
  };
}

test("local timing profile reports pause percentiles and omits events", () => {
  const flat = localProfile(session([0, 100, 200, 300, 400]));
  assert.equal(flat.samples, 4);
  assert.equal(flat.p10, 100);
  assert.equal(flat.p50, 100);
  assert.equal(flat.p90, 100);
  const empty = localProfile(session([0]));
  assert.deepEqual(empty, { samples: 0, p10: null, p50: null, p90: null });
  assert.equal(JSON.stringify(flat).includes("\"op\""), false);
});

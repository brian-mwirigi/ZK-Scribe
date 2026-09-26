import assert from "node:assert/strict";
import { test } from "node:test";
import { statusText, type StatusCounts } from "../src/status.ts";

const empty: StatusCounts = {
  initialized: true,
  watching: true,
  root: "content/",
  attested: 0,
  processProven: 0,
  typedArtifact: 0,
  signedAssertion: 0,
  refused: 0,
};

test("status names the ledger once commits have been attested", () => {
  assert.match(statusText({ ...empty, watching: false, attested: 0 }), /No sessions attested yet/);
  const building = statusText({
    ...empty,
    attested: 3,
    processProven: 1,
    refused: 2,
  });
  assert.match(building, /3 sessions attested, ledger building/);
  assert.match(building, /1 process-proven · 2 refused/);
  assert.match(building, /Watching content\//);
  assert.match(statusText({ ...empty, initialized: false }), /zk-scribe init/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { defaultConfig, parseConfig } from "../src/config.ts";

test("project config keeps a default role and rejects a bad environment", () => {
  assert.equal(parseConfig(defaultConfig()).defaultRole, "writing-original-draft");
  assert.throws(() => parseConfig({ version: "zk-scribe-config/0.1.0", defaultRole: "software", environment: "cloud" }));
  const parsed = parseConfig({
    version: "zk-scribe-config/0.1.0",
    defaultRole: "software",
    environment: "overleaf-git",
  });
  assert.equal(parsed.environment, "overleaf-git");
});

test("a saved config round-trips through JSON", () => {
  const saved = JSON.parse(JSON.stringify(defaultConfig())) as unknown;
  assert.equal(parseConfig(saved).defaultRole, "writing-original-draft");
});

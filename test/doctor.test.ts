import assert from "node:assert/strict";
import { test } from "node:test";
import { doctorReport } from "../src/doctor.ts";

test("doctor fails closed when the policy or the seed is missing", () => {
  const report = doctorReport({
    nodeMajor: 24,
    minimumMajor: 22,
    policyExists: false,
    publicKeyExists: true,
    seedExists: false,
  });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.name === "policy")?.ok, false);
  assert.equal(report.checks.find((check) => check.name === "node")?.ok, true);
});

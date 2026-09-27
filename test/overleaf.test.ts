import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { appendRemoteEdits, readSession, scanOnce } from "../src/capture/watch.ts";
import { startOverleafBridge } from "../src/capture/overleaf.ts";

test("an Overleaf session is not extended by a later file save", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-overleaf-"));
  const file = path.join(dir, "main.tex");
  fs.writeFileSync(file, "\\section{Methods}\n");
  assert.equal(scanOnce(dir), 0);
  assert.equal(appendRemoteEdits(dir, [{ removed: 0, inserted: "a" }], 1_700_000_000_000), 1);
  fs.writeFileSync(file, "\\section{Methods}\nA paragraph arrived from the Git bridge and should not be split.\n");
  assert.equal(scanOnce(dir), 0);
  const session = readSession(dir);
  assert.ok(session);
  assert.equal(session.source, "overleaf");
  assert.equal(session.events.length, 1);
  assert.equal(session.events[0].op, "insert");
  assert.equal(JSON.stringify(session).includes("Git bridge"), false);
  assert.equal(JSON.stringify(session).includes("Methods"), false);
});

test("the local bridge accepts lengths and refuses manuscript text", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-scribe-bridge-"));
  const bridge = await startOverleafBridge(dir);
  try {
    assert.equal(await post(bridge.port, bridge.token, { changes: [{ removed: 0, len: 1 }] }, false), 401);
    const leaked = {
      changes: [{ removed: 0, len: 4, boundary: false, text: "secret-manuscript" }],
    };
    assert.equal(await post(bridge.port, bridge.token, leaked), 400);
    assert.equal(
      await post(bridge.port, bridge.token, { changes: [{ removed: 0, len: 1, boundary: true }] }),
      204,
    );
    assert.equal(
      await post(bridge.port, bridge.token, { changes: [{ removed: 0, len: 20, boundary: false }] }),
      204,
    );
    const session = readSession(dir);
    assert.ok(session);
    assert.equal(session.source, "overleaf");
    assert.equal(session.events[0].op, "insert");
    assert.equal(session.events[0].len, 1);
    assert.equal(session.events[0].boundary, true);
    assert.equal(session.events[1].op, "paste");
    assert.equal(session.events[1].len, 20);
    const encoded = JSON.stringify(session);
    assert.equal(encoded.includes("secret-manuscript"), false);
    assert.equal(encoded.includes("x".repeat(15)), false);
  } finally {
    await bridge.close();
  }
});

function post(port: number, token: string, body: unknown, authorize = true): Promise<number> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/events",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...(authorize ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode ?? 0));
      },
    );
    request.on("error", reject);
    request.end(payload);
  });
}

import { randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import type { TextChange } from "./document.ts";
import { appendRemoteEdits, readSession, writeSessionAnchor } from "./watch.ts";
import { fetchLatest, QUICKNET, windowProblem, type TimeAnchor, type TimeRound } from "../time/drand.ts";

const MAX_BODY = 8_192;
const MAX_CHANGES = 40;
const MAX_SPAN = 100_000;

export type OverleafBridge = {
  port: number;
  token: string;
  close: () => Promise<void>;
};

export function startOverleafBridge(dir: string): Promise<OverleafBridge> {
  const root = path.resolve(dir);
  const token = randomBytes(32).toString("hex");
  let start: TimeRound | null = null;
  let refreshing = false;

  const refresh = async () => {
    if (refreshing) return;
    refreshing = true;
    try {
      if (!start) start = await fetchLatest();
      const end = await fetchLatest();
      const session = readSession(root);
      if (!session || session.events.length === 0) return;
      const duration = session.events[session.events.length - 1].t - session.events[0].t;
      const anchor: TimeAnchor = {
        scheme: "drand-quicknet-v1",
        startedAt: session.startedAt,
        start,
        end,
      };
      if (windowProblem(anchor, duration) === null) writeSessionAnchor(root, anchor);
    } catch {
      // The session is still saved. It is not bound to a wall-clock window.
    } finally {
      refreshing = false;
    }
  };

  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      if (request.method === "OPTIONS") {
        response.writeHead(204, {
          "access-control-allow-origin": "https://www.overleaf.com",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-allow-methods": "POST, OPTIONS",
        });
        response.end();
        return;
      }
      if (request.method !== "POST" || request.url !== "/events") {
        response.writeHead(404);
        response.end();
        return;
      }
      if (!bearerMatches(request.headers.authorization, token)) {
        response.writeHead(401);
        response.end();
        return;
      }
      readBody(request)
        .then((raw) => {
          const changes = changesFromWire(raw);
          appendRemoteEdits(root, changes);
          void refresh();
          response.writeHead(204);
          response.end();
        })
        .catch(() => {
          response.writeHead(400);
          response.end();
        });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Overleaf bridge did not bind a local port."));
        return;
      }
      writeBridgeFile(root, token, address.port);
      const timer = setInterval(() => void refresh(), QUICKNET.period * 1000);
      void refresh();
      resolve({
        port: address.port,
        token,
        close: () =>
          new Promise((done) => {
            clearInterval(timer);
            server.close(() => done());
          }),
      });
    });
  });
}

function changesFromWire(raw: string): TextChange[] {
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("bad");
  const body = parsed as Record<string, unknown>;
  if (Object.keys(body).some((key) => key !== "changes")) throw new Error("bad");
  if (!Array.isArray(body.changes) || body.changes.length === 0 || body.changes.length > MAX_CHANGES) {
    throw new Error("bad");
  }
  return body.changes.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("bad");
    const change = item as Record<string, unknown>;
    if (Object.keys(change).some((key) => key !== "removed" && key !== "len" && key !== "boundary")) {
      throw new Error("bad");
    }
    const removed = change.removed ?? 0;
    const len = change.len ?? 0;
    if (!whole(removed) || !whole(len) || removed > MAX_SPAN || len > MAX_SPAN || (removed === 0 && len === 0)) {
      throw new Error("bad");
    }
    const boundary = change.boundary === true;
    const inserted = len === 0 ? "" : boundary ? `${"x".repeat(len - 1)}.` : "x".repeat(len);
    return { removed, inserted };
  });
}

function whole(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function bearerMatches(header: string | undefined, token: string): boolean {
  const expected = Buffer.from(`Bearer ${token}`);
  const given = Buffer.from(header ?? "");
  if (expected.length !== given.length) return false;
  return timingSafeEqual(expected, given);
}

function readBody(request: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("bad"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function writeBridgeFile(dir: string, token: string, port: number): void {
  const file = path.join(dir, ".zk-scribe", "private", "overleaf.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify({ token, port })}\n`, { mode: 0o600 });
}

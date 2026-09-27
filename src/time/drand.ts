import https from "node:https";
import tls from "node:tls";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { SessionLog } from "../pop/session.ts";

// League of Entropy quicknet. Signatures verify locally. ZK-Scribe does not run a time service.
export const QUICKNET = {
  hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  publicKey:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  genesis: 1_692_803_367,
  period: 3,
  scheme: "bls-unchained-g1-rfc9380",
} as const;

export type TimeRound = {
  chain: typeof QUICKNET.hash;
  round: number;
  signature: string;
};

export type TimeAnchor = {
  scheme: "drand-quicknet-v1";
  startedAt: string;
  start: TimeRound;
  end: TimeRound;
};

const bls = bls12_381.shortSignatures;

export function roundUnix(round: number): number {
  return QUICKNET.genesis + (round - 1) * QUICKNET.period;
}

export function roundAt(unixMs: number): number {
  const unix = Math.floor(unixMs / 1000);
  if (unix < QUICKNET.genesis) return 0;
  return Math.floor((unix - QUICKNET.genesis) / QUICKNET.period) + 1;
}

export function verifyRound(round: TimeRound): boolean {
  if (round.chain !== QUICKNET.hash || !Number.isInteger(round.round) || round.round < 1) return false;
  if (!/^[0-9a-f]{96}$/.test(round.signature)) return false;
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(round.round));
  try {
    const message = bls.hash(sha256(bytes));
    return bls.verify(hexToBytes(round.signature), message, hexToBytes(QUICKNET.publicKey));
  } catch {
    return false;
  }
}

export function coverageProblem(startRound: number, endRound: number, durationMs: number, startedAt: string): string | null {
  if (!Number.isInteger(startRound) || !Number.isInteger(endRound) || endRound <= startRound) {
    return "Time beacon window is empty.";
  }
  const startMs = roundUnix(startRound) * 1000;
  const endMs = roundUnix(endRound) * 1000;
  const span = endMs - startMs + QUICKNET.period * 1000;
  if (span < durationMs) return "Time beacon window is shorter than the session.";
  const started = Date.parse(startedAt);
  if (!Number.isFinite(started)) return "Session start time is missing.";
  if (started < startMs - QUICKNET.period * 1000 || started > endMs + QUICKNET.period * 1000) {
    return "Session start is outside the time beacon window.";
  }
  return null;
}

export function windowProblem(anchor: TimeAnchor, durationMs: number): string | null {
  if (anchor.scheme !== "drand-quicknet-v1") return "Unknown time anchor.";
  if (anchor.start.chain !== anchor.end.chain) return "Time beacon chain does not match.";
  if (!verifyRound(anchor.start) || !verifyRound(anchor.end)) return "Time beacon signature is invalid.";
  return coverageProblem(anchor.start.round, anchor.end.round, durationMs, anchor.startedAt);
}

export function chainDomain(anchor: TimeAnchor): string {
  return `${anchor.start.round}:${anchor.start.signature}:${anchor.end.round}:${anchor.end.signature}`;
}

export async function fetchLatest(): Promise<TimeRound> {
  return fetchRoundNumber("latest");
}

export async function fetchRound(round: number): Promise<TimeRound> {
  if (!Number.isInteger(round) || round < 1) throw new Error("Time beacon round is invalid.");
  const parsed = await fetchRoundNumber(String(round));
  if (parsed.round !== round) throw new Error("Time beacon returned a different round.");
  return parsed;
}

export async function ensureAnchor(session: SessionLog): Promise<SessionLog> {
  const duration = durationOf(session);
  if (
    session.timeAnchor &&
    session.timeAnchor.startedAt === session.startedAt &&
    windowProblem(session.timeAnchor, duration) === null
  ) {
    return session;
  }
  const started = Date.parse(session.startedAt);
  if (!Number.isFinite(started)) return clearAnchor(session);
  const startRound = roundAt(started);
  if (startRound < 1) return clearAnchor(session);
  try {
    const start =
      session.timeAnchor?.start &&
      session.timeAnchor.start.round === startRound &&
      verifyRound(session.timeAnchor.start)
        ? session.timeAnchor.start
        : await fetchRound(startRound);
    let end = await fetchLatest();
    let anchor: TimeAnchor = { scheme: "drand-quicknet-v1", startedAt: session.startedAt, start, end };
    for (let attempt = 0; attempt < 3 && needsAnotherRound(windowProblem(anchor, duration)); attempt += 1) {
      await delay(QUICKNET.period * 1000 + 400);
      end = await fetchLatest();
      anchor = { scheme: "drand-quicknet-v1", startedAt: session.startedAt, start, end };
    }
    if (windowProblem(anchor, duration)) return clearAnchor(session);
    return { ...session, timeAnchor: anchor };
  } catch {
    return clearAnchor(session);
  }
}

async function fetchRoundNumber(round: string): Promise<TimeRound> {
  const body = await getJson(`https://api.drand.sh/${QUICKNET.hash}/public/${round}`);
  const parsed: TimeRound = {
    chain: QUICKNET.hash,
    round: Number(body.round),
    signature: String(body.signature ?? ""),
  };
  if (!verifyRound(parsed)) throw new Error("Time beacon signature did not verify.");
  return parsed;
}

function durationOf(session: SessionLog): number {
  const events = session.events;
  if (events.length === 0) return 0;
  return events[events.length - 1].t - events[0].t;
}

function clearAnchor(session: SessionLog): SessionLog {
  if (!session.timeAnchor) return session;
  const next = { ...session };
  delete next.timeAnchor;
  return next;
}

function getJson(url: string): Promise<{ round?: number; signature?: string }> {
  const ca = tls.getCACertificates("system");
  return new Promise((resolve, reject) => {
    const request = https.get(url, { ca }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        if ((response.statusCode ?? 500) >= 400) {
          reject(new Error(`Time beacon responded ${response.statusCode}.`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as { round?: number; signature?: string });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(8_000, () => request.destroy(new Error("Time beacon timed out.")));
    request.on("error", reject);
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function needsAnotherRound(problem: string | null): boolean {
  return problem === "Time beacon window is empty." || problem === "Time beacon window is shorter than the session.";
}

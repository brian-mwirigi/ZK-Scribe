#!/usr/bin/env node

// src/cli.ts
import fs5 from "node:fs";
import path6 from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

// src/canon.ts
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
function utf8(value) {
  return new TextEncoder().encode(value);
}
function sha256Hex(data) {
  return bytesToHex(sha256(data));
}
function canonicalize(value) {
  return JSON.stringify(sortValue(value));
}
function canonicalHash(value) {
  return sha256Hex(utf8(canonicalize(value)));
}
function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const source = value;
    const sorted = {};
    for (const key of Object.keys(source).sort()) sorted[key] = sortValue(source[key]);
    return sorted;
  }
  return value;
}

// src/crypto/group.ts
import { secp256k1, secp256k1_hasher } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE, randomBytes } from "@noble/curves/utils.js";
import { bytesToHex as bytesToHex2, hexToBytes } from "@noble/hashes/utils.js";
var Point = secp256k1.Point;
var ORDER = Point.Fn.ORDER;
var G = Point.BASE;
var ZERO = Point.ZERO;
var H = secp256k1_hasher.hashToCurve(utf8("ZK-Scribe/pedersen-h/v1"), {
  DST: "ZK-Scribe-pedersen-v1"
});
function modN(value) {
  const reduced = value % ORDER;
  return reduced >= 0n ? reduced : reduced + ORDER;
}
function randomScalar() {
  for (; ; ) {
    const scalar = bytesToNumberBE(randomBytes(32)) % ORDER;
    if (scalar !== 0n) return scalar;
  }
}
function mul(point, scalar) {
  const reduced = modN(scalar);
  if (reduced === 0n) return Point.ZERO;
  return point.multiply(reduced);
}
function commit(message, blinding) {
  return mul(G, message).add(mul(H, blinding));
}
function scalarToHex(scalar) {
  return bytesToHex2(numberToBytesBE(modN(scalar), 32));
}
function hexToScalar(hex) {
  const scalar = bytesToNumberBE(hexToBytes(hex));
  if (scalar < 0n || scalar >= ORDER) throw new Error("Scalar is outside the field.");
  return scalar;
}
function pointToHex(point) {
  return bytesToHex2(point.toBytes(true));
}
function hexToPoint(hex) {
  return Point.fromBytes(hexToBytes(hex));
}

// src/crypto/transcript.ts
import { sha256 as sha2562 } from "@noble/hashes/sha2.js";
import { bytesToNumberBE as bytesToNumberBE2, concatBytes, numberToBytesBE as numberToBytesBE2 } from "@noble/curves/utils.js";
var Transcript = class {
  state;
  constructor(label) {
    this.state = sha2562(utf8(`ZK-Scribe/transcript/v1:${label}`));
  }
  absorb(label, data) {
    const length = numberToBytesBE2(data.length, 4);
    this.state = sha2562(concatBytes(this.state, utf8(`|${label}|`), length, data));
  }
  absorbUtf8(label, value) {
    this.absorb(label, utf8(value));
  }
  challenge() {
    const digest = sha2562(concatBytes(this.state, utf8("|challenge")));
    this.state = sha2562(concatBytes(this.state, digest));
    return modN(bytesToNumberBE2(digest));
  }
};

// src/crypto/range.ts
function bitsForSpan(span) {
  if (span < 0n) throw new Error("Range span is negative.");
  let bits = 0;
  let capacity = 1n;
  while (capacity <= span) {
    bits += 1;
    capacity <<= 1n;
    if (bits > 20) throw new Error("Range is too wide for sigma-range-v1.");
  }
  return bits;
}
function proveInterval(args) {
  const { value, blinding, low, high, transcript } = args;
  if (value < low || value > high) {
    throw new Error(`Value ${value} is outside [${low}, ${high}].`);
  }
  const bits = bitsForSpan(high - low);
  const commitment = commit(value, blinding);
  const lowSide = proveSide({
    commitment: commitment.subtract(mul(G, low)),
    shifted: value - low,
    blinding,
    bits,
    side: "low",
    transcript
  });
  const highSide = proveSide({
    commitment: mul(G, high).subtract(commitment),
    shifted: high - value,
    blinding: modN(-blinding),
    bits,
    side: "high",
    transcript
  });
  return {
    bits,
    low: lowSide.bits,
    high: highSide.bits,
    lowLink: lowSide.link,
    highLink: highSide.link
  };
}
function verifyInterval(args) {
  try {
    const { commitment, low, high, proof, transcript } = args;
    if (low > high) return false;
    const bits = bitsForSpan(high - low);
    if (proof.bits !== bits || proof.low.length !== bits || proof.high.length !== bits) return false;
    const lowCommitment = commitment.subtract(mul(G, low));
    const highCommitment = mul(G, high).subtract(commitment);
    if (!verifySide(lowCommitment, proof.low, proof.lowLink, bits, "low", transcript)) return false;
    if (!verifySide(highCommitment, proof.high, proof.highLink, bits, "high", transcript)) return false;
    return true;
  } catch {
    return false;
  }
}
function proveSide(args) {
  const { commitment, shifted, blinding, bits, side, transcript } = args;
  transcript.absorbUtf8("side", side);
  const bitProofs = [];
  const bitCommitments = [];
  const bitBlindings = [];
  for (let index = 0; index < bits; index += 1) {
    const bit = Number(shifted >> BigInt(index) & 1n);
    const bitBlinding = randomScalar();
    const bitCommitment = commit(BigInt(bit), bitBlinding);
    bitProofs.push(proveBit(bitCommitment, bit, bitBlinding, transcript));
    bitCommitments.push(bitCommitment);
    bitBlindings.push(bitBlinding);
  }
  let weightedBlind = 0n;
  let place = 1n;
  for (let index = 0; index < bits; index += 1) {
    weightedBlind = modN(weightedBlind + place * bitBlindings[index]);
    place <<= 1n;
  }
  const difference = commitment.subtract(weightedCommitments(bitCommitments));
  const differenceBlinding = modN(blinding - weightedBlind);
  if (!mul(H, differenceBlinding).equals(difference)) {
    throw new Error("Range link does not match the bit decomposition.");
  }
  return {
    bits: bitProofs,
    link: proveLink(difference, differenceBlinding, transcript)
  };
}
function verifySide(commitment, bitProofs, link, bits, side, transcript) {
  if (bitProofs.length !== bits) return false;
  transcript.absorbUtf8("side", side);
  const bitCommitments = [];
  for (const proof of bitProofs) {
    const bitCommitment = hexToPoint(proof.commitment);
    if (!verifyBit(bitCommitment, proof, transcript)) return false;
    bitCommitments.push(bitCommitment);
  }
  const difference = commitment.subtract(weightedCommitments(bitCommitments));
  return verifyLink(difference, link, transcript);
}
function proveBit(commitment, bit, blinding, transcript) {
  const y0 = commitment;
  const y1 = commitment.subtract(G);
  const simulated = randomScalar();
  const simulatedResponse = randomScalar();
  const nonce = randomScalar();
  let a0;
  let a1;
  let c0;
  let c1;
  let z0;
  let z1;
  if (bit === 0) {
    c1 = simulated;
    z1 = simulatedResponse;
    a1 = mul(H, z1).subtract(mul(y1, c1));
    a0 = mul(H, nonce);
    absorbBit(transcript, commitment, a0, a1);
    const challenge = transcript.challenge();
    c0 = modN(challenge - c1);
    z0 = modN(nonce + c0 * blinding);
  } else if (bit === 1) {
    c0 = simulated;
    z0 = simulatedResponse;
    a0 = mul(H, z0).subtract(mul(y0, c0));
    a1 = mul(H, nonce);
    absorbBit(transcript, commitment, a0, a1);
    const challenge = transcript.challenge();
    c1 = modN(challenge - c0);
    z1 = modN(nonce + c1 * blinding);
  } else {
    throw new Error("Bit decomposition produced a non-bit.");
  }
  return {
    commitment: pointToHex(commitment),
    a0: pointToHex(a0),
    a1: pointToHex(a1),
    c0: scalarToHex(c0),
    c1: scalarToHex(c1),
    z0: scalarToHex(z0),
    z1: scalarToHex(z1)
  };
}
function verifyBit(commitment, proof, transcript) {
  const a0 = hexToPoint(proof.a0);
  const a1 = hexToPoint(proof.a1);
  absorbBit(transcript, commitment, a0, a1);
  const challenge = transcript.challenge();
  const c0 = hexToScalar(proof.c0);
  const c1 = hexToScalar(proof.c1);
  const z0 = hexToScalar(proof.z0);
  const z1 = hexToScalar(proof.z1);
  if (modN(c0 + c1) !== challenge) return false;
  const y0 = commitment;
  const y1 = commitment.subtract(G);
  const left0 = mul(H, z0);
  const right0 = a0.add(mul(y0, c0));
  const left1 = mul(H, z1);
  const right1 = a1.add(mul(y1, c1));
  return left0.equals(right0) && left1.equals(right1);
}
function proveLink(difference, blinding, transcript) {
  const nonce = randomScalar();
  const announcement = mul(H, nonce);
  transcript.absorb("D", difference.toBytes(true));
  transcript.absorb("A", announcement.toBytes(true));
  const challenge = transcript.challenge();
  return {
    a: pointToHex(announcement),
    c: scalarToHex(challenge),
    z: scalarToHex(modN(nonce + challenge * blinding))
  };
}
function verifyLink(difference, proof, transcript) {
  const announcement = hexToPoint(proof.a);
  transcript.absorb("D", difference.toBytes(true));
  transcript.absorb("A", announcement.toBytes(true));
  const challenge = transcript.challenge();
  if (hexToScalar(proof.c) !== challenge) return false;
  const response = hexToScalar(proof.z);
  return mul(H, response).equals(announcement.add(mul(difference, challenge)));
}
function absorbBit(transcript, commitment, a0, a1) {
  transcript.absorb("Ci", commitment.toBytes(true));
  transcript.absorb("A0", a0.toBytes(true));
  transcript.absorb("A1", a1.toBytes(true));
}
function weightedCommitments(commitments) {
  let sum = ZERO;
  let place = 1n;
  for (const commitment of commitments) {
    sum = sum.add(mul(commitment, place));
    place <<= 1n;
  }
  return sum;
}

// src/crypto/benchmark.ts
function rangeBenchmark() {
  const started = performance.now();
  const proof = proveInterval({
    value: 7n,
    blinding: randomScalar(),
    low: 0n,
    high: 15n,
    transcript: new Transcript("zk-scribe/benchmark")
  });
  return {
    low: 0,
    high: 15,
    milliseconds: performance.now() - started,
    bits: proof.bits
  };
}

// src/capture/keys.ts
function eventFromKey(key, t) {
  if (key.ctrl && key.name === "c") return { kind: "abort" };
  if (key.ctrl && key.name === "d") return { kind: "finish" };
  if (key.name === "backspace") {
    return { kind: "event", event: { t, op: "delete", len: 1 }, textDelta: "" };
  }
  if (key.name === "left" || key.name === "right" || key.name === "up" || key.name === "down") {
    return { kind: "event", event: { t, op: "navigate", len: 1 }, textDelta: "" };
  }
  const sequence = key.sequence ?? "";
  if (!sequence || key.ctrl || key.meta) return { kind: "ignore" };
  const boundary = /[.!?;:\n]/.test(sequence);
  const paste2 = sequence.length >= 15;
  return {
    kind: "event",
    event: {
      t,
      op: paste2 ? "paste" : "insert",
      len: sequence.length,
      boundary
    },
    textDelta: sequence
  };
}
function applyTextDelta(buffer, event, textDelta) {
  if (event.op === "delete") return buffer.slice(0, -event.len);
  if (event.op === "insert" || event.op === "paste") return buffer + textDelta;
  return buffer;
}

// src/capture/overleaf.ts
import { randomBytes as randomBytes2, timingSafeEqual } from "node:crypto";
import fs2 from "node:fs";
import http from "node:http";
import path2 from "node:path";

// src/capture/watch.ts
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// src/pop/constants.ts
var PLANNING_PAUSE_MIN_MS = 1e3;
var PLANNING_PAUSE_MAX_MS = 5e3;
var PEAK_WINDOW_MS = 2e3;
var BULK_INSERT_CHARS = 15;
var MIN_COMPOSITION_DURATION_MS = 8e3;
var MIN_COMPOSITION_INSERTS = 20;
var FEATURE_KEYS = [
  "medianIkiMs",
  "ikiCvTimes100",
  "planningPauses",
  "boundaryPauses",
  "peakCpsTimes10",
  "revisionPermille"
];

// src/capture/document.ts
function eventsFromTextChange(change, t) {
  const events = [];
  if (change.removed > 0) events.push({ t, op: "delete", len: change.removed });
  const inserted = change.inserted;
  if (inserted.length > 0) {
    const boundary = /[\s.!?;:\n]$/.test(inserted);
    events.push({
      t,
      op: inserted.length >= BULK_INSERT_CHARS ? "paste" : "insert",
      len: inserted.length,
      ...boundary ? { boundary: true } : {}
    });
  }
  return events;
}

// src/capture/edits.ts
function eventsFromEdit(before, after, t) {
  if (before === after) return [];
  let prefix = 0;
  const maxPrefix = Math.min(before.length, after.length);
  while (prefix < maxPrefix && before.charCodeAt(prefix) === after.charCodeAt(prefix)) prefix += 1;
  let suffix = 0;
  const maxSuffix = maxPrefix - prefix;
  while (suffix < maxSuffix && before.charCodeAt(before.length - 1 - suffix) === after.charCodeAt(after.length - 1 - suffix)) {
    suffix += 1;
  }
  const removed = before.length - prefix - suffix;
  const added = after.length - prefix - suffix;
  const events = [];
  if (removed > 0) events.push({ t, op: "delete", len: removed });
  if (added > 0) {
    const chunk = after.slice(prefix, after.length - suffix);
    const boundary = /[\s.!?]$/.test(chunk);
    events.push({ t, op: "insert", len: added, ...boundary ? { boundary: true } : {} });
  }
  return events;
}

// src/entry.ts
function cliArgs() {
  const script = process.argv[1] ?? "";
  if (script.endsWith(".ts")) return ["--experimental-strip-types", script];
  return [script];
}

// src/capture/watch.ts
var TEXT = /* @__PURE__ */ new Set([".md", ".markdown", ".tex", ".txt"]);
var SKIP = /* @__PURE__ */ new Set([".git", ".zk-scribe", "node_modules", "output", "build", "dist"]);
var MAX_CHARS = 2e6;
function watchLabel(dir) {
  return fs.existsSync(path.join(dir, "content")) ? "content/" : "this directory";
}
function listManuscripts(dir) {
  const content = path.join(dir, "content");
  const root = fs.existsSync(content) && fs.statSync(content).isDirectory() ? content : dir;
  const files = [];
  const walk = (folder) => {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      if (entry.name.startsWith(".") || SKIP.has(entry.name)) continue;
      const full = path.join(folder, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (isManuscriptName(entry.name)) files.push(full);
    }
  };
  if (fs.existsSync(root)) walk(root);
  return files;
}
function isManuscriptRelative(dir, relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  if (!normalized || normalized.startsWith(".zk-scribe/") || normalized.split("/").some((part) => part.startsWith("."))) {
    return false;
  }
  const base = normalized.slice(normalized.lastIndexOf("/") + 1);
  if (!isManuscriptName(base)) return false;
  const hasContent = fs.existsSync(path.join(dir, "content"));
  if (hasContent && !normalized.startsWith("content/")) return false;
  return true;
}
function sessionPath(dir) {
  return path.join(dir, ".zk-scribe", "private", "session.json");
}
function readSession(dir) {
  const file = sessionPath(dir);
  if (!fs.existsSync(file)) return null;
  const session = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(session.events) || session.events.length === 0) return null;
  return session;
}
function rotateSession(dir) {
  const file = sessionPath(dir);
  if (fs.existsSync(file)) fs.rmSync(file);
}
function scanOnce(dir, now = Date.now()) {
  const state = readState(dir);
  const current = readSession(dir);
  const started = current ? Date.parse(current.startedAt) : now;
  let t = Math.max(0, now - (Number.isFinite(started) ? started : now));
  if (current && current.events.length > 0) t = Math.max(t, current.events[current.events.length - 1].t);
  const next = {};
  const events = [];
  const captured = current?.source === "editor" || current?.source === "overleaf" || current?.source === "record";
  for (const file of listManuscripts(dir)) {
    const relative = path.relative(dir, file).replaceAll("\\", "/");
    const text = fs.readFileSync(file, "utf8");
    if (text.length > MAX_CHARS) continue;
    next[relative] = text;
    if (captured) continue;
    const before = state.files[relative];
    if (before === void 0) continue;
    const delta = eventsFromEdit(before, text, t);
    if (delta.length === 0) continue;
    events.push(...delta);
    t += 1;
  }
  writeState(dir, { files: next });
  if (captured || events.length === 0) return 0;
  const session = current ?? {
    sessionId: `watch-${now.toString(16)}`,
    startedAt: new Date(now).toISOString(),
    source: "watch",
    events: []
  };
  session.events.push(...events);
  writeSession(dir, session);
  return events.length;
}
function watcherAlive(dir) {
  const file = pidFile(dir);
  if (!fs.existsSync(file)) return false;
  const pid = Number(fs.readFileSync(file, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
function appendRemoteEdits(dir, changes, now = Date.now()) {
  const current = readSession(dir);
  const fresh = !current || current.source === "watch";
  const started = fresh ? now : Date.parse(current.startedAt);
  const origin = Number.isFinite(started) ? started : now;
  let t = Math.max(0, now - origin);
  if (!fresh && current.events.length > 0) t = Math.max(t, current.events[current.events.length - 1].t);
  const events = changes.flatMap((change) => eventsFromTextChange(change, t));
  if (events.length === 0) return 0;
  const session = fresh ? {
    sessionId: `overleaf-${now.toString(16)}`,
    startedAt: new Date(origin).toISOString(),
    source: "overleaf",
    events: []
  } : current;
  session.source = "overleaf";
  session.events.push(...events);
  writeSession(dir, session);
  return events.length;
}
function writeSessionAnchor(dir, anchor) {
  const current = readSession(dir);
  if (!current) return;
  current.timeAnchor = { ...anchor, startedAt: current.startedAt };
  writeSession(dir, current);
}
function startWatcher(dir) {
  if (watcherAlive(dir)) return true;
  const child = spawn(process.execPath, [...cliArgs(), "watch", "--dir", dir], {
    cwd: dir,
    detached: true,
    stdio: "ignore",
    windowsHide: true
  });
  if (!child.pid) return false;
  child.unref();
  fs.mkdirSync(path.dirname(pidFile(dir)), { recursive: true });
  fs.writeFileSync(pidFile(dir), `${child.pid}
`);
  return true;
}
function isManuscriptName(name) {
  if (name.toLowerCase() === "readme.md") return false;
  return TEXT.has(path.extname(name).toLowerCase());
}
function statePath(dir) {
  return path.join(dir, ".zk-scribe", "private", "watch-state.json");
}
function pidFile(dir) {
  return path.join(dir, ".zk-scribe", "private", "watch.pid");
}
function readState(dir) {
  const file = statePath(dir);
  if (!fs.existsSync(file)) return { files: {} };
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  return parsed && parsed.files ? parsed : { files: {} };
}
function writeState(dir, state) {
  const file = statePath(dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(state)}
`);
}
function writeSession(dir, session) {
  const file = sessionPath(dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(session, null, 2)}
`);
}

// src/time/drand.ts
import https from "node:https";
import tls from "node:tls";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { sha256 as sha2563 } from "@noble/hashes/sha2.js";
import { hexToBytes as hexToBytes2 } from "@noble/hashes/utils.js";
var QUICKNET = {
  hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  publicKey: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  genesis: 1692803367,
  period: 3,
  scheme: "bls-unchained-g1-rfc9380"
};
var bls = bls12_381.shortSignatures;
function roundUnix(round) {
  return QUICKNET.genesis + (round - 1) * QUICKNET.period;
}
function roundAt(unixMs) {
  const unix = Math.floor(unixMs / 1e3);
  if (unix < QUICKNET.genesis) return 0;
  return Math.floor((unix - QUICKNET.genesis) / QUICKNET.period) + 1;
}
function verifyRound(round) {
  if (round.chain !== QUICKNET.hash || !Number.isInteger(round.round) || round.round < 1) return false;
  if (!/^[0-9a-f]{96}$/.test(round.signature)) return false;
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(round.round));
  try {
    const message = bls.hash(sha2563(bytes));
    return bls.verify(hexToBytes2(round.signature), message, hexToBytes2(QUICKNET.publicKey));
  } catch {
    return false;
  }
}
function coverageProblem(startRound, endRound, durationMs, startedAt) {
  if (!Number.isInteger(startRound) || !Number.isInteger(endRound) || endRound <= startRound) {
    return "Time beacon window is empty.";
  }
  const startMs = roundUnix(startRound) * 1e3;
  const endMs = roundUnix(endRound) * 1e3;
  const span = endMs - startMs + QUICKNET.period * 1e3;
  if (span < durationMs) return "Time beacon window is shorter than the session.";
  const started = Date.parse(startedAt);
  if (!Number.isFinite(started)) return "Session start time is missing.";
  if (started < startMs - QUICKNET.period * 1e3 || started > endMs + QUICKNET.period * 1e3) {
    return "Session start is outside the time beacon window.";
  }
  return null;
}
function windowProblem(anchor, durationMs) {
  if (anchor.scheme !== "drand-quicknet-v1") return "Unknown time anchor.";
  if (anchor.start.chain !== anchor.end.chain) return "Time beacon chain does not match.";
  if (!verifyRound(anchor.start) || !verifyRound(anchor.end)) return "Time beacon signature is invalid.";
  return coverageProblem(anchor.start.round, anchor.end.round, durationMs, anchor.startedAt);
}
function chainDomain(anchor) {
  return `${anchor.start.round}:${anchor.start.signature}:${anchor.end.round}:${anchor.end.signature}`;
}
async function fetchLatest() {
  return fetchRoundNumber("latest");
}
async function fetchRound(round) {
  if (!Number.isInteger(round) || round < 1) throw new Error("Time beacon round is invalid.");
  const parsed = await fetchRoundNumber(String(round));
  if (parsed.round !== round) throw new Error("Time beacon returned a different round.");
  return parsed;
}
async function ensureAnchor(session) {
  const duration = durationOf(session);
  if (session.timeAnchor && session.timeAnchor.startedAt === session.startedAt && windowProblem(session.timeAnchor, duration) === null) {
    return session;
  }
  const started = Date.parse(session.startedAt);
  if (!Number.isFinite(started)) return clearAnchor(session);
  const startRound = roundAt(started);
  if (startRound < 1) return clearAnchor(session);
  try {
    const start2 = session.timeAnchor?.start && session.timeAnchor.start.round === startRound && verifyRound(session.timeAnchor.start) ? session.timeAnchor.start : await fetchRound(startRound);
    let end = await fetchLatest();
    let anchor = { scheme: "drand-quicknet-v1", startedAt: session.startedAt, start: start2, end };
    for (let attempt = 0; attempt < 3 && needsAnotherRound(windowProblem(anchor, duration)); attempt += 1) {
      await delay(QUICKNET.period * 1e3 + 400);
      end = await fetchLatest();
      anchor = { scheme: "drand-quicknet-v1", startedAt: session.startedAt, start: start2, end };
    }
    if (windowProblem(anchor, duration)) return clearAnchor(session);
    return { ...session, timeAnchor: anchor };
  } catch {
    return clearAnchor(session);
  }
}
async function fetchRoundNumber(round) {
  const body = await getJson(`https://api.drand.sh/${QUICKNET.hash}/public/${round}`);
  const parsed = {
    chain: QUICKNET.hash,
    round: Number(body.round),
    signature: String(body.signature ?? "")
  };
  if (!verifyRound(parsed)) throw new Error("Time beacon signature did not verify.");
  return parsed;
}
function durationOf(session) {
  const events = session.events;
  if (events.length === 0) return 0;
  return events[events.length - 1].t - events[0].t;
}
function clearAnchor(session) {
  if (!session.timeAnchor) return session;
  const next = { ...session };
  delete next.timeAnchor;
  return next;
}
function getJson(url) {
  const ca = tls.getCACertificates("system");
  return new Promise((resolve, reject) => {
    const request = https.get(url, { ca }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        if ((response.statusCode ?? 500) >= 400) {
          reject(new Error(`Time beacon responded ${response.statusCode}.`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(8e3, () => request.destroy(new Error("Time beacon timed out.")));
    request.on("error", reject);
  });
}
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function needsAnotherRound(problem) {
  return problem === "Time beacon window is empty." || problem === "Time beacon window is shorter than the session.";
}

// src/capture/overleaf.ts
var MAX_BODY = 8192;
var MAX_CHANGES = 40;
var MAX_SPAN = 1e5;
function startOverleafBridge(dir) {
  const root = path2.resolve(dir);
  const token = randomBytes2(32).toString("hex");
  let start2 = null;
  let refreshing = false;
  const refresh = async () => {
    if (refreshing) return;
    refreshing = true;
    try {
      if (!start2) start2 = await fetchLatest();
      const end = await fetchLatest();
      const session = readSession(root);
      if (!session || session.events.length === 0) return;
      const duration = session.events[session.events.length - 1].t - session.events[0].t;
      const anchor = {
        scheme: "drand-quicknet-v1",
        startedAt: session.startedAt,
        start: start2,
        end
      };
      if (windowProblem(anchor, duration) === null) writeSessionAnchor(root, anchor);
    } catch {
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
          "access-control-allow-methods": "POST, OPTIONS"
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
      readBody(request).then((raw) => {
        const changes = changesFromWire(raw);
        appendRemoteEdits(root, changes);
        void refresh();
        response.writeHead(204);
        response.end();
      }).catch(() => {
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
      const timer = setInterval(() => void refresh(), QUICKNET.period * 1e3);
      void refresh();
      resolve({
        port: address.port,
        token,
        close: () => new Promise((done) => {
          clearInterval(timer);
          server.close(() => done());
        })
      });
    });
  });
}
function changesFromWire(raw) {
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("bad");
  const body = parsed;
  if (Object.keys(body).some((key) => key !== "changes")) throw new Error("bad");
  if (!Array.isArray(body.changes) || body.changes.length === 0 || body.changes.length > MAX_CHANGES) {
    throw new Error("bad");
  }
  return body.changes.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("bad");
    const change = item;
    if (Object.keys(change).some((key) => key !== "removed" && key !== "len" && key !== "boundary")) {
      throw new Error("bad");
    }
    const removed = change.removed ?? 0;
    const len = change.len ?? 0;
    if (!whole(removed) || !whole(len) || removed > MAX_SPAN || len > MAX_SPAN || removed === 0 && len === 0) {
      throw new Error("bad");
    }
    const boundary = change.boundary === true;
    const inserted = len === 0 ? "" : boundary ? `${"x".repeat(len - 1)}.` : "x".repeat(len);
    return { removed, inserted };
  });
}
function whole(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
function bearerMatches(header, token) {
  const expected = Buffer.from(`Bearer ${token}`);
  const given = Buffer.from(header ?? "");
  if (expected.length !== given.length) return false;
  return timingSafeEqual(expected, given);
}
function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
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
function writeBridgeFile(dir, token, port) {
  const file = path2.join(dir, ".zk-scribe", "private", "overleaf.json");
  fs2.mkdirSync(path2.dirname(file), { recursive: true });
  fs2.writeFileSync(file, `${JSON.stringify({ token, port })}
`, { mode: 384 });
}

// src/credit/taxonomy.ts
var CREDIT_ROLES = [
  {
    id: "writing-original-draft",
    name: "Writing \u2013 original draft",
    feasibility: "high",
    observes: "Cognitive timing of the draft as it is typed and revised."
  },
  {
    id: "writing-review-editing",
    name: "Writing \u2013 review & editing",
    feasibility: "high",
    observes: "Cognitive timing of later edits, together with the diff those edits produce."
  },
  {
    id: "software",
    name: "Software",
    feasibility: "moderate",
    observes: "That a human typed the code. Execution and correctness are outside the proof."
  },
  {
    id: "formal-analysis",
    name: "Formal analysis",
    feasibility: "moderate",
    observes: "That a human typed the proof or analysis script. Computed results are not re-run."
  },
  {
    id: "data-curation",
    name: "Data curation",
    feasibility: "moderate",
    observes: "That a human typed metadata or curation scripts. Remote pipelines are not observed."
  },
  {
    id: "visualization",
    name: "Visualization",
    feasibility: "moderate",
    observes: "That a human typed the figure code or caption. The figure's fidelity is not observed."
  },
  {
    id: "conceptualization",
    name: "Conceptualization",
    feasibility: "unobserved",
    observes: "Nothing directly. Ideas formed in conversation or on a whiteboard leave no keystroke trace."
  },
  {
    id: "methodology",
    name: "Methodology",
    feasibility: "unobserved",
    observes: "Only the later write-up of a method, not the design act itself."
  },
  {
    id: "investigation",
    name: "Investigation",
    feasibility: "unobserved",
    observes: "Nothing. Bench work, fieldwork, and interviews happen off the keyboard."
  },
  {
    id: "validation",
    name: "Validation",
    feasibility: "unobserved",
    observes: "Nothing. Replication is a scientific activity, not a typing pattern."
  },
  {
    id: "supervision",
    name: "Supervision",
    feasibility: "unobserved",
    observes: "Nothing. Mentorship and review meetings are outside the manuscript session."
  },
  {
    id: "project-administration",
    name: "Project administration",
    feasibility: "unobserved",
    observes: "Nothing. Coordination mail and logistics are outside the writing log."
  },
  {
    id: "resources",
    name: "Resources",
    feasibility: "unobserved",
    observes: "Nothing. Materials, access, and study subjects are not digital writing events."
  },
  {
    id: "funding-acquisition",
    name: "Funding acquisition",
    feasibility: "unobserved",
    observes: "Nothing. Financial support is not a property of the manuscript keystroke log."
  }
];
var BY_ID = new Map(CREDIT_ROLES.map((role) => [role.id, role]));
function getRole(id) {
  const role = BY_ID.get(id);
  if (!role) throw new Error(`Unknown CRediT role "${id}". Run \`zk-scribe credit\` for the vocabulary.`);
  return role;
}

// src/credit/suggest.ts
var BY_EXTENSION = {
  ".md": "writing-original-draft",
  ".markdown": "writing-original-draft",
  ".tex": "writing-original-draft",
  ".txt": "writing-original-draft",
  ".py": "software",
  ".r": "software",
  ".js": "software",
  ".ts": "software",
  ".ipynb": "formal-analysis",
  ".csv": "data-curation",
  ".tsv": "data-curation",
  ".json": "data-curation",
  ".svg": "visualization",
  ".png": "visualization"
};
function suggestRole(filePath) {
  const extension = extensionOf(filePath);
  const role = BY_EXTENSION[extension] ?? "writing-original-draft";
  const described = getRole(role);
  const reason = BY_EXTENSION[extension] ? `Extension ${extension} maps to ${described.name}.` : "No extension rule matched, so the default is original drafting.";
  return { role, name: described.name, reason };
}
function extensionOf(filePath) {
  const base = filePath.replaceAll("\\", "/").split("/").pop() ?? "";
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot).toLowerCase();
}

// src/cva/policy.ts
function defaultPolicy() {
  return {
    version: "zk-scribe-policy/0.1.0",
    id: "local-author",
    allow: [
      "capture.keystroke-timing",
      "attest.process",
      "attest.assert",
      "export.manifest",
      "export.jats"
    ],
    deny: ["export.raw-events", "export.plaintext", "export.witness"],
    note: "Time keystrokes and publish proofs. Do not publish raw events, manuscript plaintext, or commitment openings."
  };
}
function policyHash(policy) {
  return canonicalHash(policy);
}
function actionAllowed(policy, action) {
  return policy.allow.includes(action) && !policy.deny.includes(action);
}
function assertActionAllowed(policy, action) {
  if (!actionAllowed(policy, action)) {
    throw new Error(`Policy "${policy.id}" does not allow "${action}".`);
  }
}

// src/cva/lint.ts
var REQUIRED_DENIALS = ["export.raw-events", "export.plaintext", "export.witness"];
function lintPolicy(policy) {
  const findings = [];
  if (!policy.allow.includes("attest.process")) {
    findings.push("allow is missing attest.process.");
  }
  for (const action of REQUIRED_DENIALS) {
    if (!policy.deny.includes(action)) findings.push(`deny is missing ${action}.`);
  }
  if (policy.allow.some((action) => policy.deny.includes(action))) {
    findings.push("An action is both allowed and denied.");
  }
  return { ok: findings.length === 0, findings };
}

// src/cva/revocation.ts
function normalizeKey(value) {
  return value.trim().toLowerCase().replace(/^0x/, "").replace(/\s+/g, "");
}
function isRevoked(publicKey, revoked) {
  const needle = normalizeKey(publicKey);
  if (needle.length === 0) return false;
  return revoked.some((entry) => normalizeKey(entry) === needle);
}
function parseRevocationList(value) {
  if (!value || typeof value !== "object") throw new Error("Revocation list must be an object.");
  const keys = value.publicKeys;
  if (!Array.isArray(keys) || keys.some((key) => typeof key !== "string")) {
    throw new Error("Revocation list publicKeys must be strings.");
  }
  return keys;
}

// src/keys.ts
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex as bytesToHex3, hexToBytes as hexToBytes3 } from "@noble/hashes/utils.js";
ed.hashes.sha512 = sha512;
function generateAgentKey() {
  const { secretKey, publicKey } = ed.keygen();
  return { secretKey, publicKey };
}
function publicKeyFromSecret(secretKey) {
  return ed.getPublicKey(secretKey);
}
function sign2(message, secretKey) {
  return ed.sign(message, secretKey);
}
function verifySignature(signature, message, publicKey) {
  try {
    return ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
function encodeKey(key) {
  return bytesToHex3(key);
}
function decodeSecretKey(hex) {
  return decodeFixed(hex, 32, "Ed25519 seed");
}
function decodePublicKey(hex) {
  return decodeFixed(hex, 32, "Ed25519 public key");
}
function decodeSignature(hex) {
  return decodeFixed(hex, 64, "Ed25519 signature");
}
function decodeFixed(hex, length, label) {
  const bytes = hexToBytes3(hex);
  if (bytes.length !== length) throw new Error(`Expected a ${length}-byte ${label}.`);
  return bytes;
}

// src/cva/grant.ts
function issueGrant(input) {
  const actions = uniqueActions(input.actions);
  assertContentHash(input.contentHash);
  decodePublicKey(input.agentPublicKey);
  const body = {
    version: "zk-scribe-grant/0.1.0",
    agentPublicKey: normalizeKey(input.agentPublicKey),
    policyHash: policyHash(input.policy),
    actions,
    contentHash: input.contentHash
  };
  return {
    ...body,
    author: {
      publicKey: encodeKey(publicKeyFromSecret(input.authorSecretKey)),
      signature: encodeKey(sign2(utf8(grantMessage(canonicalHash(body))), input.authorSecretKey))
    }
  };
}
function parseGrant(value) {
  if (!value || typeof value !== "object") throw new Error("Grant must be an object.");
  const record2 = value;
  if (record2.version !== "zk-scribe-grant/0.1.0") throw new Error("Unsupported grant version.");
  if (typeof record2.agentPublicKey !== "string" || typeof record2.policyHash !== "string") {
    throw new Error("Grant is missing the agent or the policy hash.");
  }
  if (typeof record2.contentHash !== "string") throw new Error("Grant is missing contentHash.");
  if (!Array.isArray(record2.actions) || record2.actions.some((action) => typeof action !== "string")) {
    throw new Error("Grant actions must be strings.");
  }
  const author = record2.author;
  if (!author || typeof author.publicKey !== "string" || typeof author.signature !== "string") {
    throw new Error("Grant author signature is missing.");
  }
  return {
    version: "zk-scribe-grant/0.1.0",
    agentPublicKey: record2.agentPublicKey,
    policyHash: record2.policyHash,
    actions: record2.actions,
    contentHash: record2.contentHash,
    author: { publicKey: author.publicKey, signature: author.signature }
  };
}
function hashGrant(grant) {
  return canonicalHash(grant);
}
function grantSignatureValid(grant) {
  try {
    const body = {
      version: grant.version,
      agentPublicKey: grant.agentPublicKey,
      policyHash: grant.policyHash,
      actions: grant.actions,
      contentHash: grant.contentHash
    };
    return verifySignature(
      decodeSignature(grant.author.signature),
      utf8(grantMessage(canonicalHash(body))),
      decodePublicKey(grant.author.publicKey)
    );
  } catch {
    return false;
  }
}
function grantCovers(grant, request) {
  const reasons = [];
  if (!grantSignatureValid(grant)) reasons.push("Grant signature is invalid.");
  if (normalizeKey(grant.agentPublicKey) !== normalizeKey(request.agentPublicKey)) {
    reasons.push("Grant is for a different agent.");
  }
  if (grant.policyHash !== request.policyHash) reasons.push("Grant is for a different policy.");
  if (grant.contentHash !== request.contentHash) reasons.push("Grant is for a different manuscript.");
  if (!grant.actions.includes(request.action)) reasons.push(`Grant does not allow ${request.action}.`);
  return { ok: reasons.length === 0, reasons };
}
function grantMessage(bodyHash) {
  return `ZK-Scribe/grant/v1:${bodyHash}`;
}
function uniqueActions(actions) {
  const cleaned = [...new Set(actions.map((action) => action.trim()).filter((action) => action.length > 0))].sort();
  if (cleaned.length === 0) throw new Error("Grant actions are empty.");
  return cleaned;
}
function assertContentHash(hash) {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("contentHash must be a sha256 hex digest.");
}

// src/cva/govern.ts
function govern(request) {
  const reasons = [];
  const lint = lintPolicy(request.policy);
  if (!lint.ok) reasons.push(...lint.findings);
  if (!actionAllowed(request.policy, request.action)) reasons.push(`Policy does not allow ${request.action}.`);
  if (isRevoked(request.agentPublicKey, request.revokedKeys ?? [])) reasons.push("Agent key is revoked.");
  let grantHash;
  if (request.grant) {
    grantHash = hashGrant(request.grant);
    const cover = grantCovers(request.grant, {
      action: request.action,
      agentPublicKey: request.agentPublicKey,
      policyHash: policyHash(request.policy),
      contentHash: request.contentHash
    });
    if (!cover.ok) reasons.push(...cover.reasons);
  }
  return {
    allow: reasons.length === 0,
    reasons,
    ...grantHash ? { grantHash } : {}
  };
}

// src/cva/journal.ts
var GENESIS = "0".repeat(64);
function appendJournal(entries, draft) {
  const previous = entries.length === 0 ? null : entries[entries.length - 1];
  const body = {
    version: "zk-scribe-journal/0.1.0",
    index: previous ? previous.index + 1 : 0,
    action: draft.action,
    agentPublicKey: draft.agentPublicKey,
    contentHash: draft.contentHash,
    policyHash: draft.policyHash,
    grantHash: draft.grantHash,
    allow: draft.allow,
    reasons: draft.reasons,
    prev: previous ? entryHash(previous) : GENESIS
  };
  const signature = encodeKey(sign2(utf8(journalMessage(canonicalHash(body))), draft.agentSecretKey));
  return [...entries, { ...body, signature }];
}
function entryHash(entry) {
  return canonicalHash(entry);
}
function auditJournal(entries) {
  const reasons = [];
  let previous = null;
  for (const [index, entry] of entries.entries()) {
    if (entry.version !== "zk-scribe-journal/0.1.0") reasons.push(`Entry ${index} has an unsupported version.`);
    if (entry.index !== index) reasons.push(`Entry ${index} is out of order.`);
    const expectedPrev = previous ? entryHash(previous) : GENESIS;
    if (entry.prev !== expectedPrev) reasons.push(`Entry ${index} does not follow the previous decision.`);
    if (!entrySignatureValid(entry)) reasons.push(`Entry ${index} signature is invalid.`);
    previous = entry;
  }
  return { ok: reasons.length === 0, reasons };
}
function parseJournalEntry(value) {
  if (!value || typeof value !== "object") throw new Error("Journal entry must be an object.");
  const record2 = value;
  if (record2.version !== "zk-scribe-journal/0.1.0") throw new Error("Unsupported journal version.");
  if (typeof record2.index !== "number" || typeof record2.action !== "string") {
    throw new Error("Journal entry is missing index or action.");
  }
  if (typeof record2.agentPublicKey !== "string" || typeof record2.contentHash !== "string" || typeof record2.policyHash !== "string") {
    throw new Error("Journal entry is missing a hash.");
  }
  if (record2.grantHash !== null && typeof record2.grantHash !== "string") throw new Error("Journal grantHash is invalid.");
  if (typeof record2.allow !== "boolean" || !Array.isArray(record2.reasons) || typeof record2.prev !== "string") {
    throw new Error("Journal entry is missing its decision.");
  }
  if (record2.reasons.some((reason) => typeof reason !== "string")) throw new Error("Journal reasons must be strings.");
  if (typeof record2.signature !== "string") throw new Error("Journal signature is missing.");
  return {
    version: "zk-scribe-journal/0.1.0",
    index: record2.index,
    action: record2.action,
    agentPublicKey: record2.agentPublicKey,
    contentHash: record2.contentHash,
    policyHash: record2.policyHash,
    grantHash: record2.grantHash,
    allow: record2.allow,
    reasons: record2.reasons,
    prev: record2.prev,
    signature: record2.signature
  };
}
function entrySignatureValid(entry) {
  try {
    const { signature, ...body } = entry;
    return verifySignature(
      decodeSignature(signature),
      utf8(journalMessage(canonicalHash(body))),
      decodePublicKey(entry.agentPublicKey)
    );
  } catch {
    return false;
  }
}
function journalMessage(bodyHash) {
  return `ZK-Scribe/journal/v1:${bodyHash}`;
}

// src/git/context.ts
import { execFileSync } from "node:child_process";
import path3 from "node:path";
function detectContext(cwd, subject) {
  const inside = git(["rev-parse", "--is-inside-work-tree"], cwd) === "true";
  if (!inside) return { environment: "local", revision: "uncommitted", subject };
  const revision = git(["rev-parse", "HEAD"], cwd) ?? "uncommitted";
  const remotes = git(["remote", "-v"], cwd) ?? "";
  const environment = /overleaf/i.test(remotes) ? "overleaf-git" : "git";
  return { environment, revision, subject: path3.relative(cwd, subject) || subject };
}
function git(args, cwd) {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return void 0;
  }
}

// src/git/diffstat.ts
function parseDiffStat(diff) {
  const files = /* @__PURE__ */ new Set();
  let insertions = 0;
  let deletions = 0;
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      const match = / b\/(.+)$/.exec(line);
      files.add(match?.[1] ?? line);
      continue;
    }
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+")) insertions += 1;
    else if (line.startsWith("-")) deletions += 1;
  }
  return { files: files.size, insertions, deletions };
}
function reviewNote(contentHash, stat) {
  return {
    version: "zk-scribe-review-note/0.1.0",
    contentHash,
    stat,
    note: "Counts from a unified diff. The note does not prove who typed the change."
  };
}

// src/hash/tree.ts
import { sha256 as sha2564 } from "@noble/hashes/sha2.js";
import { bytesToHex as bytesToHex4, concatBytes as concatBytes2 } from "@noble/hashes/utils.js";
function hashTree(files) {
  const sorted = [...files].sort((left, right) => normalize(left.path).localeCompare(normalize(right.path)));
  let state = sha2564(utf8("ZK-Scribe/tree/v1"));
  for (const file of sorted) {
    const pathBytes = utf8(normalize(file.path));
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, file.bytes.length);
    state = sha2564(concatBytes2(state, pathBytes, length, file.bytes));
  }
  return bytesToHex4(state);
}
function ignoredTreePath(relativePath) {
  const normalized = normalize(relativePath);
  const parts = normalized.split("/");
  return normalized === ".zk-scribe/private" || normalized.startsWith(".zk-scribe/private/") || parts.includes("node_modules") || normalized.endsWith(".witness.json");
}
function normalize(filePath) {
  return filePath.replaceAll("\\", "/");
}

// src/doctor.ts
function doctorReport(input) {
  const checks = [
    {
      name: "node",
      ok: input.nodeMajor >= input.minimumMajor,
      detail: `Node ${input.nodeMajor} is ${input.nodeMajor >= input.minimumMajor ? "new enough" : `older than ${input.minimumMajor}`}.`
    },
    {
      name: "policy",
      ok: input.policyExists,
      detail: input.policyExists ? "Consent policy is present." : "Run zk-scribe init to write .zk-scribe/policy.json."
    },
    {
      name: "agent-public-key",
      ok: input.publicKeyExists,
      detail: input.publicKeyExists ? "Public agent key is present." : "agent.public.json is missing."
    },
    {
      name: "agent-seed",
      ok: input.seedExists,
      detail: input.seedExists ? "Local agent seed is present." : "The private seed is missing, so this machine cannot sign."
    }
  ];
  return { ok: checks.every((check) => check.ok), checks };
}

// src/version.ts
var VERSION = "0.3.0";

// src/manifest/export.ts
function toProvenanceManifest(attestation) {
  const statementHash = canonicalHash(attestation.statement);
  return {
    version: "zk-scribe-manifest/0.1.0",
    claim_generator: `ZK-Scribe/${VERSION}`,
    profile: "zk-scribe.c2pa-shaped.v1",
    contentHash: attestation.statement.contentHash,
    statementHash,
    note: "Assertion labels follow the C2PA vocabulary. This JSON profile is not a JUMBF or COSE C2PA box.",
    assertions: [
      {
        label: "c2pa.actions",
        data: {
          actions: [{ action: "c2pa.created", softwareAgent: `ZK-Scribe/${VERSION}` }]
        }
      },
      { label: "c2pa.ai-disclosure", data: aiDisclosure(attestation) },
      {
        label: "zk-scribe.process-attestation",
        data: {
          statementHash,
          attestation
        }
      },
      { label: "zk-scribe.credit", data: attestation.statement.role }
    ]
  };
}
function toJats(attestation) {
  const statement = attestation.statement;
  const rows = [
    ["zk-scribe-version", statement.version],
    ["zk-scribe-role", statement.role.id],
    ["zk-scribe-binding", statement.role.binding],
    ["zk-scribe-label", statement.label],
    ["zk-scribe-content-hash", statement.contentHash],
    ["zk-scribe-swf-head", statement.swfHead],
    ["zk-scribe-statement-hash", canonicalHash(statement)],
    ["zk-scribe-agent", attestation.cva.agentPublicKey]
  ];
  const metas = rows.map(
    ([name, value]) => `    <custom-meta>
      <meta-name>${escapeXml(name)}</meta-name>
      <meta-value>${escapeXml(value)}</meta-value>
    </custom-meta>`
  ).join("\n");
  return `<custom-meta-group>
${metas}
</custom-meta-group>
`;
}
function aiDisclosure(attestation) {
  const { label, role } = attestation.statement;
  if (role.binding === "signed-assertion") {
    return {
      status: "not-process-attested",
      used: "undisclosed-by-process",
      summary: "Signed contribution claim without process evidence."
    };
  }
  if (label === "composition" && (role.binding === "process-proven" || role.binding === "typed-artifact")) {
    return {
      status: "human-process",
      used: "not-indicated-by-timing",
      summary: "Keystroke timing is inside the composition region. This does not show that the text is true, and it does not rule out earlier machine assistance."
    };
  }
  if (label === "transcription") {
    return {
      status: "transcription-pattern",
      used: "not-determined",
      summary: "Timing fits steady transcription more closely than composition."
    };
  }
  if (label === "automated") {
    return {
      status: "non-human-timing",
      used: "not-determined",
      summary: "Timing is outside the human composition region. That is not, by itself, an identification of a model."
    };
  }
  return {
    status: "indeterminate",
    used: "not-determined",
    summary: "Process evidence does not support a composition claim."
  };
}
function escapeXml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

// src/manifest/summary.ts
function toSummary(attestation) {
  return {
    version: "zk-scribe-summary/0.1.0",
    sessionId: attestation.statement.sessionId,
    contentHash: attestation.statement.contentHash,
    swfHead: attestation.statement.swfHead,
    label: attestation.statement.label,
    role: attestation.statement.role.id,
    binding: attestation.statement.role.binding,
    feasibility: attestation.statement.role.feasibility,
    action: attestation.cva.action,
    agentPublicKey: attestation.cva.agentPublicKey
  };
}

// src/manifest/html.ts
function toHtmlReport(attestation) {
  const summary = toSummary(attestation);
  const rows = Object.entries(summary).map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(String(value))}</td></tr>`).join("\n");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZK-Scribe ${escapeHtml(summary.binding)}</title>
</head>
<body>
  <h1>${escapeHtml(summary.role)}</h1>
  <p>${escapeHtml(summary.binding)} / ${escapeHtml(summary.label)}</p>
  <table>
${rows}
  </table>
</body>
</html>
`;
}
function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

// src/ledger/combine.ts
function buildLedger(entries) {
  const seen = /* @__PURE__ */ new Set();
  const unique = entries.filter((entry) => {
    const id = `${entry.contentHash}:${entry.role}:${entry.agentPublicKey}:${entry.binding}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  return {
    version: "zk-scribe-ledger/0.1.0",
    entries: unique,
    counts: {
      processProven: unique.filter((entry) => entry.binding === "process-proven").length,
      typedArtifact: unique.filter((entry) => entry.binding === "typed-artifact").length,
      signedAssertion: unique.filter((entry) => entry.binding === "signed-assertion").length,
      other: unique.filter((entry) => !["process-proven", "typed-artifact", "signed-assertion"].includes(entry.binding)).length
    }
  };
}

// src/author/endorse.ts
function endorseStatement(statementHash, secretKey) {
  return {
    publicKey: encodeKey(publicKeyFromSecret(secretKey)),
    signature: encodeKey(sign2(utf8(authorMessage(statementHash)), secretKey))
  };
}
function authorEndorsementValid(statementHash, endorsement) {
  try {
    return verifySignature(
      decodeSignature(endorsement.signature),
      utf8(authorMessage(statementHash)),
      decodePublicKey(endorsement.publicKey)
    );
  } catch {
    return false;
  }
}
function authorMessage(statementHash) {
  return `ZK-Scribe/author/v1:${statementHash}`;
}

// src/pop/regions.ts
var REGIONS = {
  composition: {
    medianIkiMs: { min: 90, max: 8e3 },
    ikiCvTimes100: { min: 45, max: 500 },
    planningPauses: { min: 2, max: 2048 },
    boundaryPauses: { min: 1, max: 2048 },
    peakCpsTimes10: { min: 1, max: 160 },
    revisionPermille: { min: 20, max: 1e3 }
  },
  transcription: {
    medianIkiMs: { min: 45, max: 150 },
    ikiCvTimes100: { min: 0, max: 40 },
    planningPauses: { min: 0, max: 1 },
    boundaryPauses: { min: 0, max: 1 },
    peakCpsTimes10: { min: 60, max: 220 },
    revisionPermille: { min: 0, max: 40 }
  },
  automated: {
    medianIkiMs: { min: 0, max: 39 },
    ikiCvTimes100: { min: 0, max: 20 },
    planningPauses: { min: 0, max: 0 },
    boundaryPauses: { min: 0, max: 0 },
    peakCpsTimes10: { min: 200, max: 2e4 },
    revisionPermille: { min: 0, max: 30 }
  }
};
function contains(features, bounds) {
  return FEATURE_KEYS.every((key) => features[key] >= bounds[key].min && features[key] <= bounds[key].max);
}
function matchLabel(features, bulkInsertEvents) {
  if (contains(features, REGIONS.automated)) return "automated";
  if (contains(features, REGIONS.transcription)) return "transcription";
  if (bulkInsertEvents === 0 && contains(features, REGIONS.composition)) return "composition";
  return "indeterminate";
}

// src/pop/session.ts
var OPS = /* @__PURE__ */ new Set(["insert", "delete", "navigate", "paste"]);
function validateSession(session) {
  if (!session || typeof session.sessionId !== "string" || session.sessionId.trim() === "") {
    throw new Error("Session is missing sessionId.");
  }
  if (typeof session.startedAt !== "string" || session.startedAt.trim() === "") {
    throw new Error("Session is missing startedAt.");
  }
  if (!Array.isArray(session.events)) throw new Error("Session events must be an array.");
  let previous = -1;
  for (const [index, event] of session.events.entries()) {
    if (!OPS.has(event.op)) throw new Error(`Event ${index} has an unknown op.`);
    if (!Number.isInteger(event.t) || event.t < 0) throw new Error(`Event ${index} has a bad timestamp.`);
    if (event.t < previous) throw new Error(`Event ${index} moves backwards in time.`);
    if (!Number.isInteger(event.len) || event.len < 1) throw new Error(`Event ${index} has a bad length.`);
    if (event.boundary !== void 0 && typeof event.boundary !== "boolean") {
      throw new Error(`Event ${index} has a bad boundary flag.`);
    }
    previous = event.t;
  }
}

// src/pop/extract.ts
function extract(session) {
  validateSession(session);
  const events = session.events;
  const inserts = events.filter((event) => event.op === "insert" || event.op === "paste");
  const deletes = events.filter((event) => event.op === "delete");
  const ikis = [];
  for (let index = 1; index < inserts.length; index += 1) {
    ikis.push(inserts[index].t - inserts[index - 1].t);
  }
  let planningPauses = 0;
  let boundaryPauses = 0;
  for (let index = 1; index < events.length; index += 1) {
    const gap = events[index].t - events[index - 1].t;
    if (gap < PLANNING_PAUSE_MIN_MS || gap > PLANNING_PAUSE_MAX_MS) continue;
    planningPauses += 1;
    if (events[index].boundary || events[index - 1].boundary) boundaryPauses += 1;
  }
  const insertChars = inserts.reduce((sum, event) => sum + event.len, 0);
  const deleteChars = deletes.reduce((sum, event) => sum + event.len, 0);
  const revisionDenom = insertChars + deleteChars;
  const features = {
    medianIkiMs: median(ikis),
    ikiCvTimes100: coefficientOfVariationTimes100(ikis),
    planningPauses,
    boundaryPauses,
    peakCpsTimes10: peakCharsPerSecondTimes10(inserts),
    revisionPermille: revisionDenom === 0 ? 0 : Math.round(deleteChars / revisionDenom * 1e3)
  };
  for (const key of FEATURE_KEYS) {
    if (!Number.isInteger(features[key]) || features[key] < 0) {
      throw new Error(`Feature ${key} is not a non-negative integer.`);
    }
  }
  const bulkInsertEvents = events.filter(
    (event) => (event.op === "paste" || event.len >= BULK_INSERT_CHARS) && event.op !== "delete" && event.op !== "navigate"
  ).length;
  const durationMs = events.length === 0 ? 0 : events[events.length - 1].t - events[0].t;
  return {
    features,
    label: matchLabel(features, bulkInsertEvents),
    eventCount: events.length,
    durationMs,
    insertChars,
    deleteChars,
    bulkInsertEvents
  };
}
function median(values) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  return sorted[mid];
}
function coefficientOfVariationTimes100(values) {
  if (values.length < 2) return 0;
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (mean === 0) return 0;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return Math.round(Math.sqrt(variance) / mean * 100);
}
function peakCharsPerSecondTimes10(inserts) {
  let start2 = 0;
  let chars = 0;
  let maxChars = 0;
  for (let index = 0; index < inserts.length; index += 1) {
    chars += inserts[index].len;
    while (inserts[start2].t + PEAK_WINDOW_MS <= inserts[index].t) {
      chars -= inserts[start2].len;
      start2 += 1;
    }
    if (chars > maxChars) maxChars = chars;
  }
  return Math.round(maxChars / (PEAK_WINDOW_MS / 1e3) * 10);
}

// src/pop/swf.ts
import { sha256 as sha2565 } from "@noble/hashes/sha2.js";
import { bytesToHex as bytesToHex5, concatBytes as concatBytes3 } from "@noble/hashes/utils.js";
function sequentialWorkHead(session, contentHash, domain) {
  const label = domain ? `ZK-Scribe/swf/v1|${session.sessionId}|${contentHash}|${domain}` : `ZK-Scribe/swf/v1|${session.sessionId}|${contentHash}`;
  let state = sha2565(utf8(label));
  session.events.forEach((event, index) => {
    state = sha2565(concatBytes3(state, eventDigest(index, event)));
  });
  return bytesToHex5(state);
}
function eventDigest(index, event) {
  const boundary = event.boundary ? 1 : 0;
  return sha2565(utf8(`${index}|${event.t}|${event.op}|${event.len}|${boundary}`));
}

// src/pop/attest.ts
var PROOF_SYSTEM = {
  commitments: "pedersen-secp256k1-v1",
  range: "sigma-bit-or-v1",
  sequentialWork: "hash-chain-v1",
  agentAuthorization: "ed25519-cva-v1"
};
var EMPTY_COUNTS = {
  eventCount: 0,
  durationMs: 0,
  insertChars: 0,
  deleteChars: 0,
  bulkInsertEvents: 0
};
function attest(input) {
  assertContentHash2(input.contentHash);
  const role = getRole(input.role);
  const assertion = input.assertion?.trim() ?? "";
  const action = assertion ? "attest.assert" : "attest.process";
  assertActionAllowed(input.policy, action);
  if (assertion && input.session) {
    throw new Error("Pass either a writing session or a signed assertion, not both.");
  }
  let label = "indeterminate";
  let binding = "unsupported";
  let detail = "";
  let extraction;
  let swfHead = "";
  let sessionId = "";
  let counts = EMPTY_COUNTS;
  if (assertion) {
    if (role.feasibility !== "unobserved") {
      throw new Error(`${role.name} is attested from a writing session, not from a bare assertion.`);
    }
    binding = "signed-assertion";
    detail = "Signed claim only. The agent did not observe this contribution.";
    sessionId = `assert-${canonicalHash(assertion).slice(0, 16)}`;
  } else {
    if (!input.session) throw new Error("A session log is required for this role.");
    if (role.feasibility === "unobserved") {
      throw new Error(`${role.name} cannot be process-attested. Pass --assert with the claim text.`);
    }
    extraction = extract(input.session);
    if (input.session.timeAnchor) {
      if (input.session.timeAnchor.startedAt !== input.session.startedAt) {
        throw new Error("Time beacon does not match the session start.");
      }
      const problem = windowProblem(input.session.timeAnchor, extraction.durationMs);
      if (problem) throw new Error(problem);
    }
    label = extraction.label;
    swfHead = sequentialWorkHead(
      input.session,
      input.contentHash,
      input.session.timeAnchor ? chainDomain(input.session.timeAnchor) : void 0
    );
    sessionId = input.session.sessionId;
    counts = {
      eventCount: extraction.eventCount,
      durationMs: extraction.durationMs,
      insertChars: extraction.insertChars,
      deleteChars: extraction.deleteChars,
      bulkInsertEvents: extraction.bulkInsertEvents
    };
    const decision = decideBinding(role.feasibility, label, extraction);
    binding = decision.binding;
    detail = decision.detail;
  }
  const statement = {
    version: "zk-scribe/0.1.0",
    sessionId,
    contentHash: input.contentHash,
    swfHead,
    label,
    assertion,
    counts,
    role: {
      id: role.id,
      name: role.name,
      feasibility: role.feasibility,
      binding,
      detail
    },
    context: input.context,
    proofSystem: PROOF_SYSTEM
  };
  const commitments = {};
  const openings = {};
  let rangeProofs = null;
  if (binding === "process-proven" || binding === "typed-artifact") {
    if (!extraction) throw new Error("Process binding is missing its extraction.");
    rangeProofs = {};
    const transcript = new Transcript("zk-scribe/pop/v1");
    transcript.absorbUtf8("statement-hash", canonicalHash(statement));
    for (const key of FEATURE_KEYS) {
      const value = BigInt(extraction.features[key]);
      const bounds = REGIONS.composition[key];
      const blinding = randomScalar();
      const commitment = commit(value, blinding);
      transcript.absorbUtf8("feature", key);
      transcript.absorb("C", commitment.toBytes(true));
      rangeProofs[key] = proveInterval({
        value,
        blinding,
        low: BigInt(bounds.min),
        high: BigInt(bounds.max),
        transcript
      });
      commitments[key] = pointToHex(commitment);
      openings[key] = { value: value.toString(), blinding: scalarToHex(blinding) };
    }
  }
  const agentPublicKey = encodeKey(publicKeyFromSecret(input.agentSecretKey));
  const statementHash = canonicalHash(statement);
  const author = input.authorSecretKey ? endorseStatement(statementHash, input.authorSecretKey) : void 0;
  const grantHash = input.grantHash;
  if (grantHash !== void 0 && !/^[0-9a-f]{64}$/.test(grantHash)) {
    throw new Error("grantHash must be a sha256 hex digest.");
  }
  const timeAnchor = input.session?.timeAnchor;
  const payload = signedPayload({
    action,
    agentPublicKey,
    policyHash: policyHash(input.policy),
    statementHash,
    commitments,
    rangeProofs,
    author,
    grantHash,
    timeAnchor
  });
  const attestation = {
    version: "zk-scribe/0.1.0",
    statement,
    policy: input.policy,
    commitments,
    rangeProofs,
    cva: {
      action,
      agentPublicKey,
      signature: encodeKey(sign2(utf8(payload), input.agentSecretKey))
    },
    ...author ? { author } : {},
    ...grantHash ? { grantHash } : {},
    ...timeAnchor ? { timeAnchor } : {}
  };
  const witness = extraction ? {
    version: "zk-scribe-witness/0.1.0",
    sessionId,
    features: extraction.features,
    openings
  } : null;
  return { attestation, witness };
}
function verify2(attestation, options) {
  const reasons = [];
  const binding = attestation.statement?.role?.binding ?? "unknown";
  const label = attestation.statement?.label ?? "unknown";
  const role = attestation.statement?.role?.id ?? "unknown";
  let signatureValid = false;
  let proofsValid = false;
  let policyValid = false;
  let identityTrusted = false;
  try {
    if (attestation.version !== "zk-scribe/0.1.0" || attestation.statement.version !== "zk-scribe/0.1.0") {
      reasons.push("Unsupported attestation version.");
    }
    if (!sameProofSystem(attestation.statement.proofSystem)) {
      reasons.push("Proof system id does not match sigma-range-v1.");
    }
    const trusted = encodeKey(decodePublicKey(options.trustedAgentKey));
    const presented = encodeKey(decodePublicKey(attestation.cva.agentPublicKey));
    identityTrusted = trusted === presented;
    if (!identityTrusted) reasons.push("Agent key does not match the trusted key.");
    if (isRevoked(presented, options.revokedKeys ?? [])) reasons.push("Agent key is revoked.");
    if (!options.expectedPolicy) {
      reasons.push("No expected policy was provided.");
    }
    const embeddedHash = policyHash(attestation.policy);
    policyValid = options.expectedPolicy !== void 0 && policyHash(options.expectedPolicy) === embeddedHash;
    if (options.expectedPolicy && !policyValid) reasons.push("Embedded policy does not match the expected policy.");
    if (attestation.policy.deny.includes(attestation.cva.action) || !attestation.policy.allow.includes(attestation.cva.action)) {
      policyValid = false;
      reasons.push(`Policy does not allow ${attestation.cva.action}.`);
    }
    const statementHash = canonicalHash(attestation.statement);
    const payload = signedPayload({
      action: attestation.cva.action,
      agentPublicKey: attestation.cva.agentPublicKey,
      policyHash: embeddedHash,
      statementHash,
      commitments: attestation.commitments,
      rangeProofs: attestation.rangeProofs,
      author: attestation.author,
      grantHash: attestation.grantHash,
      timeAnchor: attestation.timeAnchor
    });
    signatureValid = verifySignature(
      decodeSignature(attestation.cva.signature),
      utf8(payload),
      decodePublicKey(attestation.cva.agentPublicKey)
    );
    if (!signatureValid) reasons.push("Agent signature is invalid.");
    if (attestation.timeAnchor) {
      const problem = windowProblem(attestation.timeAnchor, attestation.statement.counts.durationMs);
      if (problem) reasons.push(problem);
    }
    if (attestation.author && !authorEndorsementValid(statementHash, attestation.author)) {
      reasons.push("Author endorsement does not match the statement.");
    }
    if (options.requireAuthor && !attestation.author) reasons.push("Author endorsement is required.");
    if (options.requireGrant && !attestation.grantHash) reasons.push("A grant binding is required.");
    if (options.grant) {
      if (attestation.grantHash !== hashGrant(options.grant)) reasons.push("Grant does not match the attestation.");
      else {
        const cover = grantCovers(options.grant, {
          action: attestation.cva.action,
          agentPublicKey: attestation.cva.agentPublicKey,
          policyHash: embeddedHash,
          contentHash: attestation.statement.contentHash
        });
        if (!cover.ok) reasons.push(...cover.reasons);
      }
    }
    proofsValid = checkProofs(attestation, reasons);
    checkBinding(attestation, reasons);
    if (options.require === "process" && binding !== "process-proven" && binding !== "typed-artifact") {
      reasons.push("Verifier required process evidence.");
    }
    if (options.require === "process-proven" && binding !== "process-proven") {
      reasons.push("Verifier required a process-proven writing role.");
    }
  } catch (error) {
    reasons.push(error instanceof Error ? error.message : "Verification failed.");
  }
  return {
    ok: reasons.length === 0,
    signatureValid,
    proofsValid,
    policyValid,
    identityTrusted,
    binding,
    label,
    role,
    reasons
  };
}
function audit(attestation, session, witness) {
  const reasons = [];
  const extraction = extract(session);
  if (session.sessionId !== attestation.statement.sessionId || witness.sessionId !== session.sessionId) {
    reasons.push("Session id does not match the attestation.");
  }
  const domain = session.timeAnchor ? chainDomain(session.timeAnchor) : void 0;
  if (sequentialWorkHead(session, attestation.statement.contentHash, domain) !== attestation.statement.swfHead) {
    reasons.push("Sequential work head does not match the session and content hash.");
  }
  if (canonicalHash(session.timeAnchor ?? null) !== canonicalHash(attestation.timeAnchor ?? null)) {
    reasons.push("Time beacon does not match the session.");
  }
  if (session.timeAnchor) {
    const problem = windowProblem(session.timeAnchor, extraction.durationMs);
    if (problem) reasons.push(problem);
  }
  if (extraction.label !== attestation.statement.label) reasons.push("Recomputed label does not match.");
  const counts = attestation.statement.counts;
  if (extraction.eventCount !== counts.eventCount || extraction.durationMs !== counts.durationMs || extraction.insertChars !== counts.insertChars || extraction.deleteChars !== counts.deleteChars || extraction.bulkInsertEvents !== counts.bulkInsertEvents) {
    reasons.push("Recomputed counts do not match.");
  }
  for (const key of FEATURE_KEYS) {
    if (witness.features[key] !== extraction.features[key]) {
      reasons.push(`Witness feature ${key} does not match the session.`);
    }
    const opening = witness.openings[key];
    const committed = attestation.commitments[key];
    if (opening && committed) {
      const point = commit(BigInt(opening.value), hexToScalar(opening.blinding));
      if (pointToHex(point) !== committed || opening.value !== String(extraction.features[key])) {
        reasons.push(`Opening for ${key} does not match the commitment.`);
      }
    } else if (attestation.statement.role.binding === "process-proven" || attestation.statement.role.binding === "typed-artifact") {
      reasons.push(`Missing opening for ${key}.`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}
function decideBinding(feasibility, label, extraction) {
  if (label !== "composition") {
    return {
      binding: "unsupported",
      detail: `Timing label is ${label}. This role needs a composition pattern.`
    };
  }
  if (extraction.bulkInsertEvents > 0) {
    return { binding: "unsupported", detail: "A bulk insert blocks a composition claim." };
  }
  if (extraction.durationMs < MIN_COMPOSITION_DURATION_MS || extraction.insertChars < MIN_COMPOSITION_INSERTS) {
    return { binding: "unsupported", detail: "The session is too short to support a composition claim." };
  }
  if (feasibility === "high") {
    return {
      binding: "process-proven",
      detail: "Human composition bounds hold for this writing. The proof does not establish that the text is true."
    };
  }
  return {
    binding: "typed-artifact",
    detail: "A human typed this artifact. The scientific result itself was not observed."
  };
}
function checkProofs(attestation, reasons) {
  const binding = attestation.statement.role.binding;
  const needsProof = binding === "process-proven" || binding === "typed-artifact";
  if (!needsProof) {
    if (attestation.rangeProofs && Object.keys(attestation.rangeProofs).length > 0) {
      reasons.push("A non-process claim is carrying range proofs.");
      return false;
    }
    return true;
  }
  if (attestation.statement.label !== "composition") {
    reasons.push("Process evidence requires the composition label.");
    return false;
  }
  const transcript = new Transcript("zk-scribe/pop/v1");
  transcript.absorbUtf8("statement-hash", canonicalHash(attestation.statement));
  for (const key of FEATURE_KEYS) {
    const encoded = attestation.commitments[key];
    const proof = attestation.rangeProofs?.[key];
    if (!encoded || !proof) {
      reasons.push(`Missing range proof for ${key}.`);
      return false;
    }
    const commitment = hexToPoint(encoded);
    transcript.absorbUtf8("feature", key);
    transcript.absorb("C", commitment.toBytes(true));
    const bounds = REGIONS.composition[key];
    const ok = verifyInterval({
      commitment,
      low: BigInt(bounds.min),
      high: BigInt(bounds.max),
      proof,
      transcript
    });
    if (!ok) {
      reasons.push(`Range proof for ${key} failed.`);
      return false;
    }
  }
  return true;
}
function checkBinding(attestation, reasons) {
  const { role, counts, swfHead, assertion, label } = attestation.statement;
  const described = getRole(role.id);
  if (described.feasibility !== role.feasibility || described.name !== role.name) {
    reasons.push("Role metadata does not match the CRediT vocabulary.");
  }
  if (role.binding === "unsupported") reasons.push(role.detail || "Binding is unsupported.");
  if (role.binding === "process-proven" && described.feasibility !== "high") {
    reasons.push("process-proven is only available for high-feasibility writing roles.");
  }
  if (role.binding === "typed-artifact" && described.feasibility !== "moderate") {
    reasons.push("typed-artifact is only available for moderate-feasibility roles.");
  }
  if (role.binding === "signed-assertion") {
    if (described.feasibility !== "unobserved") reasons.push("Signed assertions are for unobserved roles.");
    if (!assertion.trim()) reasons.push("Signed assertion text is empty.");
    if (attestation.cva.action !== "attest.assert") reasons.push("Assertion used the wrong agent action.");
  }
  if (role.binding === "process-proven" || role.binding === "typed-artifact") {
    if (label !== "composition") reasons.push("Process binding is not labeled composition.");
    if (counts.bulkInsertEvents !== 0) reasons.push("Bulk inserts are present.");
    if (counts.durationMs < MIN_COMPOSITION_DURATION_MS || counts.insertChars < MIN_COMPOSITION_INSERTS) {
      reasons.push("Public session counts are below the composition minimum.");
    }
    if (!/^[0-9a-f]{64}$/.test(swfHead)) reasons.push("Sequential work head is missing.");
    if (attestation.cva.action !== "attest.process") reasons.push("Process binding used the wrong agent action.");
  }
}
function signedPayload(body) {
  const payload = {
    action: body.action,
    agentPublicKey: body.agentPublicKey,
    commitments: body.commitments,
    policyHash: body.policyHash,
    rangeProofs: body.rangeProofs,
    statementHash: body.statementHash
  };
  if (body.author) payload.author = body.author;
  if (body.grantHash) payload.grantHash = body.grantHash;
  if (body.timeAnchor) payload.timeAnchor = body.timeAnchor;
  return canonicalHash(payload);
}
function sameProofSystem(value) {
  return value?.commitments === PROOF_SYSTEM.commitments && value?.range === PROOF_SYSTEM.range && value?.sequentialWork === PROOF_SYSTEM.sequentialWork && value?.agentAuthorization === PROOF_SYSTEM.agentAuthorization;
}
function assertContentHash2(hash) {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("contentHash must be a sha256 hex digest.");
}

// src/pop/explain.ts
function explainFeatures(features, bulkInsertEvents) {
  const label = matchLabel(features, bulkInsertEvents);
  return {
    label,
    bulkInsertEvents,
    checks: {
      composition: checksFor(features, REGIONS.composition),
      transcription: checksFor(features, REGIONS.transcription),
      automated: checksFor(features, REGIONS.automated)
    },
    note: noteFor(label, bulkInsertEvents)
  };
}
function checksFor(features, bounds) {
  return FEATURE_KEYS.map((feature) => {
    const value = features[feature];
    const min = bounds[feature].min;
    const max = bounds[feature].max;
    return { feature, value, min, max, inside: value >= min && value <= max };
  });
}
function noteFor(label, bulkInsertEvents) {
  if (bulkInsertEvents > 0 && label !== "composition") {
    return "A bulk insert keeps this session out of the composition region.";
  }
  if (label === "composition") return "Every composition bound holds.";
  if (label === "transcription") return "The timing fits steady transcription.";
  if (label === "automated") return "The timing fits the automated region.";
  return "The features fall outside every named region.";
}

// src/pop/histogram.ts
var PAUSE_BINS = [
  { label: "0-199", min: 0, max: 199 },
  { label: "200-499", min: 200, max: 499 },
  { label: "500-999", min: 500, max: 999 },
  { label: "1000-1999", min: 1e3, max: 1999 },
  { label: "2000-5000", min: 2e3, max: 5e3 },
  { label: "5001+", min: 5001, max: Number.POSITIVE_INFINITY }
];
function pauseHistogram(events) {
  const counts = PAUSE_BINS.map((bin) => ({ label: bin.label, count: 0 }));
  for (let index = 1; index < events.length; index += 1) {
    const gap = events[index].t - events[index - 1].t;
    const bin = counts.findIndex((_, slot) => gap >= PAUSE_BINS[slot].min && gap <= PAUSE_BINS[slot].max);
    if (bin >= 0) counts[bin].count += 1;
  }
  return counts;
}

// src/config.ts
function defaultConfig() {
  return {
    version: "zk-scribe-config/0.1.0",
    defaultRole: "writing-original-draft"
  };
}
function parseConfig(value) {
  if (!value || typeof value !== "object") throw new Error("Config must be an object.");
  const record2 = value;
  if (record2.version !== "zk-scribe-config/0.1.0") throw new Error("Unsupported config version.");
  if (typeof record2.defaultRole !== "string" || record2.defaultRole.trim() === "") {
    throw new Error("Config defaultRole is missing.");
  }
  const environment = record2.environment;
  if (environment !== void 0 && environment !== "git" && environment !== "overleaf-git" && environment !== "local") {
    throw new Error("Config environment is invalid.");
  }
  return {
    version: "zk-scribe-config/0.1.0",
    defaultRole: record2.defaultRole,
    ...typeof environment === "string" ? { environment } : {}
  };
}

// src/pop/profile.ts
function localProfile(session) {
  const gaps = interKeyIntervals(session.events);
  if (gaps.length === 0) return { samples: 0, p10: null, p50: null, p90: null };
  gaps.sort((left, right) => left - right);
  return {
    samples: gaps.length,
    p10: percentile(gaps, 10),
    p50: percentile(gaps, 50),
    p90: percentile(gaps, 90)
  };
}
function interKeyIntervals(events) {
  const gaps = [];
  for (let index = 1; index < events.length; index += 1) {
    gaps.push(events[index].t - events[index - 1].t);
  }
  return gaps;
}
function percentile(sorted, p) {
  const rank = p / 100 * (sorted.length - 1);
  const low = Math.floor(rank);
  const high = Math.ceil(rank);
  if (low === high) return sorted[low];
  const weight = rank - low;
  return sorted[low] * (1 - weight) + sorted[high] * weight;
}

// src/pop/bundle-id.ts
function bundleId(attestation) {
  return canonicalHash({
    statementHash: canonicalHash(attestation.statement),
    agentPublicKey: attestation.cva.agentPublicKey
  });
}

// src/pop/stats.ts
function sessionStats(session) {
  const extraction = extract(session);
  return {
    sessionId: session.sessionId,
    label: extraction.label,
    eventCount: extraction.eventCount,
    durationMs: extraction.durationMs,
    insertChars: extraction.insertChars,
    deleteChars: extraction.deleteChars,
    bulkInsertEvents: extraction.bulkInsertEvents,
    features: extraction.features
  };
}

// src/pop/synthesize.ts
function synthesizeSession(kind) {
  if (kind === "composition") return composition();
  if (kind === "transcription") return transcription();
  if (kind === "automated") return automated();
  return paste();
}
function composition() {
  const clock = start();
  const gaps = [80, 420, 110, 680, 150, 510, 95, 360];
  const pauses = [1400, 1800, 2200];
  for (let burst = 0; burst < 4; burst += 1) {
    for (let index = 0; index < gaps.length; index += 1) {
      if (clock.events.length > 0) advance(clock, gaps[index]);
      push(clock, "insert", 1, index === gaps.length - 1);
    }
    if (burst < pauses.length) {
      advance(clock, pauses[burst]);
      push(clock, "delete", 1, false);
      advance(clock, 240);
      push(clock, "insert", 1, false);
    }
  }
  return finish(clock, "example-composition");
}
function transcription() {
  const clock = start();
  for (let index = 0; index < 80; index += 1) {
    advance(clock, index === 0 ? 0 : 98 + index % 5);
    push(clock, "insert", 1, false);
  }
  return finish(clock, "example-transcription");
}
function automated() {
  const clock = start();
  for (let index = 0; index < 160; index += 1) {
    advance(clock, index === 0 ? 0 : 15);
    push(clock, "insert", 1, false);
  }
  return finish(clock, "example-automated");
}
function paste() {
  const clock = start();
  push(clock, "paste", 480, false);
  return finish(clock, "example-paste");
}
function start() {
  return { t: 0, events: [] };
}
function advance(clock, ms) {
  clock.t += ms;
}
function push(clock, op, len, boundary) {
  clock.events.push({ t: clock.t, op, len, boundary });
}
function finish(clock, sessionId) {
  return {
    sessionId,
    startedAt: "2026-09-26T12:00:00.000Z",
    events: clock.events
  };
}

// src/git/hook.ts
import { execFileSync as execFileSync2, spawnSync } from "node:child_process";
import fs3 from "node:fs";
import path4 from "node:path";
var BEGIN = "# zk-scribe-hook";
var END = "# zk-scribe-hook-end";
var IGNORE = [".zk-scribe/private/", "*.witness.json"];
function ensureLocalIgnore(dir) {
  const file = path4.join(dir, ".gitignore");
  const current = fs3.existsSync(file) ? fs3.readFileSync(file, "utf8") : "";
  const missing = IGNORE.filter((line) => !current.split(/\r?\n/).includes(line));
  if (missing.length === 0) return;
  const prefix = current.length === 0 || current.endsWith("\n") ? current : `${current}
`;
  fs3.writeFileSync(file, `${prefix}${missing.join("\n")}
`);
}
function installCommitHook(dir) {
  const hooks = hooksDirectory(dir);
  if (!hooks) return false;
  fs3.mkdirSync(hooks, { recursive: true });
  const target = path4.join(hooks, "pre-commit");
  const block = hookBlock(dir);
  const existing = fs3.existsSync(target) ? fs3.readFileSync(target, "utf8") : "";
  const next = existing.includes(BEGIN) ? existing.replace(hookPattern(), block) : joinHook(existing, block);
  fs3.writeFileSync(target, next);
  fs3.chmodSync(target, 493);
  return true;
}
function runCommitHook(dir) {
  try {
    if (!hooksDirectory(dir)) return;
    scanOnce(dir);
    const staged = stagedManuscripts(dir);
    if (staged.length === 0) return;
    const watched = readSession(dir);
    let wrote = 0;
    for (const relative of staged) {
      const sessionFile = watched ? sessionPath(dir) : writeCommitSession(dir, relative);
      if (!sessionFile) continue;
      if (attestFile(dir, relative, sessionFile)) wrote += 1;
    }
    if (wrote === 0) return;
    stagePublic(dir);
    if (watched) rotateSession(dir);
    log(dir, `attested ${wrote}`);
  } catch (error) {
    log(dir, error instanceof Error ? error.message : String(error));
  }
}
function attestFile(dir, relative, sessionFile) {
  const privateOut = path4.join(dir, ".zk-scribe", "private", "last-attestation.json");
  const privateWitness = path4.join(dir, ".zk-scribe", "private", "last-attestation.witness.json");
  if (fs3.existsSync(privateOut)) fs3.rmSync(privateOut);
  if (fs3.existsSync(privateWitness)) fs3.rmSync(privateWitness);
  spawnSync(
    process.execPath,
    [
      ...cliArgs(),
      "attest",
      "--dir",
      dir,
      "--file",
      relative,
      "--session",
      path4.relative(dir, sessionFile),
      "--out",
      path4.join(".zk-scribe", "private", "last-attestation.json")
    ],
    { cwd: dir, encoding: "utf8" }
  );
  if (!fs3.existsSync(privateOut)) return false;
  const attestation = JSON.parse(fs3.readFileSync(privateOut, "utf8"));
  const subject = attestation.statement.context.subject.replaceAll("\\", "/");
  if (subject !== relative.replaceAll("\\", "/")) return false;
  const output = path4.join(dir, "attestation.json");
  fs3.copyFileSync(privateOut, output);
  const name = ledgerName(attestation);
  const ledger = path4.join(dir, ".zk-scribe", "ledger", name);
  fs3.mkdirSync(path4.dirname(ledger), { recursive: true });
  fs3.copyFileSync(privateOut, ledger);
  return true;
}
function writeCommitSession(dir, relative) {
  const after = gitText(dir, [`show`, `:${relative}`]);
  if (after === null) return null;
  const before = gitText(dir, ["show", `HEAD:${relative}`]) ?? "";
  const events = eventsFromEdit(before, after, 0);
  if (events.length === 0) return null;
  const session = {
    sessionId: `commit-${relative.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 40)}`,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    events
  };
  const file = path4.join(dir, ".zk-scribe", "private", "commit-session.json");
  fs3.mkdirSync(path4.dirname(file), { recursive: true });
  fs3.writeFileSync(file, `${JSON.stringify(session, null, 2)}
`);
  return file;
}
function stagePublic(dir) {
  const ledger = path4.join(dir, ".zk-scribe", "ledger");
  const paths = [
    ".gitignore",
    "attestation.json",
    path4.join(".zk-scribe", "agent.public.json"),
    path4.join(".zk-scribe", "policy.json"),
    path4.join(".zk-scribe", "config.json")
  ];
  if (fs3.existsSync(ledger)) {
    for (const name of fs3.readdirSync(ledger)) {
      if (name.endsWith(".json")) paths.push(path4.join(".zk-scribe", "ledger", name));
    }
  }
  const present = paths.filter((file) => fs3.existsSync(path4.join(dir, file)));
  if (present.length === 0) return;
  try {
    execFileSync2("git", ["add", "--", ...present], { cwd: dir, stdio: "ignore" });
  } catch (error) {
    log(dir, error instanceof Error ? error.message : String(error));
  }
}
function stagedManuscripts(dir) {
  let out = "";
  try {
    out = execFileSync2("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    });
  } catch {
    return [];
  }
  return out.split(/\r?\n/).map((line) => line.trim().replaceAll("\\", "/")).filter((line) => line && isManuscriptRelative(dir, line));
}
function hooksDirectory(dir) {
  try {
    const relative = execFileSync2("git", ["rev-parse", "--git-path", "hooks"], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    if (!relative) return null;
    return path4.resolve(dir, relative);
  } catch {
    return null;
  }
}
function hookBlock(dir) {
  const node = process.execPath.replaceAll("\\", "/");
  const args = cliArgs().map((arg) => `"${arg.replaceAll("\\", "/")}"`).join(" ");
  const root = path4.resolve(dir).replaceAll("\\", "/");
  return `${BEGIN}
"${node}" ${args} hook --dir "${root}" >/dev/null 2>&1 || true
${END}
`;
}
function hookPattern() {
  return new RegExp(`${BEGIN}[\\s\\S]*?${END}\\n?`);
}
function joinHook(existing, block) {
  if (existing.trim() === "") return `#!/bin/sh
${block}`;
  const base = existing.endsWith("\n") ? existing : `${existing}
`;
  return `${base}${block}`;
}
function gitText(dir, args) {
  const result = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  if (result.status !== 0) return null;
  return result.stdout;
}
function ledgerName(attestation) {
  const hash = attestation.statement.contentHash.slice(0, 16);
  const session = attestation.statement.sessionId.replace(/[^a-z0-9_-]/gi, "").slice(0, 24);
  return `${hash}-${session}.json`;
}
function log(dir, line) {
  const file = path4.join(dir, ".zk-scribe", "private", "hook.log");
  fs3.mkdirSync(path4.dirname(file), { recursive: true });
  fs3.appendFileSync(file, `${(/* @__PURE__ */ new Date()).toISOString()} ${line}
`);
}

// src/status.ts
import fs4 from "node:fs";
import path5 from "node:path";
function statusCounts(dir) {
  const root = path5.join(dir, ".zk-scribe");
  const initialized = fs4.existsSync(path5.join(root, "private", "agent.seed"));
  const counts = {
    initialized,
    watching: initialized && watcherAlive(dir),
    root: watchLabel(dir),
    attested: 0,
    processProven: 0,
    typedArtifact: 0,
    signedAssertion: 0,
    refused: 0
  };
  if (!initialized) return counts;
  const seen = /* @__PURE__ */ new Set();
  for (const attestation of loadAttestations(dir)) {
    const id = `${attestation.statement.contentHash}:${attestation.statement.sessionId}:${attestation.statement.role.id}`;
    if (seen.has(id)) continue;
    seen.add(id);
    counts.attested += 1;
    const binding = attestation.statement.role.binding;
    if (binding === "process-proven") counts.processProven += 1;
    else if (binding === "typed-artifact") counts.typedArtifact += 1;
    else if (binding === "signed-assertion") counts.signedAssertion += 1;
    else counts.refused += 1;
  }
  return counts;
}
function statusText(counts) {
  if (!counts.initialized) return "Run zk-scribe init in this repository.\n";
  const lines = [];
  if (counts.attested === 0) {
    if (counts.watching) lines.push(`Watching ${counts.root}`);
    lines.push("No sessions attested yet.");
    return `${lines.join("\n")}
`;
  }
  const noun = counts.attested === 1 ? "session" : "sessions";
  lines.push(`${counts.attested} ${noun} attested, ledger building`);
  const parts = [];
  if (counts.processProven) parts.push(`${counts.processProven} process-proven`);
  if (counts.typedArtifact) parts.push(`${counts.typedArtifact} typed-artifact`);
  if (counts.signedAssertion) parts.push(`${counts.signedAssertion} signed-assertion`);
  if (counts.refused) parts.push(`${counts.refused} refused`);
  if (parts.length) lines.push(parts.join(" \xB7 "));
  if (counts.watching) lines.push(`Watching ${counts.root}`);
  return `${lines.join("\n")}
`;
}
function loadAttestations(dir) {
  const ledger = path5.join(dir, ".zk-scribe", "ledger");
  if (!fs4.existsSync(ledger)) return [];
  const found = [];
  for (const name of fs4.readdirSync(ledger)) {
    if (!name.endsWith(".json")) continue;
    try {
      found.push(JSON.parse(fs4.readFileSync(path5.join(ledger, name), "utf8")));
    } catch {
      continue;
    }
  }
  return found;
}

// src/cli.ts
var HELP = `ZK-Scribe ${VERSION}
Cryptographic authorship and contribution attestation.

Usage:
  zk-scribe init [--dir .] [--force]
  zk-scribe status [--dir .]
  zk-scribe example --kind composition|transcription|automated|paste --out session.json
  zk-scribe record --out session.json
  zk-scribe overleaf [--dir .]
  zk-scribe attest --file manuscript.md [--role <credit-role>] [--session session.json] [--assert "claim"] [--author-seed author.seed] [--grant grant.json] [--out attestation.json]
  zk-scribe verify <attestation.json> [--require process|process-proven] [--require-author] [--require-grant] [--grant grant.json] [--agent-key hex] [--policy policy.json]
  A .zk-scribe/revoked.json list, when present, refuses those agent keys.
  A .zk-scribe/grant.json file, when present, scopes attest and export to that grant.
  zk-scribe audit --attestation attestation.json --session session.json --witness attestation.witness.json
  zk-scribe export <attestation.json> --format c2pa|jats|summary|html [--out file]
  zk-scribe explain --session session.json
  zk-scribe doctor [--dir .]
  zk-scribe hash <file-or-directory>
  zk-scribe suggest <file>
  zk-scribe summary <attestation.json>
  zk-scribe histogram --session session.json
  zk-scribe ledger <attestation.json>...
  zk-scribe diffstat <changes.diff> [--content-hash hex]
  zk-scribe policy
  zk-scribe grant --file manuscript.md --actions attest.process,export.manifest --author-seed author.seed [--out .zk-scribe/grant.json]
  zk-scribe govern --action attest.process --file manuscript.md [--grant grant.json]
  zk-scribe journal
  zk-scribe stats --session session.json
  zk-scribe profile --session session.json
  zk-scribe id <attestation.json>
  zk-scribe benchmark
  zk-scribe credit
`;
function main(argv) {
  const { command, flags, positionals } = parseArgs(argv);
  if (!command || flags.help === true || command === "help" || command === "--help") {
    process.stdout.write(HELP);
    return;
  }
  if (command === "init") return init(String(flags.dir ?? "."), flags.force === true);
  if (command === "status") return statusCommand(flags);
  if (command === "watch") return watchCommand(flags);
  if (command === "hook") return runCommitHook(path6.resolve(String(flags.dir ?? ".")));
  if (command === "example") return example(flags);
  if (command === "record") return void record(String(flags.out ?? "session.json")).catch(fail);
  if (command === "overleaf") return void overleafCommand(flags).catch(fail);
  if (command === "attest") return void attestCommand(flags).catch((error) => fail(error, 2));
  if (command === "verify") return verifyCommand(flags, positionals);
  if (command === "audit") return auditCommand(flags);
  if (command === "export") return exportCommand(flags, positionals);
  if (command === "explain") return explainCommand(flags);
  if (command === "doctor") return doctorCommand(flags);
  if (command === "hash") return hashCommand(flags, positionals);
  if (command === "suggest") return suggestCommand(flags, positionals);
  if (command === "summary") return summaryCommand(flags, positionals);
  if (command === "histogram") return histogramCommand(flags);
  if (command === "ledger") return ledgerCommand(flags, positionals);
  if (command === "diffstat") return diffstatCommand(flags, positionals);
  if (command === "policy") return policyCommand(flags);
  if (command === "grant") return grantCommand(flags);
  if (command === "govern") return governCommand(flags);
  if (command === "journal") return journalCommand(flags);
  if (command === "stats") return statsCommand(flags);
  if (command === "profile") return profileCommand(flags);
  if (command === "id") return idCommand(flags, positionals);
  if (command === "benchmark") return benchmarkCommand();
  if (command === "credit") return credit();
  throw new Error(`Unknown command "${command}".

${HELP}`);
}
function init(dir, force) {
  const rootDir = path6.resolve(dir);
  const root = path6.join(rootDir, ".zk-scribe");
  const seedPath = path6.join(root, "private", "agent.seed");
  const publicPath = path6.join(root, "agent.public.json");
  fs5.mkdirSync(path6.dirname(seedPath), { recursive: true });
  const kept = fs5.existsSync(seedPath) && !force;
  if (!kept) {
    const key = generateAgentKey();
    fs5.writeFileSync(seedPath, `${encodeKey(key.secretKey)}
`);
    fs5.writeFileSync(publicPath, publicKeyFile(encodeKey(key.publicKey)));
  } else if (!fs5.existsSync(publicPath)) {
    const secret = decodeSecretKey(fs5.readFileSync(seedPath, "utf8").trim());
    fs5.writeFileSync(publicPath, publicKeyFile(encodeKey(publicKeyFromSecret(secret))));
  }
  const policyPath = path6.join(root, "policy.json");
  if (!fs5.existsSync(policyPath) || force) {
    fs5.writeFileSync(policyPath, `${JSON.stringify(defaultPolicy(), null, 2)}
`);
  }
  const configPath = path6.join(root, "config.json");
  if (!fs5.existsSync(configPath) || force) {
    fs5.writeFileSync(configPath, `${JSON.stringify(defaultConfig(), null, 2)}
`);
  }
  ensureLocalIgnore(rootDir);
  const hooked = installCommitHook(rootDir);
  const watching = process.stdout.isTTY === true && startWatcher(rootDir);
  process.stdout.write(kept ? "Agent key is on this machine.\n" : `Initialized ${root}
`);
  process.stdout.write("The seed in .zk-scribe/private/ stays local.\n");
  if (hooked) process.stdout.write("Commit hook installed.\n");
  if (watching) process.stdout.write(`Watching ${watchLabel(rootDir)}
`);
  process.stdout.write("zk-scribe status\n");
}
function publicKeyFile(publicKey) {
  return `${JSON.stringify({ version: "zk-scribe-agent/0.1.0", algorithm: "ed25519", publicKey }, null, 2)}
`;
}
function statusCommand(flags) {
  process.stdout.write(statusText(statusCounts(path6.resolve(String(flags.dir ?? ".")))));
}
function watchCommand(flags) {
  const dir = path6.resolve(String(flags.dir ?? "."));
  const pid = path6.join(dir, ".zk-scribe", "private", "watch.pid");
  fs5.mkdirSync(path6.dirname(pid), { recursive: true });
  fs5.writeFileSync(pid, `${process.pid}
`);
  const tick = () => {
    try {
      scanOnce(dir);
    } catch {
    }
  };
  tick();
  const timer = setInterval(tick, 500);
  const stop = () => {
    clearInterval(timer);
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
function example(flags) {
  const kind = String(flags.kind ?? "");
  if (kind !== "composition" && kind !== "transcription" && kind !== "automated" && kind !== "paste") {
    throw new Error("Pass --kind composition|transcription|automated|paste.");
  }
  const out = String(flags.out ?? "");
  if (!out) throw new Error("Pass --out for the session log.");
  fs5.mkdirSync(path6.dirname(path6.resolve(out)), { recursive: true });
  fs5.writeFileSync(out, `${JSON.stringify(synthesizeSession(kind), null, 2)}
`);
  process.stdout.write(`Wrote ${out}
`);
}
async function attestCommand(flags) {
  const dir = projectDir(flags);
  const file = resolveIn(dir, required(flags, "file"));
  const role = roleFor(dir, flags);
  const out = resolveIn(dir, String(flags.out ?? "attestation.json"));
  const policy = loadPolicy(dir, flags.policy);
  const secret = loadSecret(dir);
  const contentHash = sha256Hex(fs5.readFileSync(file));
  const assertion = flags.assert === void 0 ? void 0 : String(flags.assert);
  const sessionFile = flags.session ? resolveIn(dir, String(flags.session)) : "";
  let session = sessionFile ? readJson(sessionFile) : void 0;
  if (session && (session.source === "record" || session.source === "overleaf" || session.source === "editor")) {
    const sealed = await ensureAnchor(session);
    if (canonicalHash(sealed.timeAnchor ?? null) !== canonicalHash(session.timeAnchor ?? null)) {
      writeJson(sessionFile, sealed);
    }
    session = sealed;
  }
  const context = contextFrom(flags, dir, file);
  const grantHash = applyGovernance(dir, flags, policy, assertedAction(flags), contentHash);
  const { attestation, witness } = attest({
    role,
    contentHash,
    context,
    policy,
    agentSecretKey: secret,
    session,
    assertion,
    authorSecretKey: authorSeed(dir, flags["author-seed"]),
    grantHash
  });
  writeJson(out, attestation);
  if (witness) writeJson(witnessPathFor(out), witness);
  const binding = attestation.statement.role.binding;
  process.stdout.write(`${binding}: ${attestation.statement.role.detail}
`);
  process.stdout.write(`Wrote ${out}
`);
  if (witness) process.stdout.write(`Wrote ${witnessPathFor(out)} (keep this local)
`);
  if (binding === "unsupported") process.exitCode = 1;
}
function roleFor(dir, flags) {
  if (typeof flags.role === "string" && flags.role.trim() !== "") return flags.role;
  const configPath = path6.join(dir, ".zk-scribe", "config.json");
  if (!fs5.existsSync(configPath)) throw new Error("Pass --role, or add defaultRole to .zk-scribe/config.json.");
  return parseConfig(JSON.parse(fs5.readFileSync(configPath, "utf8"))).defaultRole;
}
function authorSeed(dir, value) {
  if (typeof value !== "string") return void 0;
  return decodeSecretKey(fs5.readFileSync(resolveIn(dir, value), "utf8").trim());
}
function verifyCommand(flags, positionals) {
  const project = projectDir(flags);
  const raw = positionals[0] ?? (flags.attestation === void 0 ? "" : String(flags.attestation));
  if (!raw) throw new Error("Pass the attestation file to verify.");
  const file = resolveIn(project, raw);
  const attestation = readJson(file);
  const requireFlag = flags.require === void 0 ? void 0 : String(flags.require);
  if (requireFlag !== void 0 && requireFlag !== "process" && requireFlag !== "process-proven") {
    throw new Error("--require must be process or process-proven.");
  }
  const result = verify2(attestation, {
    trustedAgentKey: loadTrustedKey(project, flags["agent-key"]),
    expectedPolicy: loadPolicy(project, flags.policy),
    require: requireFlag,
    requireAuthor: flags["require-author"] === true,
    requireGrant: flags["require-grant"] === true,
    revokedKeys: loadRevokedKeys(project),
    grant: typeof flags.grant === "string" ? parseGrant(readJson(resolveIn(project, flags.grant))) : void 0
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}
`);
  if (!result.ok) process.exitCode = 1;
}
function loadRevokedKeys(dir) {
  const file = path6.join(dir, ".zk-scribe", "revoked.json");
  if (!fs5.existsSync(file)) return void 0;
  return parseRevocationList(JSON.parse(fs5.readFileSync(file, "utf8")));
}
function auditCommand(flags) {
  const attestation = readJson(required(flags, "attestation"));
  const session = readJson(required(flags, "session"));
  const witness = readJson(required(flags, "witness"));
  const result = audit(attestation, session, witness);
  process.stdout.write(`${JSON.stringify(result, null, 2)}
`);
  if (!result.ok) process.exitCode = 1;
}
function exportCommand(flags, positionals) {
  const file = positionals[0] ?? "";
  if (!file) throw new Error("Pass the attestation file to export.");
  const format = String(flags.format ?? "");
  const dir = projectDir(flags);
  const attestation = readJson(file);
  const policy = loadPolicy(dir, flags.policy);
  if (format === "c2pa" || format === "summary" || format === "html" || format === "jats") {
    applyGovernance(dir, flags, policy, format === "jats" ? "export.jats" : "export.manifest", attestation.statement.contentHash);
  }
  if (format === "c2pa") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "manifest.c2pa.json");
    writeJson(out, toProvenanceManifest(attestation));
    process.stdout.write(`Wrote ${out}
`);
    return;
  }
  if (format === "jats") {
    if (!policy.allow.includes("export.jats") || policy.deny.includes("export.jats")) {
      throw new Error("Policy does not allow export.jats.");
    }
    const out = String(flags.out ?? "attestation.jats.xml");
    fs5.writeFileSync(out, toJats(attestation));
    process.stdout.write(`Wrote ${out}
`);
    return;
  }
  if (format === "summary") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "summary.json");
    writeJson(out, toSummary(attestation));
    process.stdout.write(`Wrote ${out}
`);
    return;
  }
  if (format === "html") {
    if (!policy.allow.includes("export.manifest") || policy.deny.includes("export.manifest")) {
      throw new Error("Policy does not allow export.manifest.");
    }
    const out = String(flags.out ?? "attestation.html");
    fs5.writeFileSync(out, toHtmlReport(attestation));
    process.stdout.write(`Wrote ${out}
`);
    return;
  }
  throw new Error("Pass --format c2pa, jats, summary, or html.");
}
function statsCommand(flags) {
  const session = readJson(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(sessionStats(session), null, 2)}
`);
}
function profileCommand(flags) {
  const session = readJson(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(localProfile(session), null, 2)}
`);
}
function idCommand(flags, positionals) {
  const target = positionals[0];
  if (!target) throw new Error("Pass an attestation file.");
  const attestation = readJson(resolveIn(projectDir(flags), target));
  process.stdout.write(`${bundleId(attestation)}
`);
}
function benchmarkCommand() {
  process.stdout.write(`${JSON.stringify(rangeBenchmark(), null, 2)}
`);
}
function policyCommand(flags) {
  const lint = lintPolicy(loadPolicy(projectDir(flags), flags.policy));
  process.stdout.write(`${JSON.stringify(lint, null, 2)}
`);
  if (!lint.ok) process.exitCode = 1;
}
function grantCommand(flags) {
  const dir = projectDir(flags);
  const author = authorSeed(dir, flags["author-seed"]);
  if (!author) throw new Error("Pass --author-seed for the grant signer.");
  const actions = String(flags.actions ?? "").split(",").map((action) => action.trim()).filter((action) => action.length > 0);
  const grant = issueGrant({
    agentPublicKey: loadTrustedKey(dir, flags["agent-key"]),
    policy: loadPolicy(dir, flags.policy),
    actions,
    contentHash: sha256Hex(fs5.readFileSync(resolveIn(dir, required(flags, "file")))),
    authorSecretKey: author
  });
  const out = resolveIn(dir, String(flags.out ?? path6.join(".zk-scribe", "grant.json")));
  writeJson(out, grant);
  process.stdout.write(`Wrote ${out}
`);
}
function governCommand(flags) {
  const dir = projectDir(flags);
  const policy = loadPolicy(dir, flags.policy);
  const contentHash = sha256Hex(fs5.readFileSync(resolveIn(dir, required(flags, "file"))));
  const decision = decideAndRecord(dir, flags, policy, required(flags, "action"), contentHash);
  process.stdout.write(`${JSON.stringify(decision, null, 2)}
`);
  if (!decision.allow) process.exitCode = 1;
}
function journalCommand(flags) {
  const result = auditJournal(readJournal(projectDir(flags)));
  process.stdout.write(`${JSON.stringify(result, null, 2)}
`);
  if (!result.ok) process.exitCode = 1;
}
function assertedAction(flags) {
  return typeof flags.assert === "string" && flags.assert.trim() !== "" ? "attest.assert" : "attest.process";
}
function applyGovernance(dir, flags, policy, action, contentHash) {
  if (!readGovernedGrant(dir, flags)) return void 0;
  const decision = decideAndRecord(dir, flags, policy, action, contentHash);
  if (!decision.allow) throw new Error(decision.reasons.join(" "));
  return decision.grantHash;
}
function decideAndRecord(dir, flags, policy, action, contentHash) {
  const secret = loadSecret(dir);
  const agentPublicKey = encodeKey(publicKeyFromSecret(secret));
  const decision = govern({
    action,
    agentPublicKey,
    policy,
    contentHash,
    revokedKeys: loadRevokedKeys(dir),
    grant: readGovernedGrant(dir, flags)
  });
  const next = appendJournal(readJournal(dir), {
    action,
    agentPublicKey,
    contentHash,
    policyHash: policyHash(policy),
    grantHash: decision.grantHash ?? null,
    allow: decision.allow,
    reasons: decision.reasons,
    agentSecretKey: secret
  });
  writeJournal(dir, next);
  return decision;
}
function readGovernedGrant(dir, flags) {
  if (typeof flags.grant === "string") return parseGrant(readJson(resolveIn(dir, flags.grant)));
  const fallback = path6.join(dir, ".zk-scribe", "grant.json");
  if (!fs5.existsSync(fallback)) return void 0;
  return parseGrant(readJson(fallback));
}
function journalFile(dir) {
  return path6.join(dir, ".zk-scribe", "private", "journal.jsonl");
}
function readJournal(dir) {
  const file = journalFile(dir);
  if (!fs5.existsSync(file)) return [];
  return fs5.readFileSync(file, "utf8").split(/\r?\n/).filter((line) => line.trim() !== "").map((line) => parseJournalEntry(JSON.parse(line)));
}
function writeJournal(dir, entries) {
  const file = journalFile(dir);
  fs5.mkdirSync(path6.dirname(file), { recursive: true });
  const body = entries.map((entry) => JSON.stringify(entry)).join("\n");
  fs5.writeFileSync(file, body.length === 0 ? "" : `${body}
`);
}
function diffstatCommand(flags, positionals) {
  const target = positionals[0];
  if (!target) throw new Error("Pass a unified diff file.");
  const diff = fs5.readFileSync(resolveIn(projectDir(flags), target), "utf8");
  const stat = parseDiffStat(diff);
  const contentHash = flags["content-hash"];
  const body = typeof contentHash === "string" ? reviewNote(contentHash, stat) : stat;
  process.stdout.write(`${JSON.stringify(body, null, 2)}
`);
}
function ledgerCommand(flags, positionals) {
  if (positionals.length === 0) throw new Error("Pass one or more attestation files.");
  const dir = projectDir(flags);
  const entries = positionals.map((file) => toSummary(readJson(resolveIn(dir, file))));
  const out = flags.out === void 0 ? "" : String(flags.out);
  const ledger = buildLedger(entries);
  if (out) writeJson(resolveIn(dir, out), ledger);
  else process.stdout.write(`${JSON.stringify(ledger, null, 2)}
`);
}
function histogramCommand(flags) {
  const session = readJson(resolveIn(projectDir(flags), required(flags, "session")));
  process.stdout.write(`${JSON.stringify(pauseHistogram(session.events), null, 2)}
`);
}
function summaryCommand(flags, positionals) {
  const target = positionals[0];
  if (!target) throw new Error("Pass an attestation file to summarize.");
  const attestation = readJson(resolveIn(projectDir(flags), target));
  process.stdout.write(`${JSON.stringify(toSummary(attestation), null, 2)}
`);
}
function suggestCommand(flags, positionals) {
  const target = positionals[0];
  if (!target) throw new Error("Pass a manuscript path to suggest a role.");
  process.stdout.write(`${JSON.stringify(suggestRole(resolveIn(projectDir(flags), target)), null, 2)}
`);
}
function hashCommand(flags, positionals) {
  const target = positionals[0];
  if (!target) throw new Error("Pass a file or directory to hash.");
  const full = resolveIn(projectDir(flags), target);
  if (!fs5.existsSync(full)) throw new Error(`Nothing found at ${full}.`);
  const stat = fs5.statSync(full);
  const files = stat.isDirectory() ? collectTree(full) : [{ path: path6.basename(full), bytes: fs5.readFileSync(full) }];
  process.stdout.write(`${hashTree(files)}
`);
}
function collectTree(root) {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs5.readdirSync(dir, { withFileTypes: true })) {
      const full = path6.join(dir, entry.name);
      const relative = path6.relative(root, full);
      if (ignoredTreePath(relative)) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files.push({ path: relative, bytes: fs5.readFileSync(full) });
    }
  };
  walk(root);
  return files;
}
function doctorCommand(flags) {
  const dir = projectDir(flags);
  const root = path6.join(dir, ".zk-scribe");
  const major = Number(process.versions.node.split(".")[0]);
  const report = doctorReport({
    nodeMajor: major,
    minimumMajor: 22,
    policyExists: fs5.existsSync(path6.join(root, "policy.json")),
    publicKeyExists: fs5.existsSync(path6.join(root, "agent.public.json")),
    seedExists: fs5.existsSync(path6.join(root, "private", "agent.seed"))
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}
`);
  if (!report.ok) process.exitCode = 1;
}
function explainCommand(flags) {
  const session = readJson(resolveIn(projectDir(flags), required(flags, "session")));
  const extraction = extract(session);
  const explanation = explainFeatures(extraction.features, extraction.bulkInsertEvents);
  process.stdout.write(`${JSON.stringify({
    label: explanation.label,
    note: explanation.note,
    durationMs: extraction.durationMs,
    insertChars: extraction.insertChars,
    checks: explanation.checks
  }, null, 2)}
`);
}
function credit() {
  for (const role of CREDIT_ROLES) {
    process.stdout.write(`${role.feasibility.padEnd(12)} ${role.id.padEnd(28)} ${role.observes}
`);
  }
}
async function overleafCommand(flags) {
  const dir = projectDir(flags);
  if (!fs5.existsSync(path6.join(dir, ".zk-scribe", "config.json"))) {
    throw new Error("Run zk-scribe init in this repository.");
  }
  const bridge = await startOverleafBridge(dir);
  const folder = path6.resolve(path6.dirname(fileURLToPath(import.meta.url)), "..", "editors", "overleaf");
  process.stdout.write(`Overleaf bridge listening on 127.0.0.1:${bridge.port}
`);
  process.stdout.write(`Token ${bridge.token}
`);
  process.stdout.write(`Load the unpacked extension from ${folder}
`);
  process.stdout.write("Paste the port and token into the extension options. The bridge stores edit lengths only.\n");
  process.stdout.write("Ctrl+C stops the bridge.\n");
  await new Promise((resolve) => {
    const stop = () => {
      void bridge.close().then(() => resolve());
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}
async function record(out) {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    throw new Error("record needs an interactive terminal.");
  }
  let beaconStart = null;
  try {
    beaconStart = await fetchLatest();
  } catch {
    beaconStart = null;
  }
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const events = [];
  let text = "";
  const rl = readline.createInterface({ input: process.stdin });
  readline.emitKeypressEvents(process.stdin, rl);
  process.stdin.setRawMode(true);
  process.stdout.write("Timing keystrokes. Typed text stays on screen and is not saved.\nCtrl+D writes the timing log. Ctrl+C discards it.\n");
  const finished = await new Promise((resolve) => {
    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.off("keypress", onKey);
      rl.close();
    };
    const onKey = (str, key) => {
      const step = eventFromKey({ ...key, sequence: key.sequence || str }, Date.now() - started);
      if (step.kind === "abort") {
        cleanup();
        resolve("discard");
        return;
      }
      if (step.kind === "finish") {
        cleanup();
        resolve("save");
        return;
      }
      if (step.kind === "event") {
        text = applyTextDelta(text, step.event, step.textDelta);
        events.push(step.event);
        if (step.event.op === "delete") process.stdout.write("\b \b");
        else if (step.textDelta) process.stdout.write(step.textDelta);
      }
    };
    process.stdin.on("keypress", onKey);
  });
  if (finished === "discard") {
    process.stdout.write("\nDiscarded. Nothing was written.\n");
    process.exitCode = 1;
    return;
  }
  const session = {
    sessionId: `rec-${started.toString(16)}`,
    startedAt,
    source: "record",
    events
  };
  const duration = events.length === 0 ? 0 : events[events.length - 1].t - events[0].t;
  if (!beaconStart) {
    process.stdout.write("Time beacon was unavailable. The log was saved without a wall-clock window.\n");
  } else {
    try {
      let end = await fetchLatest();
      const deadline = Date.now() + QUICKNET.period * 1e3 * 3 + 500;
      let anchor = { scheme: "drand-quicknet-v1", startedAt, start: beaconStart, end };
      while (needsAnotherRound(windowProblem(anchor, duration)) && Date.now() < deadline) {
        await delay2(QUICKNET.period * 1e3 + 200);
        end = await fetchLatest();
        anchor = { scheme: "drand-quicknet-v1", startedAt, start: beaconStart, end };
      }
      const problem = windowProblem(anchor, duration);
      if (problem) process.stdout.write(`${problem} The log was saved without a time beacon.
`);
      else session.timeAnchor = anchor;
    } catch {
      process.stdout.write("Time beacon was unavailable. The log was saved without a wall-clock window.\n");
    }
  }
  writeJson(out, session);
  process.stdout.write(`
Saved ${events.length} timing events to ${out}
`);
  process.stdout.write(`Local buffer hash ${sha256Hex(utf8(text))} (the text was not written)
`);
  if (session.timeAnchor) {
    process.stdout.write(`Time window rounds ${session.timeAnchor.start.round}\u2013${session.timeAnchor.end.round}
`);
  }
}
function delay2(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function projectDir(flags) {
  return path6.resolve(typeof flags.dir === "string" ? flags.dir : process.cwd());
}
function resolveIn(dir, file) {
  return path6.resolve(dir, file);
}
function contextFrom(flags, cwd, file) {
  const detected = detectContext(cwd, path6.resolve(file));
  const requested = flags.environment === void 0 ? void 0 : String(flags.environment);
  if (requested === void 0) return detected;
  if (requested !== "git" && requested !== "overleaf-git" && requested !== "local") {
    throw new Error("--environment must be git, overleaf-git, or local.");
  }
  return { ...detected, environment: requested };
}
function loadPolicy(cwd, override) {
  const file = typeof override === "string" ? override : path6.join(cwd, ".zk-scribe", "policy.json");
  if (!fs5.existsSync(file)) throw new Error(`Policy not found at ${file}. Run zk-scribe init.`);
  return readJson(file);
}
function loadSecret(cwd) {
  const file = path6.join(cwd, ".zk-scribe", "private", "agent.seed");
  if (!fs5.existsSync(file)) throw new Error(`Agent seed not found at ${file}. Run zk-scribe init.`);
  return decodeSecretKey(fs5.readFileSync(file, "utf8").trim());
}
function loadTrustedKey(cwd, override) {
  if (typeof override === "string") return override;
  const file = path6.join(cwd, ".zk-scribe", "agent.public.json");
  if (!fs5.existsSync(file)) throw new Error(`Trusted agent key not found at ${file}. Pass --agent-key.`);
  const parsed = readJson(file);
  if (!parsed.publicKey) throw new Error("agent.public.json is missing publicKey.");
  return parsed.publicKey;
}
function witnessPathFor(out) {
  return out.endsWith(".json") ? `${out.slice(0, -5)}.witness.json` : `${out}.witness.json`;
}
function required(flags, name) {
  const value = flags[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`Pass --${name}.`);
  return value;
}
function readJson(file) {
  return JSON.parse(fs5.readFileSync(file, "utf8"));
}
function writeJson(file, value) {
  fs5.mkdirSync(path6.dirname(path6.resolve(file)), { recursive: true });
  fs5.writeFileSync(file, `${JSON.stringify(value, null, 2)}
`);
}
function parseArgs(argv) {
  const [command = "", ...rest] = argv;
  const flags = {};
  const positionals = [];
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const key = token.slice(2);
    const next = rest[index + 1];
    if (next === void 0 || next.startsWith("--")) flags[key] = true;
    else {
      flags[key] = next;
      index += 1;
    }
  }
  return { command, flags, positionals };
}
function fail(error, code = 1) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}
`);
  process.exit(code);
}
try {
  main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}
`);
  process.exitCode = 2;
}

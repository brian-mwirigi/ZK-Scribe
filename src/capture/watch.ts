import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { eventsFromEdit } from "./edits.ts";
import type { KeyEvent, SessionLog } from "../pop/session.ts";

const TEXT = new Set([".md", ".markdown", ".tex", ".txt"]);
const SKIP = new Set([".git", ".zk-scribe", "node_modules", "output", "build", "dist"]);
const MAX_CHARS = 2_000_000;

type WatchState = { files: Record<string, string> };

export function watchLabel(dir: string): string {
  return fs.existsSync(path.join(dir, "content")) ? "content/" : "this directory";
}

export function listManuscripts(dir: string): string[] {
  const content = path.join(dir, "content");
  const root = fs.existsSync(content) && fs.statSync(content).isDirectory() ? content : dir;
  const files: string[] = [];
  const walk = (folder: string) => {
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

export function isManuscriptRelative(dir: string, relativePath: string): boolean {
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

export function sessionPath(dir: string): string {
  return path.join(dir, ".zk-scribe", "private", "session.json");
}

export function readSession(dir: string): SessionLog | null {
  const file = sessionPath(dir);
  if (!fs.existsSync(file)) return null;
  const session = JSON.parse(fs.readFileSync(file, "utf8")) as SessionLog;
  if (!Array.isArray(session.events) || session.events.length === 0) return null;
  return session;
}

export function rotateSession(dir: string): void {
  const file = sessionPath(dir);
  if (fs.existsSync(file)) fs.rmSync(file);
}

export function scanOnce(dir: string, now = Date.now()): number {
  const state = readState(dir);
  const current = readSession(dir);
  const started = current ? Date.parse(current.startedAt) : now;
  let t = Math.max(0, now - (Number.isFinite(started) ? started : now));
  if (current && current.events.length > 0) t = Math.max(t, current.events[current.events.length - 1].t);
  const next: Record<string, string> = {};
  const events: KeyEvent[] = [];
  for (const file of listManuscripts(dir)) {
    const relative = path.relative(dir, file).replaceAll("\\", "/");
    const text = fs.readFileSync(file, "utf8");
    if (text.length > MAX_CHARS) continue;
    next[relative] = text;
    const before = state.files[relative];
    if (before === undefined) continue;
    const delta = eventsFromEdit(before, text, t);
    if (delta.length === 0) continue;
    events.push(...delta);
    t += 1;
  }
  writeState(dir, { files: next });
  if (events.length === 0) return 0;
  const session: SessionLog = current ?? {
    sessionId: `watch-${now.toString(16)}`,
    startedAt: new Date(now).toISOString(),
    events: [],
  };
  session.events.push(...events);
  writeSession(dir, session);
  return events.length;
}

export function watcherAlive(dir: string): boolean {
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

export function startWatcher(dir: string): boolean {
  if (watcherAlive(dir)) return true;
  const cli = fileURLToPath(new URL("../cli.ts", import.meta.url));
  const child = spawn(process.execPath, ["--experimental-strip-types", cli, "watch", "--dir", dir], {
    cwd: dir,
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  if (!child.pid) return false;
  child.unref();
  fs.mkdirSync(path.dirname(pidFile(dir)), { recursive: true });
  fs.writeFileSync(pidFile(dir), `${child.pid}\n`);
  return true;
}

function isManuscriptName(name: string): boolean {
  if (name.toLowerCase() === "readme.md") return false;
  return TEXT.has(path.extname(name).toLowerCase());
}

function statePath(dir: string): string {
  return path.join(dir, ".zk-scribe", "private", "watch-state.json");
}

function pidFile(dir: string): string {
  return path.join(dir, ".zk-scribe", "private", "watch.pid");
}

function readState(dir: string): WatchState {
  const file = statePath(dir);
  if (!fs.existsSync(file)) return { files: {} };
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as WatchState;
  return parsed && parsed.files ? parsed : { files: {} };
}

function writeState(dir: string, state: WatchState): void {
  const file = statePath(dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(state)}\n`);
}

function writeSession(dir: string, session: SessionLog): void {
  const file = sessionPath(dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(session, null, 2)}\n`);
}

import type { KeyEvent } from "../pop/session.ts";

// A save or a commit is one observed edit. Splitting it into single keystrokes
// would invent a writing session the agent did not see.
export function eventsFromEdit(before: string, after: string, t: number): KeyEvent[] {
  if (before === after) return [];
  let prefix = 0;
  const maxPrefix = Math.min(before.length, after.length);
  while (prefix < maxPrefix && before.charCodeAt(prefix) === after.charCodeAt(prefix)) prefix += 1;
  let suffix = 0;
  const maxSuffix = maxPrefix - prefix;
  while (
    suffix < maxSuffix &&
    before.charCodeAt(before.length - 1 - suffix) === after.charCodeAt(after.length - 1 - suffix)
  ) {
    suffix += 1;
  }
  const removed = before.length - prefix - suffix;
  const added = after.length - prefix - suffix;
  const events: KeyEvent[] = [];
  if (removed > 0) events.push({ t, op: "delete", len: removed });
  if (added > 0) {
    const chunk = after.slice(prefix, after.length - suffix);
    const boundary = /[\s.!?]$/.test(chunk);
    events.push({ t, op: "insert", len: added, ...(boundary ? { boundary: true } : {}) });
  }
  return events;
}

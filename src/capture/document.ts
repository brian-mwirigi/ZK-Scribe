import { BULK_INSERT_CHARS } from "../pop/constants.ts";
import type { KeyEvent } from "../pop/session.ts";

export type TextChange = {
  removed: number;
  inserted: string;
};

// One editor change is one delete and/or one insert of the length the editor
// reported. The characters are not copied onto the event.
export function eventsFromTextChange(change: TextChange, t: number): KeyEvent[] {
  const events: KeyEvent[] = [];
  if (change.removed > 0) events.push({ t, op: "delete", len: change.removed });
  const inserted = change.inserted;
  if (inserted.length > 0) {
    const boundary = /[\s.!?;:\n]$/.test(inserted);
    events.push({
      t,
      op: inserted.length >= BULK_INSERT_CHARS ? "paste" : "insert",
      len: inserted.length,
      ...(boundary ? { boundary: true } : {}),
    });
  }
  return events;
}

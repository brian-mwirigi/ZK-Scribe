import { extract } from "./extract.ts";
import type { Features } from "./constants.ts";
import type { Label } from "./regions.ts";
import type { SessionLog } from "./session.ts";

export type SessionStats = {
  sessionId: string;
  label: Label;
  eventCount: number;
  durationMs: number;
  insertChars: number;
  deleteChars: number;
  bulkInsertEvents: number;
  features: Features;
};

export function sessionStats(session: SessionLog): SessionStats {
  const extraction = extract(session);
  return {
    sessionId: session.sessionId,
    label: extraction.label,
    eventCount: extraction.eventCount,
    durationMs: extraction.durationMs,
    insertChars: extraction.insertChars,
    deleteChars: extraction.deleteChars,
    bulkInsertEvents: extraction.bulkInsertEvents,
    features: extraction.features,
  };
}

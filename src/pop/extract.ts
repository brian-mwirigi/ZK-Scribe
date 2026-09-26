import {
  BULK_INSERT_CHARS,
  FEATURE_KEYS,
  PEAK_WINDOW_MS,
  PLANNING_PAUSE_MAX_MS,
  PLANNING_PAUSE_MIN_MS,
  type Features,
} from "./constants.ts";
import { matchLabel, type Label } from "./regions.ts";
import { validateSession, type SessionLog } from "./session.ts";

export type Extraction = {
  features: Features;
  label: Label;
  eventCount: number;
  durationMs: number;
  insertChars: number;
  deleteChars: number;
  bulkInsertEvents: number;
};

export function extract(session: SessionLog): Extraction {
  validateSession(session);
  const events = session.events;
  const inserts = events.filter((event) => event.op === "insert" || event.op === "paste");
  const deletes = events.filter((event) => event.op === "delete");
  const ikis: number[] = [];
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
  const features: Features = {
    medianIkiMs: median(ikis),
    ikiCvTimes100: coefficientOfVariationTimes100(ikis),
    planningPauses,
    boundaryPauses,
    peakCpsTimes10: peakCharsPerSecondTimes10(inserts),
    revisionPermille: revisionDenom === 0 ? 0 : Math.round((deleteChars / revisionDenom) * 1000),
  };
  for (const key of FEATURE_KEYS) {
    if (!Number.isInteger(features[key]) || features[key] < 0) {
      throw new Error(`Feature ${key} is not a non-negative integer.`);
    }
  }

  const bulkInsertEvents = events.filter(
    (event) => (event.op === "paste" || event.len >= BULK_INSERT_CHARS) && event.op !== "delete" && event.op !== "navigate",
  ).length;
  const durationMs = events.length === 0 ? 0 : events[events.length - 1].t - events[0].t;
  return {
    features,
    label: matchLabel(features, bulkInsertEvents),
    eventCount: events.length,
    durationMs,
    insertChars,
    deleteChars,
    bulkInsertEvents,
  };
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  return sorted[mid];
}

function coefficientOfVariationTimes100(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (mean === 0) return 0;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return Math.round((Math.sqrt(variance) / mean) * 100);
}

function peakCharsPerSecondTimes10(inserts: Array<{ t: number; len: number }>): number {
  let start = 0;
  let chars = 0;
  let maxChars = 0;
  for (let index = 0; index < inserts.length; index += 1) {
    chars += inserts[index].len;
    while (inserts[start].t + PEAK_WINDOW_MS <= inserts[index].t) {
      chars -= inserts[start].len;
      start += 1;
    }
    if (chars > maxChars) maxChars = chars;
  }
  return Math.round((maxChars / (PEAK_WINDOW_MS / 1000)) * 10);
}

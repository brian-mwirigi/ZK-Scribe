export const PLANNING_PAUSE_MIN_MS = 1000;
export const PLANNING_PAUSE_MAX_MS = 5000;
export const PEAK_WINDOW_MS = 2000;
export const BULK_INSERT_CHARS = 15;
export const MIN_COMPOSITION_DURATION_MS = 8000;
export const MIN_COMPOSITION_INSERTS = 20;

export const FEATURE_KEYS = [
  "medianIkiMs",
  "ikiCvTimes100",
  "planningPauses",
  "boundaryPauses",
  "peakCpsTimes10",
  "revisionPermille",
] as const;

export type FeatureKey = (typeof FEATURE_KEYS)[number];
export type Features = Record<FeatureKey, number>;

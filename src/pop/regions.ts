import { FEATURE_KEYS, type FeatureKey, type Features } from "./constants.ts";

export type Bound = { min: number; max: number };
export type FeatureBounds = Record<FeatureKey, Bound>;
export type Label = "composition" | "transcription" | "automated" | "indeterminate";

export const REGIONS: Record<Exclude<Label, "indeterminate">, FeatureBounds> = {
  composition: {
    medianIkiMs: { min: 90, max: 8000 },
    ikiCvTimes100: { min: 45, max: 500 },
    planningPauses: { min: 2, max: 2048 },
    boundaryPauses: { min: 1, max: 2048 },
    peakCpsTimes10: { min: 1, max: 160 },
    revisionPermille: { min: 20, max: 1000 },
  },
  transcription: {
    medianIkiMs: { min: 45, max: 150 },
    ikiCvTimes100: { min: 0, max: 40 },
    planningPauses: { min: 0, max: 1 },
    boundaryPauses: { min: 0, max: 1 },
    peakCpsTimes10: { min: 60, max: 220 },
    revisionPermille: { min: 0, max: 40 },
  },
  automated: {
    medianIkiMs: { min: 0, max: 39 },
    ikiCvTimes100: { min: 0, max: 20 },
    planningPauses: { min: 0, max: 0 },
    boundaryPauses: { min: 0, max: 0 },
    peakCpsTimes10: { min: 200, max: 20000 },
    revisionPermille: { min: 0, max: 30 },
  },
};

export function contains(features: Features, bounds: FeatureBounds): boolean {
  return FEATURE_KEYS.every((key) => features[key] >= bounds[key].min && features[key] <= bounds[key].max);
}

export function regionsOverlap(left: FeatureBounds, right: FeatureBounds): boolean {
  return FEATURE_KEYS.every(
    (key) => left[key].min <= right[key].max && right[key].min <= left[key].max,
  );
}

export function matchLabel(features: Features, bulkInsertEvents: number): Label {
  if (contains(features, REGIONS.automated)) return "automated";
  if (contains(features, REGIONS.transcription)) return "transcription";
  if (bulkInsertEvents === 0 && contains(features, REGIONS.composition)) return "composition";
  return "indeterminate";
}

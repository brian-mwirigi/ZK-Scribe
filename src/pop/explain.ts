import { FEATURE_KEYS, type Features } from "./constants.ts";
import { matchLabel, REGIONS, type FeatureBounds, type Label } from "./regions.ts";

export type BoundCheck = {
  feature: string;
  value: number;
  min: number;
  max: number;
  inside: boolean;
};

export type Explanation = {
  label: Label;
  bulkInsertEvents: number;
  checks: Record<Exclude<Label, "indeterminate">, BoundCheck[]>;
  note: string;
};

export function explainFeatures(features: Features, bulkInsertEvents: number): Explanation {
  const label = matchLabel(features, bulkInsertEvents);
  return {
    label,
    bulkInsertEvents,
    checks: {
      composition: checksFor(features, REGIONS.composition),
      transcription: checksFor(features, REGIONS.transcription),
      automated: checksFor(features, REGIONS.automated),
    },
    note: noteFor(label, bulkInsertEvents),
  };
}

function checksFor(features: Features, bounds: FeatureBounds): BoundCheck[] {
  return FEATURE_KEYS.map((feature) => {
    const value = features[feature];
    const min = bounds[feature].min;
    const max = bounds[feature].max;
    return { feature, value, min, max, inside: value >= min && value <= max };
  });
}

function noteFor(label: Label, bulkInsertEvents: number): string {
  if (bulkInsertEvents > 0 && label !== "composition") {
    return "A bulk insert keeps this session out of the composition region.";
  }
  if (label === "composition") return "Every composition bound holds.";
  if (label === "transcription") return "The timing fits steady transcription.";
  if (label === "automated") return "The timing fits the automated region.";
  return "The features fall outside every named region.";
}

export const PAUSE_BINS = [
  { label: "0-199", min: 0, max: 199 },
  { label: "200-499", min: 200, max: 499 },
  { label: "500-999", min: 500, max: 999 },
  { label: "1000-1999", min: 1000, max: 1999 },
  { label: "2000-5000", min: 2000, max: 5000 },
  { label: "5001+", min: 5001, max: Number.POSITIVE_INFINITY },
] as const;

export type PauseBin = { label: string; count: number };

export function pauseHistogram(events: { t: number }[]): PauseBin[] {
  const counts = PAUSE_BINS.map((bin) => ({ label: bin.label, count: 0 }));
  for (let index = 1; index < events.length; index += 1) {
    const gap = events[index].t - events[index - 1].t;
    const bin = counts.findIndex((_, slot) => gap >= PAUSE_BINS[slot].min && gap <= PAUSE_BINS[slot].max);
    if (bin >= 0) counts[bin].count += 1;
  }
  return counts;
}

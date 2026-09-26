import type { SessionLog } from "./session.ts";

export type TimingProfile = {
  samples: number;
  p10: number | null;
  p50: number | null;
  p90: number | null;
};

export function localProfile(session: SessionLog): TimingProfile {
  const gaps = interKeyIntervals(session.events);
  if (gaps.length === 0) return { samples: 0, p10: null, p50: null, p90: null };
  gaps.sort((left, right) => left - right);
  return {
    samples: gaps.length,
    p10: percentile(gaps, 10),
    p50: percentile(gaps, 50),
    p90: percentile(gaps, 90),
  };
}

function interKeyIntervals(events: { t: number }[]): number[] {
  const gaps: number[] = [];
  for (let index = 1; index < events.length; index += 1) {
    gaps.push(events[index].t - events[index - 1].t);
  }
  return gaps;
}

function percentile(sorted: number[], p: number): number {
  const rank = (p / 100) * (sorted.length - 1);
  const low = Math.floor(rank);
  const high = Math.ceil(rank);
  if (low === high) return sorted[low];
  const weight = rank - low;
  return sorted[low] * (1 - weight) + sorted[high] * weight;
}

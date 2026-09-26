import { randomScalar } from "./group.ts";
import { proveInterval } from "./range.ts";
import { Transcript } from "./transcript.ts";

export type RangeBenchmark = {
  low: number;
  high: number;
  milliseconds: number;
  bits: number;
};

export function rangeBenchmark(): RangeBenchmark {
  const started = performance.now();
  const proof = proveInterval({
    value: 7n,
    blinding: randomScalar(),
    low: 0n,
    high: 15n,
    transcript: new Transcript("zk-scribe/benchmark"),
  });
  return {
    low: 0,
    high: 15,
    milliseconds: performance.now() - started,
    bits: proof.bits,
  };
}

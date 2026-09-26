import {
  G,
  H,
  ZERO,
  commit,
  hexToPoint,
  hexToScalar,
  modN,
  mul,
  pointToHex,
  randomScalar,
  scalarToHex,
  type Point,
} from "./group.ts";
import { Transcript } from "./transcript.ts";

export type BitProof = {
  commitment: string;
  a0: string;
  a1: string;
  c0: string;
  c1: string;
  z0: string;
  z1: string;
};

export type LinkProof = {
  a: string;
  c: string;
  z: string;
};

export type IntervalProof = {
  bits: number;
  low: BitProof[];
  high: BitProof[];
  lowLink: LinkProof;
  highLink: LinkProof;
};

export function bitsForSpan(span: bigint): number {
  if (span < 0n) throw new Error("Range span is negative.");
  let bits = 0;
  let capacity = 1n;
  while (capacity <= span) {
    bits += 1;
    capacity <<= 1n;
    if (bits > 20) throw new Error("Range is too wide for sigma-range-v1.");
  }
  return bits;
}

export function proveInterval(args: {
  value: bigint;
  blinding: bigint;
  low: bigint;
  high: bigint;
  transcript: Transcript;
}): IntervalProof {
  const { value, blinding, low, high, transcript } = args;
  if (value < low || value > high) {
    throw new Error(`Value ${value} is outside [${low}, ${high}].`);
  }
  const bits = bitsForSpan(high - low);
  const commitment = commit(value, blinding);
  const lowSide = proveSide({
    commitment: commitment.subtract(mul(G, low)),
    shifted: value - low,
    blinding,
    bits,
    side: "low",
    transcript,
  });
  const highSide = proveSide({
    commitment: mul(G, high).subtract(commitment),
    shifted: high - value,
    blinding: modN(-blinding),
    bits,
    side: "high",
    transcript,
  });
  return {
    bits,
    low: lowSide.bits,
    high: highSide.bits,
    lowLink: lowSide.link,
    highLink: highSide.link,
  };
}

export function verifyInterval(args: {
  commitment: Point;
  low: bigint;
  high: bigint;
  proof: IntervalProof;
  transcript: Transcript;
}): boolean {
  try {
    const { commitment, low, high, proof, transcript } = args;
    if (low > high) return false;
    const bits = bitsForSpan(high - low);
    if (proof.bits !== bits || proof.low.length !== bits || proof.high.length !== bits) return false;
    const lowCommitment = commitment.subtract(mul(G, low));
    const highCommitment = mul(G, high).subtract(commitment);
    if (!verifySide(lowCommitment, proof.low, proof.lowLink, bits, "low", transcript)) return false;
    if (!verifySide(highCommitment, proof.high, proof.highLink, bits, "high", transcript)) return false;
    return true;
  } catch {
    return false;
  }
}

function proveSide(args: {
  commitment: Point;
  shifted: bigint;
  blinding: bigint;
  bits: number;
  side: string;
  transcript: Transcript;
}): { bits: BitProof[]; link: LinkProof } {
  const { commitment, shifted, blinding, bits, side, transcript } = args;
  transcript.absorbUtf8("side", side);
  const bitProofs: BitProof[] = [];
  const bitCommitments: Point[] = [];
  const bitBlindings: bigint[] = [];
  for (let index = 0; index < bits; index += 1) {
    const bit = Number((shifted >> BigInt(index)) & 1n);
    const bitBlinding = randomScalar();
    const bitCommitment = commit(BigInt(bit), bitBlinding);
    bitProofs.push(proveBit(bitCommitment, bit, bitBlinding, transcript));
    bitCommitments.push(bitCommitment);
    bitBlindings.push(bitBlinding);
  }
  let weightedBlind = 0n;
  let place = 1n;
  for (let index = 0; index < bits; index += 1) {
    weightedBlind = modN(weightedBlind + place * bitBlindings[index]);
    place <<= 1n;
  }
  const difference = commitment.subtract(weightedCommitments(bitCommitments));
  const differenceBlinding = modN(blinding - weightedBlind);
  if (!mul(H, differenceBlinding).equals(difference)) {
    throw new Error("Range link does not match the bit decomposition.");
  }
  return {
    bits: bitProofs,
    link: proveLink(difference, differenceBlinding, transcript),
  };
}

function verifySide(
  commitment: Point,
  bitProofs: BitProof[],
  link: LinkProof,
  bits: number,
  side: string,
  transcript: Transcript,
): boolean {
  if (bitProofs.length !== bits) return false;
  transcript.absorbUtf8("side", side);
  const bitCommitments: Point[] = [];
  for (const proof of bitProofs) {
    const bitCommitment = hexToPoint(proof.commitment);
    if (!verifyBit(bitCommitment, proof, transcript)) return false;
    bitCommitments.push(bitCommitment);
  }
  const difference = commitment.subtract(weightedCommitments(bitCommitments));
  return verifyLink(difference, link, transcript);
}

function proveBit(commitment: Point, bit: number, blinding: bigint, transcript: Transcript): BitProof {
  const y0 = commitment;
  const y1 = commitment.subtract(G);
  const simulated = randomScalar();
  const simulatedResponse = randomScalar();
  const nonce = randomScalar();
  let a0: Point;
  let a1: Point;
  let c0: bigint;
  let c1: bigint;
  let z0: bigint;
  let z1: bigint;
  if (bit === 0) {
    c1 = simulated;
    z1 = simulatedResponse;
    a1 = mul(H, z1).subtract(mul(y1, c1));
    a0 = mul(H, nonce);
    absorbBit(transcript, commitment, a0, a1);
    const challenge = transcript.challenge();
    c0 = modN(challenge - c1);
    z0 = modN(nonce + c0 * blinding);
  } else if (bit === 1) {
    c0 = simulated;
    z0 = simulatedResponse;
    a0 = mul(H, z0).subtract(mul(y0, c0));
    a1 = mul(H, nonce);
    absorbBit(transcript, commitment, a0, a1);
    const challenge = transcript.challenge();
    c1 = modN(challenge - c0);
    z1 = modN(nonce + c1 * blinding);
  } else {
    throw new Error("Bit decomposition produced a non-bit.");
  }
  return {
    commitment: pointToHex(commitment),
    a0: pointToHex(a0),
    a1: pointToHex(a1),
    c0: scalarToHex(c0),
    c1: scalarToHex(c1),
    z0: scalarToHex(z0),
    z1: scalarToHex(z1),
  };
}

function verifyBit(commitment: Point, proof: BitProof, transcript: Transcript): boolean {
  const a0 = hexToPoint(proof.a0);
  const a1 = hexToPoint(proof.a1);
  absorbBit(transcript, commitment, a0, a1);
  const challenge = transcript.challenge();
  const c0 = hexToScalar(proof.c0);
  const c1 = hexToScalar(proof.c1);
  const z0 = hexToScalar(proof.z0);
  const z1 = hexToScalar(proof.z1);
  if (modN(c0 + c1) !== challenge) return false;
  const y0 = commitment;
  const y1 = commitment.subtract(G);
  const left0 = mul(H, z0);
  const right0 = a0.add(mul(y0, c0));
  const left1 = mul(H, z1);
  const right1 = a1.add(mul(y1, c1));
  return left0.equals(right0) && left1.equals(right1);
}

function proveLink(difference: Point, blinding: bigint, transcript: Transcript): LinkProof {
  const nonce = randomScalar();
  const announcement = mul(H, nonce);
  transcript.absorb("D", difference.toBytes(true));
  transcript.absorb("A", announcement.toBytes(true));
  const challenge = transcript.challenge();
  return {
    a: pointToHex(announcement),
    c: scalarToHex(challenge),
    z: scalarToHex(modN(nonce + challenge * blinding)),
  };
}

function verifyLink(difference: Point, proof: LinkProof, transcript: Transcript): boolean {
  const announcement = hexToPoint(proof.a);
  transcript.absorb("D", difference.toBytes(true));
  transcript.absorb("A", announcement.toBytes(true));
  const challenge = transcript.challenge();
  if (hexToScalar(proof.c) !== challenge) return false;
  const response = hexToScalar(proof.z);
  return mul(H, response).equals(announcement.add(mul(difference, challenge)));
}

function absorbBit(transcript: Transcript, commitment: Point, a0: Point, a1: Point): void {
  transcript.absorb("Ci", commitment.toBytes(true));
  transcript.absorb("A0", a0.toBytes(true));
  transcript.absorb("A1", a1.toBytes(true));
}

function weightedCommitments(commitments: Point[]): Point {
  let sum = ZERO;
  let place = 1n;
  for (const commitment of commitments) {
    sum = sum.add(mul(commitment, place));
    place <<= 1n;
  }
  return sum;
}

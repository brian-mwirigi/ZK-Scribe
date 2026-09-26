import { secp256k1, secp256k1_hasher } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE, randomBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { utf8 } from "../canon.ts";

export type Point = ReturnType<typeof secp256k1.Point.fromAffine>;

const Point = secp256k1.Point;
const ORDER = Point.Fn.ORDER;

export const G = Point.BASE;
export const ZERO = Point.ZERO;

export const H = secp256k1_hasher.hashToCurve(utf8("ZK-Scribe/pedersen-h/v1"), {
  DST: "ZK-Scribe-pedersen-v1",
});

export function modN(value: bigint): bigint {
  const reduced = value % ORDER;
  return reduced >= 0n ? reduced : reduced + ORDER;
}

export function randomScalar(): bigint {
  for (;;) {
    const scalar = bytesToNumberBE(randomBytes(32)) % ORDER;
    if (scalar !== 0n) return scalar;
  }
}

export function mul(point: Point, scalar: bigint): Point {
  const reduced = modN(scalar);
  if (reduced === 0n) return Point.ZERO;
  return point.multiply(reduced);
}

export function commit(message: bigint, blinding: bigint): Point {
  return mul(G, message).add(mul(H, blinding));
}

export function scalarToHex(scalar: bigint): string {
  return bytesToHex(numberToBytesBE(modN(scalar), 32));
}

export function hexToScalar(hex: string): bigint {
  const scalar = bytesToNumberBE(hexToBytes(hex));
  if (scalar < 0n || scalar >= ORDER) throw new Error("Scalar is outside the field.");
  return scalar;
}

export function pointToHex(point: Point): string {
  return bytesToHex(point.toBytes(true));
}

export function hexToPoint(hex: string): Point {
  return Point.fromBytes(hexToBytes(hex));
}

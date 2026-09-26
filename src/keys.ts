import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

ed.hashes.sha512 = sha512;

export type AgentKey = {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
};

export function generateAgentKey(): AgentKey {
  const { secretKey, publicKey } = ed.keygen();
  return { secretKey, publicKey };
}

export function publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
  return ed.getPublicKey(secretKey);
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed.sign(message, secretKey);
}

export function verifySignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export function encodeKey(key: Uint8Array): string {
  return bytesToHex(key);
}

export function decodeSecretKey(hex: string): Uint8Array {
  return decodeFixed(hex, 32, "Ed25519 seed");
}

export function decodePublicKey(hex: string): Uint8Array {
  return decodeFixed(hex, 32, "Ed25519 public key");
}

export function decodeSignature(hex: string): Uint8Array {
  return decodeFixed(hex, 64, "Ed25519 signature");
}

function decodeFixed(hex: string, length: number, label: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== length) throw new Error(`Expected a ${length}-byte ${label}.`);
  return bytes;
}

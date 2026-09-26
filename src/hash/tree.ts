import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { utf8 } from "../canon.ts";

export type TreeFile = {
  path: string;
  bytes: Uint8Array;
};

export function hashTree(files: TreeFile[]): string {
  const sorted = [...files].sort((left, right) => normalize(left.path).localeCompare(normalize(right.path)));
  let state = sha256(utf8("ZK-Scribe/tree/v1"));
  for (const file of sorted) {
    const pathBytes = utf8(normalize(file.path));
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, file.bytes.length);
    state = sha256(concatBytes(state, pathBytes, length, file.bytes));
  }
  return bytesToHex(state);
}

export function ignoredTreePath(relativePath: string): boolean {
  const normalized = normalize(relativePath);
  const parts = normalized.split("/");
  return (
    normalized === ".zk-scribe/private" ||
    normalized.startsWith(".zk-scribe/private/") ||
    parts.includes("node_modules") ||
    normalized.endsWith(".witness.json")
  );
}

function normalize(filePath: string): string {
  return filePath.replaceAll("\\", "/");
}

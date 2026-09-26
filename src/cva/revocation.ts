export function normalizeKey(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, "").replace(/\s+/g, "");
}

export function isRevoked(publicKey: string, revoked: readonly string[]): boolean {
  const needle = normalizeKey(publicKey);
  if (needle.length === 0) return false;
  return revoked.some((entry) => normalizeKey(entry) === needle);
}

export function parseRevocationList(value: unknown): string[] {
  if (!value || typeof value !== "object") throw new Error("Revocation list must be an object.");
  const keys = (value as { publicKeys?: unknown }).publicKeys;
  if (!Array.isArray(keys) || keys.some((key) => typeof key !== "string")) {
    throw new Error("Revocation list publicKeys must be strings.");
  }
  return keys;
}

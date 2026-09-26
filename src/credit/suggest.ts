import { getRole, type CreditRoleId } from "./taxonomy.ts";

const BY_EXTENSION: Record<string, CreditRoleId> = {
  ".md": "writing-original-draft",
  ".markdown": "writing-original-draft",
  ".tex": "writing-original-draft",
  ".txt": "writing-original-draft",
  ".py": "software",
  ".r": "software",
  ".js": "software",
  ".ts": "software",
  ".ipynb": "formal-analysis",
  ".csv": "data-curation",
  ".tsv": "data-curation",
  ".json": "data-curation",
  ".svg": "visualization",
  ".png": "visualization",
};

export function suggestRole(filePath: string): { role: CreditRoleId; name: string; reason: string } {
  const extension = extensionOf(filePath);
  const role = BY_EXTENSION[extension] ?? "writing-original-draft";
  const described = getRole(role);
  const reason = BY_EXTENSION[extension]
    ? `Extension ${extension} maps to ${described.name}.`
    : "No extension rule matched, so the default is original drafting.";
  return { role, name: described.name, reason };
}

function extensionOf(filePath: string): string {
  const base = filePath.replaceAll("\\", "/").split("/").pop() ?? "";
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot).toLowerCase();
}

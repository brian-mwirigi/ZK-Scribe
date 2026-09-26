import type { Attestation } from "../pop/attest.ts";
import { toSummary } from "./summary.ts";

export function toHtmlReport(attestation: Attestation): string {
  const summary = toSummary(attestation);
  const rows = Object.entries(summary)
    .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(String(value))}</td></tr>`)
    .join("\n");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZK-Scribe ${escapeHtml(summary.binding)}</title>
</head>
<body>
  <h1>${escapeHtml(summary.role)}</h1>
  <p>${escapeHtml(summary.binding)} / ${escapeHtml(summary.label)}</p>
  <table>
${rows}
  </table>
</body>
</html>
`;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

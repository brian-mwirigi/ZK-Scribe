import { canonicalHash } from "../canon.ts";
import type { Attestation } from "../pop/attest.ts";
import { VERSION } from "../version.ts";

export function toProvenanceManifest(attestation: Attestation) {
  return {
    version: "zk-scribe-manifest/0.1.0",
    claim_generator: `ZK-Scribe/${VERSION}`,
    profile: "zk-scribe.c2pa-shaped.v1",
    note: "Assertion labels follow the C2PA vocabulary. This JSON profile is not a JUMBF or COSE C2PA box.",
    assertions: [
      {
        label: "c2pa.actions",
        data: {
          actions: [{ action: "c2pa.created", softwareAgent: `ZK-Scribe/${VERSION}` }],
        },
      },
      { label: "c2pa.ai-disclosure", data: aiDisclosure(attestation) },
      {
        label: "zk-scribe.process-attestation",
        data: {
          statementHash: canonicalHash(attestation.statement),
          attestation,
        },
      },
      { label: "zk-scribe.credit", data: attestation.statement.role },
    ],
  };
}

export function toJats(attestation: Attestation): string {
  const statement = attestation.statement;
  const rows: Array<[string, string]> = [
    ["zk-scribe-version", statement.version],
    ["zk-scribe-role", statement.role.id],
    ["zk-scribe-binding", statement.role.binding],
    ["zk-scribe-label", statement.label],
    ["zk-scribe-content-hash", statement.contentHash],
    ["zk-scribe-swf-head", statement.swfHead],
    ["zk-scribe-statement-hash", canonicalHash(statement)],
    ["zk-scribe-agent", attestation.cva.agentPublicKey],
  ];
  const metas = rows
    .map(
      ([name, value]) =>
        `    <custom-meta>\n      <meta-name>${escapeXml(name)}</meta-name>\n      <meta-value>${escapeXml(value)}</meta-value>\n    </custom-meta>`,
    )
    .join("\n");
  return `<custom-meta-group>\n${metas}\n</custom-meta-group>\n`;
}

function aiDisclosure(attestation: Attestation) {
  const { label, role } = attestation.statement;
  if (role.binding === "signed-assertion") {
    return {
      status: "not-process-attested",
      used: "undisclosed-by-process",
      summary: "Signed contribution claim without process evidence.",
    };
  }
  if (label === "composition" && (role.binding === "process-proven" || role.binding === "typed-artifact")) {
    return {
      status: "human-process",
      used: "not-indicated-by-timing",
      summary:
        "Keystroke timing is inside the composition region. This does not show that the text is true, and it does not rule out earlier machine assistance.",
    };
  }
  if (label === "transcription") {
    return {
      status: "transcription-pattern",
      used: "not-determined",
      summary: "Timing fits steady transcription more closely than composition.",
    };
  }
  if (label === "automated") {
    return {
      status: "non-human-timing",
      used: "not-determined",
      summary: "Timing is outside the human composition region. That is not, by itself, an identification of a model.",
    };
  }
  return {
    status: "indeterminate",
    used: "not-determined",
    summary: "Process evidence does not support a composition claim.",
  };
}

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export type CreditRoleId =
  | "conceptualization"
  | "data-curation"
  | "formal-analysis"
  | "funding-acquisition"
  | "investigation"
  | "methodology"
  | "project-administration"
  | "resources"
  | "software"
  | "supervision"
  | "validation"
  | "visualization"
  | "writing-original-draft"
  | "writing-review-editing";

export type Feasibility = "high" | "moderate" | "unobserved";

export type CreditRole = {
  id: CreditRoleId;
  name: string;
  feasibility: Feasibility;
  observes: string;
};

export const CREDIT_ROLES: readonly CreditRole[] = [
  {
    id: "writing-original-draft",
    name: "Writing – original draft",
    feasibility: "high",
    observes: "Cognitive timing of the draft as it is typed and revised.",
  },
  {
    id: "writing-review-editing",
    name: "Writing – review & editing",
    feasibility: "high",
    observes: "Cognitive timing of later edits, together with the diff those edits produce.",
  },
  {
    id: "software",
    name: "Software",
    feasibility: "moderate",
    observes: "That a human typed the code. Execution and correctness are outside the proof.",
  },
  {
    id: "formal-analysis",
    name: "Formal analysis",
    feasibility: "moderate",
    observes: "That a human typed the proof or analysis script. Computed results are not re-run.",
  },
  {
    id: "data-curation",
    name: "Data curation",
    feasibility: "moderate",
    observes: "That a human typed metadata or curation scripts. Remote pipelines are not observed.",
  },
  {
    id: "visualization",
    name: "Visualization",
    feasibility: "moderate",
    observes: "That a human typed the figure code or caption. The figure's fidelity is not observed.",
  },
  {
    id: "conceptualization",
    name: "Conceptualization",
    feasibility: "unobserved",
    observes: "Nothing directly. Ideas formed in conversation or on a whiteboard leave no keystroke trace.",
  },
  {
    id: "methodology",
    name: "Methodology",
    feasibility: "unobserved",
    observes: "Only the later write-up of a method, not the design act itself.",
  },
  {
    id: "investigation",
    name: "Investigation",
    feasibility: "unobserved",
    observes: "Nothing. Bench work, fieldwork, and interviews happen off the keyboard.",
  },
  {
    id: "validation",
    name: "Validation",
    feasibility: "unobserved",
    observes: "Nothing. Replication is a scientific activity, not a typing pattern.",
  },
  {
    id: "supervision",
    name: "Supervision",
    feasibility: "unobserved",
    observes: "Nothing. Mentorship and review meetings are outside the manuscript session.",
  },
  {
    id: "project-administration",
    name: "Project administration",
    feasibility: "unobserved",
    observes: "Nothing. Coordination mail and logistics are outside the writing log.",
  },
  {
    id: "resources",
    name: "Resources",
    feasibility: "unobserved",
    observes: "Nothing. Materials, access, and study subjects are not digital writing events.",
  },
  {
    id: "funding-acquisition",
    name: "Funding acquisition",
    feasibility: "unobserved",
    observes: "Nothing. Financial support is not a property of the manuscript keystroke log.",
  },
];

const BY_ID = new Map(CREDIT_ROLES.map((role) => [role.id, role]));

export function getRole(id: string): CreditRole {
  const role = BY_ID.get(id as CreditRoleId);
  if (!role) throw new Error(`Unknown CRediT role "${id}". Run \`zk-scribe credit\` for the vocabulary.`);
  return role;
}

export function isCreditRoleId(id: string): id is CreditRoleId {
  return BY_ID.has(id as CreditRoleId);
}

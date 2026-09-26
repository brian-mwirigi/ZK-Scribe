export type KeyOp = "insert" | "delete" | "navigate" | "paste";

export type KeyEvent = {
  t: number;
  op: KeyOp;
  len: number;
  boundary?: boolean;
};

export type SessionLog = {
  sessionId: string;
  startedAt: string;
  events: KeyEvent[];
};

const OPS = new Set<KeyOp>(["insert", "delete", "navigate", "paste"]);

export function validateSession(session: SessionLog): void {
  if (!session || typeof session.sessionId !== "string" || session.sessionId.trim() === "") {
    throw new Error("Session is missing sessionId.");
  }
  if (typeof session.startedAt !== "string" || session.startedAt.trim() === "") {
    throw new Error("Session is missing startedAt.");
  }
  if (!Array.isArray(session.events)) throw new Error("Session events must be an array.");
  let previous = -1;
  for (const [index, event] of session.events.entries()) {
    if (!OPS.has(event.op)) throw new Error(`Event ${index} has an unknown op.`);
    if (!Number.isInteger(event.t) || event.t < 0) throw new Error(`Event ${index} has a bad timestamp.`);
    if (event.t < previous) throw new Error(`Event ${index} moves backwards in time.`);
    if (!Number.isInteger(event.len) || event.len < 1) throw new Error(`Event ${index} has a bad length.`);
    if (event.boundary !== undefined && typeof event.boundary !== "boolean") {
      throw new Error(`Event ${index} has a bad boundary flag.`);
    }
    previous = event.t;
  }
}

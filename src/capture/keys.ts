import type { KeyEvent } from "../pop/session.ts";

export type KeyInfo = {
  name?: string;
  sequence?: string;
  ctrl?: boolean;
  meta?: boolean;
};

export type CaptureStep =
  | { kind: "event"; event: KeyEvent; textDelta: string }
  | { kind: "finish" }
  | { kind: "abort" }
  | { kind: "ignore" };

export function eventFromKey(key: KeyInfo, t: number): CaptureStep {
  if (key.ctrl && key.name === "c") return { kind: "abort" };
  if (key.ctrl && key.name === "d") return { kind: "finish" };
  if (key.name === "backspace") {
    return { kind: "event", event: { t, op: "delete", len: 1 }, textDelta: "" };
  }
  if (key.name === "left" || key.name === "right" || key.name === "up" || key.name === "down") {
    return { kind: "event", event: { t, op: "navigate", len: 1 }, textDelta: "" };
  }
  const sequence = key.sequence ?? "";
  if (!sequence || key.ctrl || key.meta) return { kind: "ignore" };
  const boundary = /[.!?;:\n]/.test(sequence);
  const paste = sequence.length >= 15;
  return {
    kind: "event",
    event: {
      t,
      op: paste ? "paste" : "insert",
      len: sequence.length,
      boundary,
    },
    textDelta: sequence,
  };
}

export function applyTextDelta(buffer: string, event: KeyEvent, textDelta: string): string {
  if (event.op === "delete") return buffer.slice(0, -event.len);
  if (event.op === "insert" || event.op === "paste") return buffer + textDelta;
  return buffer;
}

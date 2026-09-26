import type { KeyEvent, SessionLog } from "./session.ts";

type Clock = { t: number; events: KeyEvent[] };

export function synthesizeSession(kind: "composition" | "transcription" | "automated" | "paste"): SessionLog {
  if (kind === "composition") return composition();
  if (kind === "transcription") return transcription();
  if (kind === "automated") return automated();
  return paste();
}

function composition(): SessionLog {
  const clock = start();
  const gaps = [80, 420, 110, 680, 150, 510, 95, 360];
  const pauses = [1400, 1800, 2200];
  for (let burst = 0; burst < 4; burst += 1) {
    for (let index = 0; index < gaps.length; index += 1) {
      if (clock.events.length > 0) advance(clock, gaps[index]);
      push(clock, "insert", 1, index === gaps.length - 1);
    }
    if (burst < pauses.length) {
      advance(clock, pauses[burst]);
      push(clock, "delete", 1, false);
      advance(clock, 240);
      push(clock, "insert", 1, false);
    }
  }
  return finish(clock, "example-composition");
}

function transcription(): SessionLog {
  const clock = start();
  for (let index = 0; index < 80; index += 1) {
    advance(clock, index === 0 ? 0 : 98 + (index % 5));
    push(clock, "insert", 1, false);
  }
  return finish(clock, "example-transcription");
}

function automated(): SessionLog {
  const clock = start();
  for (let index = 0; index < 160; index += 1) {
    advance(clock, index === 0 ? 0 : 15);
    push(clock, "insert", 1, false);
  }
  return finish(clock, "example-automated");
}

function paste(): SessionLog {
  const clock = start();
  push(clock, "paste", 480, false);
  return finish(clock, "example-paste");
}

function start(): Clock {
  return { t: 0, events: [] };
}

function advance(clock: Clock, ms: number): void {
  clock.t += ms;
}

function push(clock: Clock, op: KeyEvent["op"], len: number, boundary: boolean): void {
  clock.events.push({ t: clock.t, op, len, boundary });
}

function finish(clock: Clock, sessionId: string): SessionLog {
  return {
    sessionId,
    startedAt: "2026-09-26T12:00:00.000Z",
    events: clock.events,
  };
}

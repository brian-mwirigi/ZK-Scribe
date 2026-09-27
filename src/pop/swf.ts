import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { utf8 } from "../canon.ts";
import type { KeyEvent, SessionLog } from "./session.ts";

export function sequentialWorkHead(session: SessionLog, contentHash: string, domain?: string): string {
  const label = domain
    ? `ZK-Scribe/swf/v1|${session.sessionId}|${contentHash}|${domain}`
    : `ZK-Scribe/swf/v1|${session.sessionId}|${contentHash}`;
  let state = sha256(utf8(label));
  session.events.forEach((event, index) => {
    state = sha256(concatBytes(state, eventDigest(index, event)));
  });
  return bytesToHex(state);
}

function eventDigest(index: number, event: KeyEvent): Uint8Array {
  const boundary = event.boundary ? 1 : 0;
  return sha256(utf8(`${index}|${event.t}|${event.op}|${event.len}|${boundary}`));
}

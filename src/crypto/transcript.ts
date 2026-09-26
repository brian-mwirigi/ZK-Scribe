import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToNumberBE, concatBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { utf8 } from "../canon.ts";
import { modN } from "./group.ts";

export class Transcript {
  private state: Uint8Array;

  constructor(label: string) {
    this.state = sha256(utf8(`ZK-Scribe/transcript/v1:${label}`));
  }

  absorb(label: string, data: Uint8Array): void {
    const length = numberToBytesBE(data.length, 4);
    this.state = sha256(concatBytes(this.state, utf8(`|${label}|`), length, data));
  }

  absorbUtf8(label: string, value: string): void {
    this.absorb(label, utf8(value));
  }

  challenge(): bigint {
    const digest = sha256(concatBytes(this.state, utf8("|challenge")));
    this.state = sha256(concatBytes(this.state, digest));
    return modN(bytesToNumberBE(digest));
  }
}

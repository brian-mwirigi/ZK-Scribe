import { utf8 } from "../canon.ts";
import {
  decodePublicKey,
  decodeSignature,
  encodeKey,
  publicKeyFromSecret,
  sign,
  verifySignature,
} from "../keys.ts";

export type AuthorEndorsement = {
  publicKey: string;
  signature: string;
};

export function endorseStatement(statementHash: string, secretKey: Uint8Array): AuthorEndorsement {
  return {
    publicKey: encodeKey(publicKeyFromSecret(secretKey)),
    signature: encodeKey(sign(utf8(authorMessage(statementHash)), secretKey)),
  };
}

export function authorEndorsementValid(statementHash: string, endorsement: AuthorEndorsement): boolean {
  try {
    return verifySignature(
      decodeSignature(endorsement.signature),
      utf8(authorMessage(statementHash)),
      decodePublicKey(endorsement.publicKey),
    );
  } catch {
    return false;
  }
}

function authorMessage(statementHash: string): string {
  return `ZK-Scribe/author/v1:${statementHash}`;
}

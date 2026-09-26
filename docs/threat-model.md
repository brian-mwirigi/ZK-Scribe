# Threat model

ZK-Scribe is for an author who wants a publisher to check a human writing process without receiving a keystroke log. The author, or anyone who holds the agent seed, is able to choose the witness. The proofs show that the hidden features satisfy the public statement. They do not show that the features came from a live keyboard.

## Publisher checks that hold in this version

- The attestation was signed by the trusted agent key.
- The signed policy is the policy the publisher expected, and that policy allows the action.
- For a process binding, each committed feature lies in the composition region.
- The role binding matches the feasibility of that CRediT role. Writing roles are `process-proven`. Typed artifacts are `typed-artifact`. Offline roles are `signed-assertion` only.
- The statement, including the manuscript hash, execution context, and hash-chain head, is covered by the signature.
- The published file does not contain the session events or the commitment openings. `audit` is the local check that those openings match the log.

## Publisher checks that do not hold yet

- The features were extracted from the hash-chained events, rather than chosen because they fall in the region.
- The hash chain was computed slowly, in step with the timestamps, rather than synthesized in one pass.
- The agent binary that collected the events is the binary the author authorized. The signature shows that the key allowed the action. It does not show that the process which used the key left the events untouched.
- The manuscript hash is the text the session produced. The agent signs them together. A dishonest agent can pair any file hash with any log.
- Public counts such as duration and bulk-insert totals match the log. `audit` checks that locally. The range proofs cover the hidden timing features, not those public counters.
- Offline work happened. A signed assertion is an accountable claim. It is not evidence of bench work, funding, supervision, or the origin of an idea.
- The scientific content is true. Composition evidence is about how the characters were entered.

## People this is meant to constrain

Someone who does not hold the agent key cannot forge a passing attestation for that key, move a proof onto a different manuscript, or swap a signed assertion into a process-proven writing role without breaking the signature or the range proofs.

A gift-authorship claim has no process binding when that person's key never signed a composition proof for the manuscript. The absence is meaningful only for the roles the agent can see, and only when the real authors actually ran the agent.

## People this does not yet constrain

The holder of the seed can build a session whose statistics sit in the composition box, sign it, and pass `verify`. Closing that gap requires a capture path the author cannot cheaply rewrite, plus a delay function on the event chain, plus a circuit that ties the features to that chain.

## Privacy

Raw timing can identify a person and can expose motor or neurological traits. The published attestation is designed so a verifier checks ranges instead of receiving the timing vector. The witness file undoes that. It is gitignored, the default policy refuses to export it, and `export` has no path that prints it.

The terminal recorder echoes characters for the person typing and writes only operation, length, time, and boundary. That is the capture rule editor integrations should keep.

## What a failed check means

`verify` exits non-zero when the bundle is not a valid claim of the kind the flag asked for. A transcription pattern, a bulk paste, or a short session produces an `unsupported` binding. That is a refusal to certify. It is not a finding that the author used a model, and it should not be treated as one.

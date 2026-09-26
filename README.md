# ZK-Scribe

ZK-Scribe is a local agent that turns a writing session into a privacy-preserving authorship attestation. It commits to keystroke timing, proves those features sit inside a human composition region, and binds the result to a [CRediT](https://credit.niso.org/) role and a manuscript hash.

Publishers receive a signed attestation. They do not receive the keystroke log, the manuscript plaintext, or the commitment openings.

## What a valid proof establishes

For `writing-original-draft` and `writing-review-editing`, a `process-proven` attestation means:

- The authorized agent signed this statement under the pinned consent policy.
- The hidden timing features open a Pedersen commitment on secp256k1.
- A sigma-protocol range proof shows each feature lies in the composition region.
- The statement is bound to a manuscript sha256 and to a hash chain over the session.

For `software`, `formal-analysis`, `data-curation`, and `visualization`, the same timing proof is a `typed-artifact` binding. It says a human typed the artifact. It does not say the code runs, the statistics are correct, or the figure is faithful.

For every other CRediT role, ZK-Scribe will only record a `signed-assertion`. That is an author signature on a sentence, explicitly marked as unobserved.

## What this version leaves open

This repository is the first slice of that system. The proof system identifiers in every statement say so:

| Piece | This version | Production target |
| --- | --- | --- |
| Commitments | Pedersen on secp256k1 | same role |
| Range proofs | Bit decomposition and OR-proofs (`sigma-bit-or-v1`) | Bulletproofs, then a Groth16 circuit |
| Process order | Hash chain (`hash-chain-v1`) | A sequential work / delay function, so a log cannot be synthesized after the fact |
| Agent authorization | Ed25519 signature over agent, action, policy, and context (`ed25519-cva-v1`) | A zero-knowledge authorization relation |
| Feature correctness | Local audit against the witness file | A circuit that recomputes the features from the chained events |

A person who controls the agent key can still invent a session log whose features sit in the composition region. The hash chain binds order. It does not yet bind the log to wall-clock time. Hiding the features from the publisher is implemented. Proving the agent computed them honestly is the next proof.

The composition region is a conservative box over pause bands, revision, and speed. It is not a trained biometric model, and it is not a claim about the accuracy figures in the research literature. Sessions that look like steady transcription, metronomic input, or a bulk paste do not receive a composition binding.

Failure to prove composition is not an accusation of misconduct. It means this log did not meet the bar for a positive authorship claim.

## Quick start

Requires Node.js 22 or newer.

```sh
npm install -g https://github.com/brian-mwirigi/ZK-Scribe/archive/main.tar.gz
cd /path/to/manuscript
zk-scribe init
zk-scribe status
```

`init` is the opt-in. It writes the agent key, starts watching the manuscript directory, and installs a git pre-commit hook. The next commits attest the observed session and leave `attestation.json` plus a ledger under `.zk-scribe/ledger/`. The event log and the commitment openings stay in `.zk-scribe/private/`.

`status` is the first thing to read after a few commits. A line such as `3 sessions attested, ledger building` means the hook is writing the ledger. The next line says how many of those are `process-proven` and how many were refused. A refusal is not a process proof.

A file save is one edit of the length that actually changed. ZK-Scribe does not split that save into fake keystrokes. Composition still requires the timing bounds, so a bulk save is refused. A session captured with `record`, or any log that already meets the bounds, is what the hook certifies.

From a checkout of this repository, the same commands are available with `npm install` and `npm run zk-scribe --`.

```bash
npm install
npm test
npm run zk-scribe -- init
npm run zk-scribe -- example --kind composition --out examples/composition.json
npm run zk-scribe -- attest --session examples/composition.json --file examples/manuscript.md --role writing-original-draft
npm run zk-scribe -- verify attestation.json --require process-proven
npm run zk-scribe -- export attestation.json --format c2pa
npm run zk-scribe -- export attestation.json --format jats
```

`init` writes:

- `.zk-scribe/private/agent.seed` — stays on this machine and is gitignored
- `.zk-scribe/agent.public.json` — the publisher's trust anchor
- `.zk-scribe/policy.json` — the consent policy the signature commits to
- `.zk-scribe/config.json` — the default CRediT role used when `attest` omits `--role`

`attest` also writes `attestation.witness.json`. That file opens the commitments. Keep it local. The default policy denies exporting it.

`record` times an interactive terminal session. Typed characters are echoed and then discarded; the saved log stores operation, length, timestamp, and a boundary flag. Ctrl+D saves the log. Ctrl+C discards it. Editor hooks for Overleaf and local markdown come after this log format.

## Commands

`status` reads the ledger. `init` installs the commit hook. `explain`, `doctor`, `hash`, `suggest`, `summary`, `histogram`, `ledger`, `diffstat`, `policy`, `grant`, `govern`, `journal`, `stats`, `profile`, `id`, and `benchmark` sit beside `attest` and `verify`. Running `zk-scribe` with no arguments prints the full list.

`stats` and `profile` read a local session and print counts or pause percentiles. They do not write an attestation. `id` prints a bundle id from the statement hash and the agent key. `benchmark` times one small range proof. `verify` refuses a key listed in `.zk-scribe/revoked.json` when that file exists. `grant` lets an author key scope the agent to one manuscript and a list of actions. When `.zk-scribe/grant.json` is present, `attest` and `export` refuse anything outside that grant, and the attestation signature covers the grant hash. `govern` records the decision in `.zk-scribe/private/journal.jsonl`. `journal` checks that signed chain.

## Roles

`npm run zk-scribe -- credit` prints the fourteen CRediT roles and what the agent can actually see. The feasibility notes live in [docs/credit.md](docs/credit.md).

## Verify in CI

`verify` exits 0 only when the signature, the pinned policy, the trusted agent key, and the binding all agree. `--require process-proven` is the check for a writing role. `--require process` also accepts a typed-artifact binding. A signed assertion fails both of those flags. See [docs/integrations.md](docs/integrations.md) for Manubot and Overleaf.

## Layout

```
src/crypto     Pedersen commitments and sigma range proofs
src/pop        Session logs, features, hash chain, attest, and verify
src/cva        Consent policy and the agent authorization payload
src/credit     CRediT vocabulary
src/manifest   C2PA-shaped JSON and a JATS custom-meta block
src/capture    Terminal key classification
```

Further reading: [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [integrations](docs/integrations.md).

## License

This repository is the open trust core, under the [Apache License 2.0](LICENSE).

The core is the local agent and the proof check: keystroke-timing capture, proof generation, manuscript and Git binding, the on-machine consent policy, and `verify`. A researcher can read the code that handles timing on their machine. Anyone can check an attestation without a ZK-Scribe server.

The hosted institutional verification service, publisher-workflow connectors, and compliance dashboards are a separate convenience product. They sit outside this repository.

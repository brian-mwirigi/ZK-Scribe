# Integrations

The agent has to live where the manuscript is drafted. The two paths that matter are Overleaf's Git bridge and a Git-native pipeline such as Manubot.

## Overleaf

Overleaf does not offer a general public API for reading and writing project files. Browser extensions that hook the editor DOM break when the interface changes. ZK-Scribe does not use that path.

Overleaf projects can be a real Git remote. A local agent can commit, pull, and push with a normal Git client, and the history carries timestamps, diffs, and author fields. The attestation's execution context records `overleaf-git` when a remote URL contains `overleaf`. The hash-chain head and the ZK-Scribe attestation travel with the repository. They are not stuffed into LaTeX comments that a compiler will drop.

That Git remote is not on the free tier. It is available to paid Overleaf Cloud plans and to self-hosted Overleaf Server Pro 4.0 and newer. Free projects are limited to one collaborator and have no Git remote. GitHub Sync is a separate feature: Overleaf mirrors a project to a GitHub repository from its own UI. It is not a substitute for cloning the project as a Git remote.

A practical deployment is a local process:

1. `record`, or a later editor hook, writes the timing log.
2. `attest` hashes the manuscript, binds the proof to the current revision, and writes the attestation.
3. The author pushes through the Overleaf Git remote.
4. A GitHub Action runs `verify --require process-proven` for projects that also use GitHub Sync.

The sync job should fail the build when the attestation is missing or invalid. That is an opt-in gate for the repository, not a detector pointed at unrelated authors.

## Manubot

Manubot already stores the manuscript in Git and compiles it with GitHub Actions through Pandoc to HTML, PDF, and JATS. That matches the agent.

1. Install with `npm install -g github:brian-mwirigi/ZK-Scribe`. Node.js 22 or newer.
2. In the manuscript repository, run `zk-scribe init`. That watches `content/` and installs a pre-commit hook.
3. Keep writing and committing. The hook attests the observed session. `zk-scribe status` shows the ledger.
4. CI runs the verifier.
5. `export --format jats` supplies a `custom-meta-group` for the JATS header. The full attestation file remains the signature bundle.

`record` is still there for a terminal session whose timing can meet the composition bounds. The hook uses that local session when it exists. Otherwise it attests the commit's text change as one edit, and a bulk change is refused.

Copy [integrations/manubot/verify-attestation.yml](../integrations/manubot/verify-attestation.yml) into the manuscript repository once `attestation.json`, `.zk-scribe/agent.public.json`, and `.zk-scribe/policy.json` are committed there. `init` stages those public files on the next manuscript commit. Do not commit `.zk-scribe/private/` or `*.witness.json`.

## Disclosure

COPE's position is that a model cannot be an author, because authorship requires accountability. The Vancouver Standard being drafted by COPE, WCRIF, and STM is a reporting standard for AI disclosure, aimed at completion around the end of 2026 and early 2027. Disclosure and attestation answer different questions. Disclosure says which tools were used. Attestation says which human process produced a given artifact.

ZK-Scribe's `c2pa.ai-disclosure` assertion is a process status, not a self-report form. A composition binding supports a human-process status for the covered file. It does not claim the ideas had no machine assistance before they were typed, and a failed binding is not a determination that a model wrote the paper.

# Integrations

The agent has to live where the manuscript is drafted. VS Code records local edits. Overleaf records the source editor through a browser extension and a local bridge, then uses the Git hook. Manubot is the Git-native pipeline.

## Overleaf

Overleaf does not offer a general public API for reading keystrokes. The extension listens to the source editor (`.cm-content`) and posts each change as a removal count, an inserted length, and a boundary flag. The manuscript text stays in Overleaf. `zk-scribe overleaf` binds `127.0.0.1` only, checks a token, and writes `.zk-scribe/private/session.json`.

The extension has to be loaded unpacked, or installed later from a store. It will miss edits if Overleaf stops using that editor node. The visual editor is not captured. `zk-scribe record` is still there for a terminal session.

Overleaf projects can be a real Git remote. A local agent can commit, pull, and push with a normal Git client. The attestation's execution context records `overleaf-git` when a remote URL contains `overleaf`. The hash-chain head and the attestation travel with the repository. They are not stuffed into LaTeX comments that a compiler will drop.

That Git remote is not on the free tier. It is available to paid Overleaf Cloud plans and to self-hosted Overleaf Server Pro 4.0 and newer. Free projects are limited to one collaborator and have no Git remote. GitHub Sync is a separate feature: Overleaf mirrors a project to a GitHub repository from its own UI. It is not a substitute for cloning the project as a Git remote.

A paragraph that arrives only through Git, with no captured session, is one edit. A bulk change is refused. Once a terminal, VS Code, or Overleaf session is on disk, the hook does not append that Git sync onto it.

1. Install with `npm install -g zk-scribe`. Node.js 22 or newer.
2. Clone the Overleaf Git remote and run `zk-scribe init`.
3. Run `zk-scribe overleaf`. Load [editors/overleaf](../editors/overleaf) as an unpacked extension and paste the port and token into its options.
4. Write in the Overleaf source editor.
5. Commit from the clone. The hook attests the captured session and stages `attestation.json`.
6. Push through the Overleaf Git remote.
7. A GitHub Action runs `verify --require process-proven` for projects that also use GitHub Sync.

The sync job should fail the build when the attestation is missing or invalid. That is an opt-in gate for the repository, not a detector pointed at unrelated authors.

## VS Code

Local Markdown, TeX, and text files can be timed inside the editor. The extension listens to `vscode.workspace.onDidChangeTextDocument` and writes `op`, `t`, and `len` to `.zk-scribe/private/session.json`. The characters in `contentChanges` are not stored.

1. Run `zk-scribe init` in the manuscript folder.
2. Install [editors/vscode](../editors/vscode) with **Developer: Install Extension from Location…**.
3. Type in the manuscript. Each change is one edit of the length the editor reported.
4. Commit. The hook attests that session. The extension updates the watcher's file snapshot, so the save is not recorded a second time as a bulk insert.

A paste of 15 characters or more stays one paste. The composition check refuses it.

## Manubot

Manubot already stores the manuscript in Git and compiles it with GitHub Actions through Pandoc to HTML, PDF, and JATS. That matches the agent.

1. Install with `npm install -g zk-scribe`. Node.js 22 or newer.
2. In the manuscript repository, run `zk-scribe init`. That watches `content/` and installs a pre-commit hook.
3. Keep writing and committing. The hook attests the observed session. `zk-scribe status` shows the ledger.
4. CI runs the verifier.
5. `export --format jats` supplies a `custom-meta-group` for the JATS header. The full attestation file remains the signature bundle.

`record` is still there for a terminal session whose timing can meet the composition bounds. The hook uses that local session when it exists. Otherwise it attests the commit's text change as one edit, and a bulk change is refused.

Copy [integrations/manubot/verify-attestation.yml](../integrations/manubot/verify-attestation.yml) into the manuscript repository once `attestation.json`, `.zk-scribe/agent.public.json`, and `.zk-scribe/policy.json` are committed there. `init` stages those public files on the next manuscript commit. Do not commit `.zk-scribe/private/` or `*.witness.json`.

## Disclosure

COPE's position is that a model cannot be an author, because authorship requires accountability. The Vancouver Standard being drafted by COPE, WCRIF, and STM is a reporting standard for AI disclosure, aimed at completion around the end of 2026 and early 2027. Disclosure and attestation answer different questions. Disclosure says which tools were used. Attestation says which human process produced a given artifact.

ZK-Scribe's `c2pa.ai-disclosure` assertion is a process status, not a self-report form. A composition binding supports a human-process status for the covered file. It does not claim the ideas had no machine assistance before they were typed, and a failed binding is not a determination that a model wrote the paper.

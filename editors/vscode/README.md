# ZK-Scribe for VS Code

Records each change in a Markdown, TeX, or text manuscript as an operation, a time, and a length. The characters stay in the editor. The log is `.zk-scribe/private/session.json`.

Run `zk-scribe init` in the manuscript folder first. Then install this folder with **Developer: Install Extension from Location…** and choose `editors/vscode`. Reopen the folder if the status bar does not show ZK-Scribe.

A typed character is one insert. A paste is one insert of that length. The commit hook already attests this session. A length of 15 or more is refused for a composition proof.

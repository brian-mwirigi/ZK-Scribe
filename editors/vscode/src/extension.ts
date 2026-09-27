import fs from "node:fs";
import path from "node:path";
import * as vscode from "vscode";
import { recordEditorChange } from "../../../src/capture/watch.ts";

let capturing = false;

export function activate(context: vscode.ExtensionContext): void {
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.name = "ZK-Scribe";
  status.text = "ZK-Scribe";
  status.tooltip = "Edit timing stays in .zk-scribe/private/session.json. The text is not stored.";
  context.subscriptions.push(status);

  const arm = () => {
    if (capturing || !workspaceReady()) return;
    capturing = true;
    status.show();
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(onChange));
  };

  arm();
  const watcher = vscode.workspace.createFileSystemWatcher("**/.zk-scribe/config.json");
  context.subscriptions.push(watcher, watcher.onDidCreate(() => arm()));
}

export function deactivate(): void {
  capturing = false;
}

function onChange(event: vscode.TextDocumentChangeEvent): void {
  const document = event.document;
  if (document.uri.scheme !== "file" || event.contentChanges.length === 0) return;
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!folder || !fs.existsSync(path.join(folder.uri.fsPath, ".zk-scribe", "config.json"))) return;
  const relative = path.relative(folder.uri.fsPath, document.uri.fsPath);
  recordEditorChange(
    folder.uri.fsPath,
    relative,
    event.contentChanges.map((change) => ({
      removed: change.rangeLength,
      inserted: change.text,
    })),
    document.getText(),
  );
}

function workspaceReady(): boolean {
  return (vscode.workspace.workspaceFolders ?? []).some((folder) =>
    fs.existsSync(path.join(folder.uri.fsPath, ".zk-scribe", "config.json")),
  );
}

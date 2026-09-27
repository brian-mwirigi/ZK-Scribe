"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// editors/vscode/src/extension.ts
var extension_exports = {};
__export(extension_exports, {
  activate: () => activate,
  deactivate: () => deactivate
});
module.exports = __toCommonJS(extension_exports);
var import_node_fs2 = __toESM(require("node:fs"));
var import_node_path2 = __toESM(require("node:path"));
var vscode = __toESM(require("vscode"));

// src/capture/watch.ts
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);

// src/pop/constants.ts
var BULK_INSERT_CHARS = 15;

// src/capture/document.ts
function eventsFromTextChange(change, t) {
  const events = [];
  if (change.removed > 0) events.push({ t, op: "delete", len: change.removed });
  const inserted = change.inserted;
  if (inserted.length > 0) {
    const boundary = /[\s.!?;:\n]$/.test(inserted);
    events.push({
      t,
      op: inserted.length >= BULK_INSERT_CHARS ? "paste" : "insert",
      len: inserted.length,
      ...boundary ? { boundary: true } : {}
    });
  }
  return events;
}

// src/capture/watch.ts
var TEXT = /* @__PURE__ */ new Set([".md", ".markdown", ".tex", ".txt"]);
var MAX_CHARS = 2e6;
function isManuscriptRelative(dir, relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  if (!normalized || normalized.startsWith(".zk-scribe/") || normalized.split("/").some((part) => part.startsWith("."))) {
    return false;
  }
  const base = normalized.slice(normalized.lastIndexOf("/") + 1);
  if (!isManuscriptName(base)) return false;
  const hasContent = import_node_fs.default.existsSync(import_node_path.default.join(dir, "content"));
  if (hasContent && !normalized.startsWith("content/")) return false;
  return true;
}
function sessionPath(dir) {
  return import_node_path.default.join(dir, ".zk-scribe", "private", "session.json");
}
function readSession(dir) {
  const file = sessionPath(dir);
  if (!import_node_fs.default.existsSync(file)) return null;
  const session = JSON.parse(import_node_fs.default.readFileSync(file, "utf8"));
  if (!Array.isArray(session.events) || session.events.length === 0) return null;
  return session;
}
function recordEditorChange(dir, relativePath, changes, text, now = Date.now()) {
  const relative = relativePath.replaceAll("\\", "/");
  if (!isManuscriptRelative(dir, relative) || text.length > MAX_CHARS) return 0;
  const state = readState(dir);
  state.files[relative] = text;
  writeState(dir, state);
  const current = readSession(dir);
  const started = current ? Date.parse(current.startedAt) : now;
  const origin = Number.isFinite(started) ? started : now;
  let t = Math.max(0, now - origin);
  if (current && current.events.length > 0) t = Math.max(t, current.events[current.events.length - 1].t);
  const events = changes.flatMap((change) => eventsFromTextChange(change, t));
  if (events.length === 0) return 0;
  const session = current ?? {
    sessionId: `editor-${now.toString(16)}`,
    startedAt: new Date(origin).toISOString(),
    events: []
  };
  session.events.push(...events);
  writeSession(dir, session);
  return events.length;
}
function isManuscriptName(name) {
  if (name.toLowerCase() === "readme.md") return false;
  return TEXT.has(import_node_path.default.extname(name).toLowerCase());
}
function statePath(dir) {
  return import_node_path.default.join(dir, ".zk-scribe", "private", "watch-state.json");
}
function readState(dir) {
  const file = statePath(dir);
  if (!import_node_fs.default.existsSync(file)) return { files: {} };
  const parsed = JSON.parse(import_node_fs.default.readFileSync(file, "utf8"));
  return parsed && parsed.files ? parsed : { files: {} };
}
function writeState(dir, state) {
  const file = statePath(dir);
  import_node_fs.default.mkdirSync(import_node_path.default.dirname(file), { recursive: true });
  import_node_fs.default.writeFileSync(file, `${JSON.stringify(state)}
`);
}
function writeSession(dir, session) {
  const file = sessionPath(dir);
  import_node_fs.default.mkdirSync(import_node_path.default.dirname(file), { recursive: true });
  import_node_fs.default.writeFileSync(file, `${JSON.stringify(session, null, 2)}
`);
}

// editors/vscode/src/extension.ts
var capturing = false;
function activate(context) {
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
function deactivate() {
  capturing = false;
}
function onChange(event) {
  const document = event.document;
  if (document.uri.scheme !== "file" || event.contentChanges.length === 0) return;
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!folder || !import_node_fs2.default.existsSync(import_node_path2.default.join(folder.uri.fsPath, ".zk-scribe", "config.json"))) return;
  const relative = import_node_path2.default.relative(folder.uri.fsPath, document.uri.fsPath);
  recordEditorChange(
    folder.uri.fsPath,
    relative,
    event.contentChanges.map((change) => ({
      removed: change.rangeLength,
      inserted: change.text
    })),
    document.getText()
  );
}
function workspaceReady() {
  return (vscode.workspace.workspaceFolders ?? []).some(
    (folder) => import_node_fs2.default.existsSync(import_node_path2.default.join(folder.uri.fsPath, ".zk-scribe", "config.json"))
  );
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  activate,
  deactivate
});

import { execFileSync } from "node:child_process";
import path from "node:path";

export type ExecutionContext = {
  environment: "git" | "overleaf-git" | "local";
  revision: string;
  subject: string;
};

export function detectContext(cwd: string, subject: string): ExecutionContext {
  const inside = git(["rev-parse", "--is-inside-work-tree"], cwd) === "true";
  if (!inside) return { environment: "local", revision: "uncommitted", subject };
  const revision = git(["rev-parse", "HEAD"], cwd) ?? "uncommitted";
  const remotes = git(["remote", "-v"], cwd) ?? "";
  const environment = /overleaf/i.test(remotes) ? "overleaf-git" : "git";
  return { environment, revision, subject: path.relative(cwd, subject) || subject };
}

function git(args: string[], cwd: string): string | undefined {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return undefined;
  }
}

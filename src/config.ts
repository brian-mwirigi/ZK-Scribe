export type ProjectEnvironment = "git" | "overleaf-git" | "local";

export type ProjectConfig = {
  version: "zk-scribe-config/0.1.0";
  defaultRole: string;
  environment?: ProjectEnvironment;
};

export function defaultConfig(): ProjectConfig {
  return {
    version: "zk-scribe-config/0.1.0",
    defaultRole: "writing-original-draft",
  };
}

export function parseConfig(value: unknown): ProjectConfig {
  if (!value || typeof value !== "object") throw new Error("Config must be an object.");
  const record = value as Record<string, unknown>;
  if (record.version !== "zk-scribe-config/0.1.0") throw new Error("Unsupported config version.");
  if (typeof record.defaultRole !== "string" || record.defaultRole.trim() === "") {
    throw new Error("Config defaultRole is missing.");
  }
  const environment = record.environment;
  if (
    environment !== undefined &&
    environment !== "git" &&
    environment !== "overleaf-git" &&
    environment !== "local"
  ) {
    throw new Error("Config environment is invalid.");
  }
  return {
    version: "zk-scribe-config/0.1.0",
    defaultRole: record.defaultRole,
    ...(typeof environment === "string" ? { environment } : {}),
  };
}

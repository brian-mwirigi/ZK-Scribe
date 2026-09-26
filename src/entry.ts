// Re-enter this process. A global install runs plain JavaScript. The
// repository checkout runs the TypeScript source with the strip-types flag.
export function cliArgs(): string[] {
  const script = process.argv[1] ?? "";
  if (script.endsWith(".ts")) return ["--experimental-strip-types", script];
  return [script];
}

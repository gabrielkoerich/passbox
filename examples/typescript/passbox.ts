/**
 * dotenv, without the secrets on disk.
 *
 * The usual `.env` holds values, so it is gitignored, copied between machines over Slack, and
 * readable by anything on the box. `.env.passbox` holds *names* instead:
 *
 *     DATABASE_URL=app/db-url
 *     STRIPE_KEY=app/stripe
 *
 * That file is safe to commit. It documents what the service needs without being worth stealing.
 * execArgs() turns it into a `passbox exec` command line, so the values go from the broker into
 * the program's environment and never through this process.
 */

import { readFileSync } from "node:fs";

/** `VAR=secret/name` per line, `#` comments and blanks ignored. */
export function parse(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const name = line.slice(eq + 1).trim();
    if (name) out.set(line.slice(0, eq).trim(), name);
  }
  return out;
}

/**
 * The `passbox exec` arguments that launch a program with every variable the file names:
 *
 *     passbox exec --env DATABASE_URL=app/db-url -- node server.js
 *
 * The program keeps reading process.env, and a heap dump or an unhandled rejection in the process
 * that launches it cannot carry what that process never held.
 */
export function execArgs(path = ".env.passbox", namespace?: string): string[] {
  const wanted = parse(readFileSync(path, "utf8"));
  const args: string[] = ["exec"];
  for (const [variable, name] of wanted) {
    args.push("--env", `${variable}=${namespace ? `${namespace}/${name}` : name}`);
  }
  args.push("--");
  return args;
}

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
 * At startup this resolves each name through passbox and populates process.env, so the rest of
 * the code keeps reading process.env and never knows the difference.
 *
 * No dependency: it shells out to the passbox CLI, so no key material enters this process
 * beyond the values themselves.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

/** passbox caps a grant at 24 hours and refuses more, so ask for the ceiling. */
const GRANT_SECS = 86_400;

/** A read can raise a Touch ID prompt, so allow for a human reaching for the sensor. */
const TIMEOUT_MS = 120_000;

export interface LoadOptions {
  /** Defaults to `.env.passbox` in the working directory. */
  path?: string;
  /** Prepended to every name, so the file can say `db-url` rather than `app/db-url`. */
  namespace?: string;
  /** Shown in the prompt beside the secret. Make it something a human recognises. */
  agent?: string;
  /** Overwrite variables already in the environment. Off, so production wins. */
  override?: boolean;
}

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

function run(args: string[], env: NodeJS.ProcessEnv, quiet = false): string {
  return execFileSync("passbox", args, {
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    env,
    // A failed grant is expected on a store with no broker, so it should not look like an error
    stdio: quiet ? ["ignore", "pipe", "ignore"] : ["ignore", "pipe", "inherit"],
  });
}

/**
 * One approval for everything the file names, rather than one per variable.
 *
 * An inherited PASSBOX_TOKEN wins, which is how a container or a supervisor hands one down.
 * A grant that fails is not fatal: the reads below simply prompt instead.
 */
function mintToken(names: string[], agent?: string): string | undefined {
  if (process.env.PASSBOX_TOKEN) return process.env.PASSBOX_TOKEN;
  try {
    const env = { ...process.env, ...(agent ? { PASSBOX_AGENT: agent } : {}) };
    return run(["grant", ...names, "--for", String(GRANT_SECS)], env, true).trim() || undefined;
  } catch {
    return undefined;
  }
}

/** Resolve `.env.passbox` into process.env. Returns the variables it set. */
export function config(options: LoadOptions = {}): string[] {
  const path = options.path ?? ".env.passbox";
  if (!existsSync(path)) return [];

  const wanted = parse(readFileSync(path, "utf8"));
  const full = (n: string) => (options.namespace ? `${options.namespace}/${n}` : n);

  // Anything already set stays set, so a deployment can override without touching this file
  const missing = [...wanted].filter(([v]) => options.override || !process.env[v]);
  if (missing.length === 0) return [];

  const token = mintToken(missing.map(([, n]) => full(n)), options.agent);
  const env = {
    ...process.env,
    ...(options.agent ? { PASSBOX_AGENT: options.agent } : {}),
    ...(token ? { PASSBOX_TOKEN: token } : {}),
  };

  const set: string[] = [];
  for (const [variable, name] of missing) {
    process.env[variable] = run(["get", full(name)], env);
    set.push(variable);
  }
  return set;
}

/**
 * Better than config() where the program can be launched rather than loaded.
 *
 * `passbox exec` puts the value into the child and never into this process, so a heap dump or
 * an unhandled rejection here cannot carry it:
 *
 *     passbox exec --env DATABASE_URL=app/db-url -- node server.js
 *
 * Use config() when something has to run in this process before the values are known.
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

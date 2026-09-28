/** Round trip against a throwaway store, so it needs no hardware and raises no prompt. */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { config, parse, execArgs } from "./passbox.js";

const store = mkdtempSync(join(tmpdir(), "passbox-ts-"));
const env = {
  ...process.env,
  PASSBOX_DIR: store,
  PASSBOX_PASSPHRASE: "correct horse battery staple",
};
process.env.PASSBOX_DIR = store;
process.env.PASSBOX_PASSPHRASE = env.PASSBOX_PASSPHRASE;

execFileSync("passbox", ["init"], { env, stdio: "ignore" });
execFileSync("passbox", ["add", "demo/db-url"], { env, input: "postgres://localhost/app" });
execFileSync("passbox", ["add", "demo/stripe"], { env, input: "sk_test_123" });

const manifest = join(store, ".env.passbox");
writeFileSync(manifest, "# a comment\nDATABASE_URL=db-url\n\nSTRIPE_KEY=stripe\n");

// the file parses to names, and ignores comments and blanks
const wanted = parse("# c\nA=one\n\nB=two\n");
assert.deepEqual([...wanted], [["A", "one"], ["B", "two"]]);

const set = config({ path: manifest, namespace: "demo", agent: "self-check" });
assert.deepEqual(set.sort(), ["DATABASE_URL", "STRIPE_KEY"]);
assert.equal(process.env.DATABASE_URL, "postgres://localhost/app");
assert.equal(process.env.STRIPE_KEY, "sk_test_123");

// a variable already set is left alone, so a deployment can override
process.env.STRIPE_KEY = "from-the-environment";
config({ path: manifest, namespace: "demo" });
assert.equal(process.env.STRIPE_KEY, "from-the-environment");

// and the exec form builds the command that never loads them here at all
assert.deepEqual(execArgs(manifest, "demo"), [
  "exec",
  "--env", "DATABASE_URL=demo/db-url",
  "--env", "STRIPE_KEY=demo/stripe",
  "--",
]);

rmSync(store, { recursive: true, force: true });
console.log("all checks passed");

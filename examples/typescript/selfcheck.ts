/** Round trip against a throwaway store, so it needs no hardware and raises no prompt. */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { parse, execArgs } from "./passbox.js";

const store = mkdtempSync(join(tmpdir(), "passbox-ts-"));
const env = {
  ...process.env,
  PASSBOX_DIR: store,
  PASSBOX_PASSPHRASE: "correct horse battery staple",
};

execFileSync("passbox", ["init"], { env, stdio: "ignore" });
execFileSync("passbox", ["add", "demo/db-url"], { env, input: "postgres://localhost/app" });
execFileSync("passbox", ["add", "demo/stripe"], { env, input: "sk_test_123" });

const manifest = join(store, ".env.passbox");
writeFileSync(manifest, "# a comment\nDATABASE_URL=db-url\n\nSTRIPE_KEY=stripe\n");

// the file parses to names, and ignores comments and blanks
const wanted = parse("# c\nA=one\n\nB=two\n");
assert.deepEqual([...wanted], [["A", "one"], ["B", "two"]]);

// the exec form builds the command that never loads them here at all
const args = execArgs(manifest, "demo");
assert.deepEqual(args, [
  "exec",
  "--env", "DATABASE_URL=demo/db-url",
  "--env", "STRIPE_KEY=demo/stripe",
  "--",
]);

// and the launched program finds them in its environment
const check = 'test "$DATABASE_URL" = postgres://localhost/app && test "$STRIPE_KEY" = sk_test_123 && echo ok';
const out = execFileSync("passbox", [...args, "sh", "-c", check], { env, encoding: "utf8" });
assert.equal(out.trim(), "ok");

rmSync(store, { recursive: true, force: true });
console.log("all checks passed");

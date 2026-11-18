import { afterEach, beforeEach, expect, test } from "bun:test";
import { forget, sign } from "./apns";
import relay, { type Env } from "./index";

// A KV namespace held in a map, with only the calls the relay makes
function kv(): KVNamespace & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    async get(key: string, type?: string) {
      const value = data.get(key);
      if (value === undefined) {
        return null;
      }

      return type === "json" ? JSON.parse(value) : value;
    },
    async put(key: string, value: string) {
      data.set(key, value);
    },
    async delete(key: string) {
      data.delete(key);
    },
  } as unknown as KVNamespace & { data: Map<string, string> };
}

async function pem(): Promise<{ key: string; publicKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const body = btoa(String.fromCharCode(...der));
  return { key: `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`, publicKey: pair.publicKey };
}

function call(env: Env, path: string, body: unknown): Promise<Response> {
  return relay.fetch(
    new Request(`https://relay.example${path}`, { method: "POST", body: JSON.stringify(body) }),
    env,
  );
}

const DEVICE = "ab".repeat(32);
let sent: { url: string; init: RequestInit }[] = [];
let answer = 200;
const realFetch = globalThis.fetch;
let env: Env & { PHONES: ReturnType<typeof kv> };

beforeEach(async () => {
  forget();
  sent = [];
  answer = 200;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    sent.push({ url, init });
    return new Response(answer === 200 ? "" : '{"reason":"Unregistered"}', { status: answer });
  }) as typeof fetch;
  env = {
    PHONES: kv(),
    APNS_KEY: (await pem()).key,
    KEY_ID: "KEY1234567",
    TEAM_ID: "TEAM123456",
    TOPIC: "com.example.app",
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

test("the token names the key and the team and verifies with the key's public half", async () => {
  const { key, publicKey } = await pem();
  const jwt = await sign({ keyId: "KEY1234567", teamId: "TEAM123456", key }, 1_700_000_000);
  const [head, claims, signature] = jwt.split(".");
  const decode = (part: string) =>
    Uint8Array.from(atob(part.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  expect(JSON.parse(new TextDecoder().decode(decode(head)))).toEqual({ alg: "ES256", kid: "KEY1234567" });
  expect(JSON.parse(new TextDecoder().decode(decode(claims)))).toEqual({
    iss: "TEAM123456",
    iat: 1_700_000_000,
  });
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    decode(signature),
    new TextEncoder().encode(`${head}.${claims}`),
  );
  expect(valid).toBe(true);
});

test("a registered phone is pushed with the fixed sentence, and only with its secret", async () => {
  const { id, secret } = (await (await call(env, "/register", { token: DEVICE, environment: "production" })).json()) as {
    id: string;
    secret: string;
  };
  expect(id).toMatch(/^[0-9a-f]{32}$/);
  // The store keeps a hash, so reading it is not enough to push
  expect(env.PHONES.data.get(id)).not.toContain(secret);

  expect((await call(env, "/push", { id, secret: "wrong" })).status).toBe(403);
  expect(sent).toHaveLength(0);

  expect((await call(env, "/push", { id, secret })).status).toBe(200);
  expect(sent[0].url).toBe(`https://api.push.apple.com/3/device/${DEVICE}`);
  const headers = sent[0].init.headers as Record<string, string>;
  expect(headers["apns-topic"]).toBe("com.example.app");
  expect(headers.authorization).toStartWith("bearer ");
  expect(JSON.parse(sent[0].init.body as string)).toEqual({
    aps: { alert: { title: "passbox", body: "Your Mac is waiting for an approval" }, sound: "default" },
  });

  // Pushing writes nothing, so the free plan's daily writes go to registrations alone
  const stored = env.PHONES.data.get(id);
  await call(env, "/push", { id, secret });
  expect(env.PHONES.data.get(id)).toBe(stored);
});

test("a phone re-registers a new device token under the same id", async () => {
  const first = (await (await call(env, "/register", { token: DEVICE, environment: "sandbox" })).json()) as {
    id: string;
    secret: string;
  };
  const again = (await (
    await call(env, "/register", { token: "cd".repeat(32), environment: "sandbox", ...first })
  ).json()) as { id: string };
  expect(again.id).toBe(first.id);
  await call(env, "/push", first);
  expect(sent[0].url).toBe(`https://api.sandbox.push.apple.com/3/device/${"cd".repeat(32)}`);
});

test("a token Apple calls unregistered is forgotten", async () => {
  const phone = (await (await call(env, "/register", { token: DEVICE, environment: "production" })).json()) as {
    id: string;
    secret: string;
  };
  answer = 410;
  expect((await call(env, "/push", phone)).status).toBe(502);
  expect(env.PHONES.data.has(phone.id)).toBe(false);
});

test("what is not a device token is refused", async () => {
  expect((await call(env, "/register", { token: "nothex", environment: "production" })).status).toBe(400);
  expect((await call(env, "/register", { token: DEVICE, environment: "elsewhere" })).status).toBe(400);
  expect((await call(env, "/nowhere", {})).status).toBe(404);
});

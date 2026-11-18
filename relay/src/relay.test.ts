import { afterAll, beforeEach, expect, test } from "bun:test";
import { createServer } from "node:http2";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { forget, sign } from "./apns";
import { close, send as http2 } from "./http2";
import { type Deps, type Phone, handle } from "./relay";
import { sqlite } from "./server";

async function pem(): Promise<{ key: string; publicKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const body = btoa(String.fromCharCode(...der));
  return { key: `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`, publicKey: pair.publicKey };
}

const DEVICE = "ab".repeat(32);
let data: Map<string, Phone>;
let sent: { url: string; headers: Record<string, string>; body: string }[];
let answer: number;
let deps: Deps;

function call(path: string, body: unknown): Promise<Response> {
  return handle(new Request(`https://relay.example${path}`, { method: "POST", body: JSON.stringify(body) }), deps);
}

async function registered(environment = "production"): Promise<{ id: string; secret: string }> {
  return (await (await call("/register", { token: DEVICE, environment })).json()) as { id: string; secret: string };
}

beforeEach(async () => {
  forget();
  data = new Map();
  sent = [];
  answer = 200;
  deps = {
    phones: {
      async get(id) {
        return data.get(id);
      },
      async put(id, phone) {
        data.set(id, phone);
      },
      async delete(id) {
        data.delete(id);
      },
    },
    async send(url, headers, body) {
      sent.push({ url, headers, body });
      return { status: answer, body: answer === 200 ? "" : '{"reason":"Unregistered"}' };
    },
    config: { key: (await pem()).key, keyId: "KEY1234567", teamId: "TEAM123456", topic: "com.example.app" },
  };
});

afterAll(() => close());

test("the token names the key and the team and verifies with the key's public half", async () => {
  const { key, publicKey } = await pem();
  const jwt = await sign({ keyId: "KEY1234567", teamId: "TEAM123456", key }, 1_700_000_000);
  const [head, claims, signature] = jwt.split(".");
  const decode = (part: string) =>
    Uint8Array.from(atob(part.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  expect(JSON.parse(new TextDecoder().decode(decode(head)))).toEqual({ alg: "ES256", kid: "KEY1234567" });
  expect(JSON.parse(new TextDecoder().decode(decode(claims)))).toEqual({ iss: "TEAM123456", iat: 1_700_000_000 });
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    decode(signature),
    new TextEncoder().encode(`${head}.${claims}`),
  );
  expect(valid).toBe(true);
});

test("a registered phone is pushed with the fixed sentence, and only with its secret", async () => {
  const { id, secret } = await registered();
  expect(id).toMatch(/^[0-9a-f]{32}$/);
  // The store keeps a hash, so reading it is not enough to push
  expect(JSON.stringify(data.get(id))).not.toContain(secret);

  expect((await call("/push", { id, secret: "wrong" })).status).toBe(403);
  expect(sent).toHaveLength(0);

  expect((await call("/push", { id, secret })).status).toBe(200);
  expect(sent[0].url).toBe(`https://api.push.apple.com/3/device/${DEVICE}`);
  expect(sent[0].headers["apns-topic"]).toBe("com.example.app");
  expect(sent[0].headers.authorization).toStartWith("bearer ");
  expect(JSON.parse(sent[0].body)).toEqual({
    aps: { alert: { title: "passbox", body: "Your Mac is waiting for an approval" }, sound: "default" },
  });

  // Pushing writes nothing, so a store that counts writes spends them on registrations alone
  const stored = JSON.stringify(data.get(id));
  await call("/push", { id, secret });
  expect(JSON.stringify(data.get(id))).toBe(stored);
});

test("a phone re-registers a new device token under the same id", async () => {
  const first = await registered("sandbox");
  const again = (await (
    await call("/register", { token: "cd".repeat(32), environment: "sandbox", ...first })
  ).json()) as { id: string };
  expect(again.id).toBe(first.id);
  await call("/push", first);
  expect(sent[0].url).toBe(`https://api.sandbox.push.apple.com/3/device/${"cd".repeat(32)}`);
});

test("a token Apple calls unregistered is forgotten", async () => {
  const phone = await registered();
  answer = 410;
  expect((await call("/push", phone)).status).toBe(502);
  expect(data.has(phone.id)).toBe(false);
});

test("what is not a device token is refused", async () => {
  expect((await call("/register", { token: "nothex", environment: "production" })).status).toBe(400);
  expect((await call("/register", { token: DEVICE, environment: "elsewhere" })).status).toBe(400);
  expect((await call("/nowhere", {})).status).toBe(404);
});

test("the server's sender speaks HTTP/2, which APNs requires", async () => {
  const seen: { version: string; path: string; topic: string; body: string }[] = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      seen.push({
        version: request.httpVersion,
        path: request.url,
        topic: String(request.headers["apns-topic"]),
        body,
      });
      response.writeHead(400);
      response.end('{"reason":"BadDeviceToken"}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };

  const reply = await http2(`http://127.0.0.1:${port}/3/device/${DEVICE}`, { "apns-topic": "t" }, "{}");
  expect(reply).toEqual({ status: 400, body: '{"reason":"BadDeviceToken"}' });
  expect(seen).toEqual([{ version: "2.0", path: `/3/device/${DEVICE}`, topic: "t", body: "{}" }]);
  close();
  server.close();
});

test("the server keeps phones in SQLite", async () => {
  const phones = sqlite(join(mkdtempSync(join(tmpdir(), "relay-")), "phones.db"));
  const phone: Phone = { token: DEVICE, environment: "production", secret: "h" };
  await phones.put("a", phone);
  expect(await phones.get("a")).toEqual(phone);
  await phones.delete("a");
  expect(await phones.get("a")).toBeUndefined();
});

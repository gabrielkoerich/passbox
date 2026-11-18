/**
 * The push relay. Only the app's owner can ask APNs to wake the app, so the key lives here and no
 * Mac ever holds it. A phone registers its device token and gets back an id and a secret, which it
 * hands to its Mac when they pair. The Mac sends those two when a prompt is waiting, and the phone
 * is told that much and nothing more: the secret's name and the agent stay on the Mac.
 *
 * Nothing here knows where it runs. `cloudflare.ts` and `server.ts` each hand `handle` a place to
 * keep phones and a way to reach Apple
 **/

import { token } from "./apns";

export interface Phone {
  token: string;
  environment: "production" | "sandbox";
  // SHA-256 of the secret, so the store alone cannot push
  secret: string;
}

export interface Phones {
  get(id: string): Promise<Phone | undefined>;
  put(id: string, phone: Phone): Promise<void>;
  delete(id: string): Promise<void>;
}

// One POST to APNs. It has to be HTTP/2, which is why each runtime brings its own
export type Send = (
  url: string,
  headers: Record<string, string>,
  body: string,
) => Promise<{ status: number; body: string }>;

export interface Config {
  // The .p8 key's text
  key: string;
  keyId: string;
  teamId: string;
  // The app's bundle id
  topic: string;
}

export interface Deps {
  phones: Phones;
  send: Send;
  config: Config;
}

const ALERT = {
  aps: {
    alert: { title: "passbox", body: "Your Mac is waiting for an approval" },
    sound: "default",
  },
};

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function hash(secret: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret))));
}

function random(bytes: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function body(request: Request): Promise<Record<string, unknown>> {
  try {
    const parsed: unknown = await request.json();
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }

    return {};
  } catch {
    return {};
  }
}

// The phone it names, if the secret is the one it was given
async function owned(phones: Phones, id: unknown, secret: unknown): Promise<Phone | undefined> {
  if (typeof id !== "string" || typeof secret !== "string" || !/^[0-9a-f]{32}$/.test(id)) {
    return undefined;
  }

  const phone = await phones.get(id);
  if (!phone || phone.secret !== (await hash(secret))) {
    return undefined;
  }

  return phone;
}

// A new phone, or a known one whose device token changed, which iOS does after a restore
async function register(phones: Phones, input: Record<string, unknown>): Promise<Response> {
  const { token: device, environment } = input;
  if (typeof device !== "string" || !/^[0-9a-f]{64,200}$/.test(device)) {
    return reply(400, { error: "the device token is not hex" });
  }

  if (environment !== "production" && environment !== "sandbox") {
    return reply(400, { error: "environment is production or sandbox" });
  }

  const known = await owned(phones, input.id, input.secret);
  if (known) {
    await phones.put(input.id as string, { ...known, token: device, environment });
    return reply(200, { id: input.id, secret: input.secret });
  }

  const id = random(16);
  const secret = random(32);
  await phones.put(id, { token: device, environment, secret: await hash(secret) });
  return reply(200, { id, secret });
}

// A push only reads, so a store that counts writes, as Cloudflare KV does, spends them on registrations
async function push(deps: Deps, input: Record<string, unknown>, now: number): Promise<Response> {
  const phone = await owned(deps.phones, input.id, input.secret);
  if (!phone) {
    return reply(403, { error: "no phone with that id and secret" });
  }

  const host = phone.environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  const bearer = await token(
    { keyId: deps.config.keyId, teamId: deps.config.teamId, key: deps.config.key },
    Math.floor(now / 1000),
  );
  const apple = await deps.send(
    `https://${host}/3/device/${phone.token}`,
    {
      authorization: `bearer ${bearer}`,
      "apns-topic": deps.config.topic,
      "apns-push-type": "alert",
      "apns-priority": "10",
    },
    JSON.stringify(ALERT),
  );
  if (apple.status === 200) {
    return reply(200, { ok: true });
  }

  // The app was deleted or the token replaced, so this id can never be delivered to again
  if (apple.status === 410) {
    await deps.phones.delete(input.id as string);
  }

  return reply(502, { error: `apple refused the push: ${apple.status} ${apple.body}` });
}

export async function handle(request: Request, deps: Deps, now = Date.now()): Promise<Response> {
  if (request.method !== "POST") {
    return reply(405, { error: "POST only" });
  }

  const path = new URL(request.url).pathname;
  const input = await body(request);
  if (path === "/register") {
    return register(deps.phones, input);
  }

  if (path === "/push") {
    return push(deps, input, now);
  }

  return reply(404, { error: "the paths are /register and /push" });
}

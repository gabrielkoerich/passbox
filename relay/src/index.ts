/**
 * The push relay. Only the app's owner can ask APNs to wake the app, so the key lives here and no
 * Mac ever holds it. A phone registers its device token and gets back an id and a secret, which it
 * hands to its Mac when they pair. The Mac sends those two when a prompt is waiting, and the phone
 * is told that much and nothing more: the secret's name and the agent stay on the Mac
 **/

import { token } from "./apns";

export interface Env {
  PHONES: KVNamespace;
  APNS_KEY: string;
  KEY_ID: string;
  TEAM_ID: string;
  TOPIC: string;
}

interface Phone {
  token: string;
  environment: "production" | "sandbox";
  // SHA-256 of the secret, so the store alone cannot push
  secret: string;
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
async function owned(env: Env, id: unknown, secret: unknown): Promise<Phone | undefined> {
  if (typeof id !== "string" || typeof secret !== "string" || !/^[0-9a-f]{32}$/.test(id)) {
    return undefined;
  }

  const phone = await env.PHONES.get<Phone>(id, "json");
  if (!phone || phone.secret !== (await hash(secret))) {
    return undefined;
  }

  return phone;
}

// A new phone, or a known one whose device token changed, which iOS does after a restore
async function register(env: Env, input: Record<string, unknown>): Promise<Response> {
  const { token: device, environment } = input;
  if (typeof device !== "string" || !/^[0-9a-f]{64,200}$/.test(device)) {
    return reply(400, { error: "the device token is not hex" });
  }

  if (environment !== "production" && environment !== "sandbox") {
    return reply(400, { error: "environment is production or sandbox" });
  }

  const known = await owned(env, input.id, input.secret);
  if (known) {
    await env.PHONES.put(
      input.id as string,
      JSON.stringify({ ...known, token: device, environment } satisfies Phone),
    );
    return reply(200, { id: input.id, secret: input.secret });
  }

  const id = random(16);
  const secret = random(32);
  await env.PHONES.put(
    id,
    JSON.stringify({ token: device, environment, secret: await hash(secret) } satisfies Phone),
  );
  return reply(200, { id, secret });
}

// A push only reads, since the free plan allows a thousand writes a day and a hundred thousand reads
async function push(env: Env, input: Record<string, unknown>, now: number): Promise<Response> {
  const phone = await owned(env, input.id, input.secret);
  if (!phone) {
    return reply(403, { error: "no phone with that id and secret" });
  }

  const id = input.id as string;
  const host = phone.environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  const bearer = await token(
    { keyId: env.KEY_ID, teamId: env.TEAM_ID, key: env.APNS_KEY },
    Math.floor(now / 1000),
  );
  const apple = await fetch(`https://${host}/3/device/${phone.token}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${bearer}`,
      "apns-topic": env.TOPIC,
      "apns-push-type": "alert",
      "apns-priority": "10",
    },
    body: JSON.stringify(ALERT),
  });
  if (apple.status === 200) {
    return reply(200, { ok: true });
  }

  const why = await apple.text();
  // The app was deleted or the token replaced, so this id can never be delivered to again
  if (apple.status === 410) {
    await env.PHONES.delete(id);
  }

  return reply(502, { error: `apple refused the push: ${apple.status} ${why}` });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return reply(405, { error: "POST only" });
    }

    const path = new URL(request.url).pathname;
    const input = await body(request);
    if (path === "/register") {
      return register(env, input);
    }

    if (path === "/push") {
      return push(env, input, Date.now());
    }

    return reply(404, { error: "the paths are /register and /push" });
  },
} satisfies ExportedHandler<Env>;

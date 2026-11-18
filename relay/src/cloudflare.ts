/**
 * The relay as a Cloudflare Worker: phones in a KV namespace, and APNs reached with the Worker's
 * own fetch. The key is a secret set with `wrangler secret put APNS_KEY`, the rest are plain vars
 * in wrangler.toml
 **/

import { type Phone, type Phones, type Send, handle } from "./relay";

export interface Env {
  PHONES: KVNamespace;
  APNS_KEY: string;
  KEY_ID: string;
  TEAM_ID: string;
  TOPIC: string;
}

function kv(namespace: KVNamespace): Phones {
  return {
    async get(id) {
      return (await namespace.get<Phone>(id, "json")) ?? undefined;
    },
    async put(id, phone) {
      await namespace.put(id, JSON.stringify(phone));
    },
    async delete(id) {
      await namespace.delete(id);
    },
  };
}

const send: Send = async (url, headers, body) => {
  const response = await fetch(url, { method: "POST", headers, body });
  return { status: response.status, body: await response.text() };
};

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, {
      phones: kv(env.PHONES),
      send,
      config: { key: env.APNS_KEY, keyId: env.KEY_ID, teamId: env.TEAM_ID, topic: env.TOPIC },
    });
  },
} satisfies ExportedHandler<Env>;

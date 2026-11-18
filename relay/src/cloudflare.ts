/**
 * The relay as a Cloudflare Worker: phones in D1, in the same table the server keeps in SQLite, and
 * APNs reached with the Worker's own fetch. The key is a secret set once with `wrangler secret put
 * APNS_KEY`, the rest are plain vars in wrangler.toml
 **/

import { type Phone, type Phones, type Send, handle } from "./relay";

export interface Env {
  PHONES: D1Database;
  APNS_KEY: string;
  KEY_ID: string;
  TEAM_ID: string;
  TOPIC: string;
}

// Made once per isolate, so a fresh database needs no migration step
let ready: Promise<unknown> | undefined;

function d1(db: D1Database): Phones {
  ready ??= db.prepare("CREATE TABLE IF NOT EXISTS phones (id TEXT PRIMARY KEY, phone TEXT NOT NULL)").run();
  return {
    async get(id) {
      await ready;
      const row = await db.prepare("SELECT phone FROM phones WHERE id = ?").bind(id).first<{ phone: string }>();
      return row ? (JSON.parse(row.phone) as Phone) : undefined;
    },
    async put(id, phone) {
      await ready;
      await db.prepare("INSERT OR REPLACE INTO phones (id, phone) VALUES (?, ?)").bind(id, JSON.stringify(phone)).run();
    },
    async delete(id) {
      await ready;
      await db.prepare("DELETE FROM phones WHERE id = ?").bind(id).run();
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
      phones: d1(env.PHONES),
      send,
      config: { key: env.APNS_KEY, keyId: env.KEY_ID, teamId: env.TEAM_ID, topic: env.TOPIC },
    });
  },
} satisfies ExportedHandler<Env>;

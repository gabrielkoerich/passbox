/**
 * The relay as a plain server, for a VPS or any machine with Bun: phones in a SQLite file, APNs
 * over `node:http2`. It listens on loopback without TLS, so a proxy such as Caddy terminates HTTPS
 * in front of it. Configured by environment:
 *
 *   APNS_KEY_FILE  the .p8 key       KEY_ID, TEAM_ID  from the Apple Developer site
 *   TOPIC          the app's bundle id
 *   DATA           the SQLite file, phones.db by default
 *   HOST, PORT     where it listens, 127.0.0.1:8788 by default
 **/

import { Database } from "bun:sqlite";
import { send } from "./http2";
import { type Phone, type Phones, handle } from "./relay";

export function sqlite(path: string): Phones {
  const db = new Database(path, { create: true });
  db.run("CREATE TABLE IF NOT EXISTS phones (id TEXT PRIMARY KEY, phone TEXT NOT NULL)");
  const get = db.query<{ phone: string }, [string]>("SELECT phone FROM phones WHERE id = ?");
  const put = db.query("INSERT OR REPLACE INTO phones (id, phone) VALUES (?, ?)");
  const remove = db.query("DELETE FROM phones WHERE id = ?");
  return {
    async get(id) {
      const row = get.get(id);
      return row ? (JSON.parse(row.phone) as Phone) : undefined;
    },
    async put(id, phone) {
      put.run(id, JSON.stringify(phone));
    },
    async delete(id) {
      remove.run(id);
    },
  };
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }

  return value;
}

if (import.meta.main) {
  const config = {
    key: await Bun.file(required("APNS_KEY_FILE")).text(),
    keyId: required("KEY_ID"),
    teamId: required("TEAM_ID"),
    topic: required("TOPIC"),
  };
  const phones = sqlite(process.env.DATA ?? "phones.db");
  const server = Bun.serve({
    hostname: process.env.HOST ?? "127.0.0.1",
    port: Number(process.env.PORT ?? 8788),
    fetch: (request) => handle(request, { phones, send, config }),
  });
  console.log(`passbox push relay on ${server.url}`);
}

/**
 * APNs over `node:http2`, for a relay that runs under Bun or Node on a server of its own. Their
 * fetch speaks HTTP/1.1, which APNs refuses. One session per origin is kept open and reused, as
 * Apple asks, and a session that closes is opened again on the next push
 **/

import { connect, type ClientHttp2Session } from "node:http2";
import type { Send } from "./relay";

const sessions = new Map<string, ClientHttp2Session>();

function session(origin: string): ClientHttp2Session {
  const open = sessions.get(origin);
  if (open && !open.closed && !open.destroyed) {
    return open;
  }

  const fresh = connect(origin);
  fresh.on("error", () => sessions.delete(origin));
  fresh.on("close", () => sessions.delete(origin));
  sessions.set(origin, fresh);
  return fresh;
}

export const send: Send = (url, headers, body) => {
  const { origin, pathname } = new URL(url);
  return new Promise((resolve, reject) => {
    const stream = session(origin).request({ ":method": "POST", ":path": pathname, ...headers });
    let status = 0;
    let text = "";
    stream.setEncoding("utf8");
    stream.on("response", (head) => {
      status = Number(head[":status"]);
    });
    stream.on("data", (chunk: string) => {
      text += chunk;
    });
    stream.on("end", () => resolve({ status, body: text }));
    stream.on("error", reject);
    stream.end(body);
  });
};

// Tests and a server that is stopping close what is open
export function close(): void {
  for (const open of sessions.values()) {
    open.close();
  }

  sessions.clear();
}

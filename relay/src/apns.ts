/**
 * The token APNs takes in place of a certificate: an ES256 JWT naming the key and the team, signed
 * with the .p8 key. Apple refuses a token older than an hour and one renewed more often than every
 * 20 minutes, so one is kept and reused for 40
 **/

export interface Signer {
  keyId: string;
  teamId: string;
  // The .p8 file's text, as Apple hands it out
  key: string;
}

const REUSE_SECONDS = 40 * 60;

let cached: { token: string; issued: number; keyId: string } | undefined;

function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }

  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function json(value: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(value)));
}

export async function importKey(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
}

// A fresh token, signed now. WebCrypto returns the raw r and s that JWS wants, not DER
export async function sign(signer: Signer, now: number): Promise<string> {
  const head = `${json({ alg: "ES256", kid: signer.keyId })}.${json({ iss: signer.teamId, iat: now })}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await importKey(signer.key),
    new TextEncoder().encode(head),
  );
  return `${head}.${base64url(new Uint8Array(signature))}`;
}

export async function token(signer: Signer, now: number): Promise<string> {
  if (cached && cached.keyId === signer.keyId && now - cached.issued < REUSE_SECONDS) {
    return cached.token;
  }

  cached = { token: await sign(signer, now), issued: now, keyId: signer.keyId };
  return cached.token;
}

// Tests only, so each starts without the last one's token
export function forget(): void {
  cached = undefined;
}

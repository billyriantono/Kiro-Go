// Kiro-Go egress relay — Vercel Edge Function.
//
// Deploy:
//   1. Create a new project (or add to an existing one). Put this file at
//      api/relay.js in the repo.
//   2. Deploy. The relay URL is https://<project>.vercel.app/api/relay
//   3. In Kiro-Go admin → Egress Relay: paste that URL (the secret is already set).
//
// The secret below (RELAY_KEY) is baked in by the Kiro-Go admin panel, so you do
// NOT need to add any environment variable — just deploy. (You may still override
// it with a RELAY_KEY environment variable if you prefer.)
//
// Forwards each request to the real target in X-Relay-Target after checking the
// shared secret (X-Relay-Key) and an upstream host allow-list, then streams the
// upstream response back so Kiro's SSE streaming keeps working.

export const config = { runtime: "edge" };

const RELAY_KEY = "__RELAY_KEY__";

const ALLOW_SUFFIXES = [
  ".amazonaws.com",
  ".kiro.dev",
  ".microsoftonline.com",
  ".microsoftonline.us",
  ".microsoftonline.cn",
];

function hostAllowed(host) {
  host = host.toLowerCase();
  return ALLOW_SUFFIXES.some((s) => host === s.slice(1) || host.endsWith(s));
}

export default async function handler(request) {
  const target = request.headers.get("X-Relay-Target");
  const key = request.headers.get("X-Relay-Key") || "";
  const expected = process.env.RELAY_KEY || RELAY_KEY;
  if (expected && expected !== "__RELAY_KEY__" && key !== expected) {
    return new Response("unauthorized", { status: 401 });
  }
  // Health probe from the Kiro-Go admin "Test relay" button.
  if (request.headers.get("X-Relay-Ping")) {
    return new Response("relay-ok", { status: 200 });
  }
  if (!target) return new Response("missing X-Relay-Target", { status: 400 });
  let url;
  try {
    url = new URL(target);
  } catch {
    return new Response("bad target", { status: 400 });
  }
  if (url.protocol !== "https:" || !hostAllowed(url.hostname)) {
    return new Response("target not allowed", { status: 403 });
  }

  const headers = new Headers(request.headers);
  headers.delete("X-Relay-Target");
  headers.delete("X-Relay-Key");
  headers.delete("Host");

  const method = request.method;
  const body =
    method === "GET" || method === "HEAD" ? undefined : await request.arrayBuffer();

  const upstream = await fetch(url.toString(), {
    method,
    headers,
    body,
    redirect: "manual",
  });

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: new Headers(upstream.headers),
  });
}

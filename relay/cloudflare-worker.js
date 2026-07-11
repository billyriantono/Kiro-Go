// Kiro-Go egress relay — Cloudflare Worker.
//
// Deploy:
//   1. Cloudflare dashboard → Workers & Pages → Create → Worker. Paste this file.
//   2. Deploy. Copy the worker URL (https://<name>.<subdomain>.workers.dev).
//   3. In Kiro-Go admin → Egress Relay: paste the URL (the secret is already set).
//
// The secret below (RELAY_KEY) is baked in by the Kiro-Go admin panel, so you do
// NOT need to configure any environment variable — just deploy. (You may still
// override it with a Worker Secret named RELAY_KEY if you prefer.)
//
// The relay forwards each request to the real target carried in X-Relay-Target,
// after checking the shared secret (X-Relay-Key) and an upstream host allow-list
// so it cannot be abused as an open proxy. The upstream response is streamed
// straight back, so Kiro's SSE streaming keeps working.

const RELAY_KEY = "__RELAY_KEY__";

const ALLOW_SUFFIXES = [
  ".amazonaws.com", // codewhisperer / q / oidc
  ".kiro.dev", // app.kiro.dev, *.auth.desktop.kiro.dev
  ".microsoftonline.com",
  ".microsoftonline.us",
  ".microsoftonline.cn",
];

function hostAllowed(host) {
  host = host.toLowerCase();
  return ALLOW_SUFFIXES.some((s) => host === s.slice(1) || host.endsWith(s));
}

export default {
  async fetch(request, env) {
    const target = request.headers.get("X-Relay-Target");
    const key = request.headers.get("X-Relay-Key") || "";
    const expected = (env && env.RELAY_KEY) || RELAY_KEY;
    if (expected && expected !== "__RELAY_KEY__" && key !== expected) {
      return new Response("unauthorized", { status: 401 });
    }
    // Health probe from the Kiro-Go admin "Test relay" button: validate the
    // secret (above) then confirm without forwarding.
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

    // Stream the upstream response straight back (keeps SSE working).
    const respHeaders = new Headers(upstream.headers);
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: respHeaders,
    });
  },
};

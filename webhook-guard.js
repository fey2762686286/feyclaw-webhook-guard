/**
 * FeyClaw Webhook Guard — Cloudflare Worker
 *
 * Verifies HMAC signatures from GitHub, Linear, and Expo
 * before forwarding requests to the OpenClaw tunnel.
 *
 * Secrets are stored as Worker environment variables:
 *   GITHUB_WEBHOOK_SECRET
 *   LINEAR_WEBHOOK_SECRET
 *   EXPO_WEBHOOK_SECRET
 *   OPENCLAW_HOOKS_TOKEN
 *   CF_ACCESS_CLIENT_ID
 *   CF_ACCESS_CLIENT_SECRET
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Only handle POST to /hooks/*
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // Path format: /hooks/<source>/<agentId>
    // e.g. /hooks/github/work, /hooks/linear/code
    const parts = url.pathname.split("/").filter(Boolean); // ["hooks", "source", "agentId"]

    if (parts[0] !== "hooks" || parts.length < 2) {
      return new Response("Not Found", { status: 404 });
    }

    const source = parts[1];                        // github | linear | expo
    const agentName = parts[2] || "fey";            // default to "fey" if omitted

    // Map friendly agent names to OpenClaw agent IDs
    const agentMap = { fey: "work", lin: "main", cau: "code" };
    const agentId = agentMap[agentName] || agentName; // fallback to raw value

    // Read body once — needed for HMAC verification
    const body = await request.arrayBuffer();
    const bodyText = new TextDecoder().decode(body);

    let verified = false;

    if (source === "github") {
      const sig = request.headers.get("x-hub-signature-256");
      if (!sig) return unauthorized("Missing GitHub signature");
      verified = await verifyHmacSha256(body, env.GITHUB_WEBHOOK_SECRET, sig.replace("sha256=", ""));

    } else if (source === "linear") {
      const sig = request.headers.get("linear-signature");
      if (!sig) return unauthorized("Missing Linear signature");
      verified = await verifyHmacSha256(body, env.LINEAR_WEBHOOK_SECRET, sig);

    } else if (source === "expo") {
      const sig = request.headers.get("expo-signature");
      if (!sig) return unauthorized("Missing Expo signature");
      verified = await verifyHmacSha1(body, env.EXPO_WEBHOOK_SECRET, sig.replace("sha1=", ""));

    } else {
      return new Response("Unknown webhook source", { status: 400 });
    }

    if (!verified) {
      return new Response("Invalid signature", { status: 401 });
    }

    // Transform payload into OpenClaw /hooks/agent format
    const event = request.headers.get("x-github-event") ||
                  request.headers.get("linear-event") ||
                  "webhook";

    const ocPayload = JSON.stringify({
      message: `Incoming ${source} webhook: ${event}\n\n${bodyText}`,
      name: source.charAt(0).toUpperCase() + source.slice(1),
      agentId: agentId,
      wakeMode: "now",
      deliver: false
    });

    // Forward to OpenClaw /hooks/agent
    const forwardHeaders = new Headers();
    forwardHeaders.set("Authorization", `Bearer ${env.OPENCLAW_HOOKS_TOKEN}`);
    forwardHeaders.set("Content-Type", "application/json");
    forwardHeaders.set("X-Webhook-Source", source);

    const tunnelUrl = `https://hook.feyhook.win/hooks/agent`;

    const response = await fetch(tunnelUrl, {
      method: "POST",
      headers: forwardHeaders,
      body: ocPayload,
    });

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    });
  },
};

// ─── HMAC Helpers ───────────────────────────────────────────────────────────

async function verifyHmacSha256(body, secret, expectedHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, body);
  const actual = bufToHex(sig);
  return timingSafeEqual(actual, expectedHex);
}

async function verifyHmacSha1(body, secret, expectedHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, body);
  const actual = bufToHex(sig);
  return timingSafeEqual(actual, expectedHex);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function unauthorized(msg) {
  return new Response(msg, { status: 401 });
}

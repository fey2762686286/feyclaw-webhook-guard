# FeyClaw Webhook Guard

A Cloudflare Worker that sits in front of [OpenClaw](https://openclaw.ai) and verifies HMAC signatures from external webhook sources before forwarding to your OpenClaw instance.

## What It Does

```
GitHub / Linear / Expo
    → Cloudflare WAF (blocks non /hooks/* paths)
        → Worker (verifies HMAC signature)
            → OpenClaw /hooks/agent (routes to correct agent)
```

No request reaches your server without a valid cryptographic signature. If the HMAC check fails, the worker returns 401 and the request is dropped at the edge.

## Supported Sources

| Service | Signature Header | Algorithm |
|---------|-----------------|-----------|
| GitHub  | `X-Hub-Signature-256` | HMAC-SHA256 |
| Linear  | `linear-signature` | HMAC-SHA256 |
| Expo    | `expo-signature` | HMAC-SHA1 |

## URL Pattern

```
https://hook.feyhook.win/hooks/<source>/<agent>
```

- `<source>` — `github`, `linear`, or `expo`
- `<agent>` — friendly agent name (see routing table below)

### Agent Routing

| URL segment | OpenClaw agent ID | Agent |
|-------------|------------------|-------|
| `fey` | `work` | Fey 🦊 (default) |
| `lin` | `main` | Lin 🦁 |
| `cau` | `code` | Cau 🦍 |

If omitted, defaults to `fey`.

### Examples

```
https://hook.feyhook.win/hooks/github/fey    # GitHub → Fey
https://hook.feyhook.win/hooks/linear/fey    # Linear → Fey
https://hook.feyhook.win/hooks/github/cau    # GitHub → Cau
https://hook.feyhook.win/hooks/expo/fey      # Expo → Fey
```

## Setup

### 1. Deploy the Worker

```bash
# Via Cloudflare API
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/workers/scripts/feyclaw-webhook-guard" \
  -H "Authorization: Bearer <CF_API_TOKEN>" \
  -F "metadata={\"main_module\":\"webhook-guard.js\",\"compatibility_date\":\"2024-01-01\"};type=application/json" \
  -F "webhook-guard.js=@webhook-guard.js;type=application/javascript+module"
```

### 2. Set Worker Secrets

Set these via the Cloudflare dashboard or API:

| Secret | Description |
|--------|-------------|
| `GITHUB_WEBHOOK_SECRET` | Secret from GitHub webhook settings |
| `LINEAR_WEBHOOK_SECRET` | Signing secret provided by Linear |
| `EXPO_WEBHOOK_SECRET` | Secret from Expo webhook settings |
| `OPENCLAW_HOOKS_TOKEN` | Your OpenClaw `hooks.token` value |
| `CF_ACCESS_CLIENT_ID` | Cloudflare Access service token ID (optional) |
| `CF_ACCESS_CLIENT_SECRET` | Cloudflare Access service token secret (optional) |

### 3. Add Worker Route

In Cloudflare Dashboard → **feyhook.win** → **Workers & Pages** → **Routes**:

- **Route:** `hook.feyhook.win/hooks/*`
- **Worker:** `feyclaw-webhook-guard`
- **Failure mode:** Fail closed (block)

### 4. Add WAF Rule

Block all non-webhook paths at the edge:

```
(http.host eq "hook.feyhook.win" and not starts_with(http.request.uri.path, "/hooks"))
→ Block
```

This prevents your OpenClaw WebUI from being exposed via the tunnel.

### 5. Configure GitHub

1. Repo → Settings → Webhooks → Add webhook
2. **Payload URL:** `https://hook.feyhook.win/hooks/github/fey`
3. **Content type:** `application/json`
4. **Secret:** value of `GITHUB_WEBHOOK_SECRET`

### 6. Configure Linear

1. Linear → Settings → API → Webhooks → New webhook
2. **URL:** `https://hook.feyhook.win/hooks/linear/fey`
3. Copy the signing secret Linear provides → set as `LINEAR_WEBHOOK_SECRET`

### 7. Configure Expo

1. expo.dev → Project → Webhooks → Add webhook
2. **URL:** `https://hook.feyhook.win/hooks/expo/fey`
3. Copy the generated secret → set as `EXPO_WEBHOOK_SECRET`

## How Forwarding Works

Once HMAC is verified, the worker transforms the raw webhook payload into an OpenClaw `/hooks/agent` request:

```json
{
  "message": "Incoming github webhook: push\n\n<original payload>",
  "name": "Github",
  "agentId": "work",
  "wakeMode": "now",
  "deliver": false
}
```

OpenClaw receives this on port 18789 via a Cloudflare Tunnel and routes it to the appropriate agent.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Edge | Cloudflare WAF blocks all non `/hooks/*` paths |
| Worker | HMAC-SHA256 (or SHA1 for Expo) signature verification |
| Origin | Cloudflare Tunnel — origin never publicly exposed |

HMAC-SHA256 with a 32-byte random secret provides 256 bits of entropy — equivalent to AES-256. This is the industry standard for webhook authentication (used by GitHub, Stripe, Linear, etc.).

## Generating Secrets

```bash
openssl rand -hex 32
```

## License

MIT

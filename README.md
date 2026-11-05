# immich-device-auth

Proof of concept: let third-party Immich apps get a **scoped, expiring** API key
by showing a QR code, instead of asking users to paste a never-expiring key.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/approval-dark.png">
    <img src="docs/approval-light.png" alt="Approval page on a phone: Allow Kitchen Photo Frame? It lists album read, asset view and download, timeline read, for 1 day, with Deny and Approve buttons" width="300">
  </picture>
  <br><em>What the user sees after scanning the QR code</em>
</p>

It's a small service deployed next to Immich that implements the OAuth 2.0
device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)),
the flow TVs and CLIs use for "scan this code to sign in". It needs no changes
to Immich; everything goes through Immich's public API.

**Requires an Immich server with OAuth (OIDC) sign-in enabled.** Users approve
by signing in through Immich's identity provider, so their password never
passes through this service.

## How it works

```mermaid
sequenceDiagram
  participant App as Third-party app
  participant Broker as immich-device-auth
  participant Phone as User's phone
  participant Immich
  participant IdP as Identity provider

  App->>Broker: POST /device/code (client_name, scope, ttl)
  Broker-->>App: device_code, user_code, verification_uri_complete
  App->>App: Show QR code of verification_uri_complete
  loop every `interval` seconds
    App->>Broker: POST /device/token (device_code)
    Broker-->>App: authorization_pending
  end
  Phone->>Broker: Open approval page (scanned QR)
  Broker-->>Phone: "Allow Kitchen Photo Frame? It will be able to: album read, …"
  Phone->>Broker: Tap Approve
  Broker->>Immich: POST /oauth/authorize (PKCE)
  Broker-->>Phone: Redirect to identity provider
  Phone->>IdP: Sign in
  IdP-->>Phone: Redirect to broker callback
  Phone->>Broker: GET /device/oauth/callback
  Broker->>Immich: POST /oauth/callback → session
  Broker->>Immich: POST /api-keys (approved permissions) → client key
  Broker->>Immich: POST /api-keys (apiKey.delete only) → revoker key
  Broker->>Immich: POST /auth/logout
  App->>Broker: POST /device/token (device_code)
  Broker-->>App: access_token (= client key), expires_at, scope
  App->>Immich: Any request with x-api-key
  Note over Broker,Immich: When the grant expires
  Broker->>Immich: DELETE /api-keys/{client key} (as revoker)
  Broker->>Immich: DELETE /api-keys/{revoker} (as revoker)
```

Design choices worth calling out:

- **No passwords.** The approval page has no credential fields; approving
  starts Immich's OAuth sign-in, with PKCE.
- **The app only ever gets the permissions the user approved.** Requests for
  `all`, key/session/auth management, admin, server config, jobs, libraries,
  plugins or workflows are rejected before the user even sees them (see
  `FORBIDDEN_PERMISSIONS` in `src/config.ts`).
- **No full-access credential outlives the approval.** The login session is
  logged out right after the keys are minted. To delete the client key later,
  the broker keeps a second key that can *only* delete keys, and that key
  deletes itself once it's done.
- **The client key's secret is never stored**, only its SHA-256, so the client
  can revoke early.
- **Keys are visible in Immich.** They appear in the user's API key list named
  like `Kitchen Photo Frame · device grant · expires 2026-11-06 19:00 UTC`, so
  users can revoke them from Immich too. The broker handles that gracefully.
- **Abandoned approvals are cleaned up.** If the user approves but the app
  never collects the key before the device code expires, the key is revoked.
- **Pending requests live in memory; issued grants persist** in SQLite (Node's
  built-in `node:sqlite`, no native dependencies), so expiry survives restarts.

## Try it locally (no Immich needed)

```sh
npm install
npm run mock-immich                           # fake Immich on :2283
IMMICH_URL=http://localhost:2283 npm run dev  # broker on :3080
REVOKE_AFTER=1 npm run demo                   # prints a QR code; approve it in a browser
npm test                                      # end-to-end tests against the mock
```

The mock's fake identity provider signs everyone in as `demo@immich.app`
without asking, so tapping Approve completes straight away.

## Deploy

Before deploying, in your identity provider allow
`<PUBLIC_URL>/device/oauth/callback` as a redirect URI on Immich's OAuth
client, and make sure OAuth is enabled in Immich.

### Kubernetes (Helm)

```sh
helm install device-auth oci://ghcr.io/peddavid/charts/immich-device-auth \
  --version 0.1.0 -n immich \
  --set immich.url=http://immich-server.immich.svc.cluster.local:2283 \
  --set immich.publicUrl=https://photos.example.com \
  --set publicUrl=https://device.photos.example.com \
  --set ingress.enabled=true --set ingress.className=nginx
```

The chart runs one replica with a small PVC for issued grants (kept on
uninstall, since losing it means expired keys are never deleted). See
[`values.yaml`](charts/immich-device-auth/values.yaml) for TLS, TTLs and the
rest.

### Docker

```sh
docker run -d --name immich-device-auth -p 3080:3080 \
  -v immich-device-auth:/data \
  -e IMMICH_URL=http://immich-server:2283 \
  -e IMMICH_PUBLIC_URL=https://photos.example.com \
  -e PUBLIC_URL=https://device.photos.example.com \
  ghcr.io/peddavid/immich-device-auth:0.1.0
```

Images are built for `linux/amd64` and `linux/arm64`. Tags: `0.1.0`, `0.1`,
`main` (latest commit on main), `sha-<commit>`.

### Releasing

Bump the version in `package.json` and `charts/immich-device-auth/Chart.yaml`
(`version` and `appVersion`), then push a matching `vX.Y.Z` tag. CI tests the
code, installs the chart in a kind cluster, and publishes the image and chart.

## API for client apps

**`POST /device/code`** (form-encoded or JSON)

| Field | |
|---|---|
| `client_name` | Shown to the user and used in the key name. 1–60 characters. |
| `scope` | Space-separated Immich permissions, e.g. `album.read asset.view`. Or `permissions` as a JSON array. |
| `ttl` | Requested key lifetime in seconds (min 60). Capped at `MAX_TTL_SECONDS`. |

Returns `device_code`, `user_code`, `verification_uri`,
`verification_uri_complete`, `verification_uri_complete_qr` (an SVG of the QR
code, for apps that can't draw one), `expires_in`, `interval`, `scope`,
`token_ttl`.

**`POST /device/token`** with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
and `device_code`. Standard RFC 8628 errors: `authorization_pending`,
`slow_down`, `access_denied`, `expired_token`. On success:

```json
{
  "access_token": "<Immich API key secret>",
  "token_type": "immich_api_key",
  "expires_in": 3600,
  "expires_at": "2026-11-05T20:00:00.000Z",
  "scope": "album.read asset.view",
  "immich_url": "https://photos.example.com"
}
```

Use `access_token` as the `x-api-key` header against `immich_url`.

**`POST /device/revoke`** with `token=<access_token>` to end access early.
Always answers 200.

## Configuration

| Variable | Default | |
|---|---|---|
| `IMMICH_URL` | required | Immich as reachable from the broker (without `/api`). |
| `IMMICH_PUBLIC_URL` | `IMMICH_URL` | Immich URL handed to apps. |
| `PUBLIC_URL` | `http://localhost:3080` | Broker URL phones open. |
| `PORT` | `3080` | |
| `DATABASE_PATH` | `./data/device-auth.db` | |
| `DEFAULT_TTL_SECONDS` / `MAX_TTL_SECONDS` | 1 hour / 7 days | Key lifetime. |
| `DEVICE_CODE_TTL_SECONDS` | 600 | How long a QR code stays valid. |
| `POLL_INTERVAL_SECONDS` | 5 | |
| `SWEEP_INTERVAL_SECONDS` | 30 | How often expired keys are deleted. |
| `TRUST_PROXY` | `false` | Use `X-Forwarded-For` for rate limiting. |
| `MAX_CODE_LOOKUP_FAILURES` | 20 | Wrong codes per IP per 10 minutes. |
| `IMMICH_NATIVE_KEY_EXPIRY` | `false` | See below. |

### Identity provider setup

The broker asks Immich to start OAuth with
`redirectUri = PUBLIC_URL/device/oauth/callback`. Add that URI to the allowed
redirect URIs of Immich's client in the identity provider, next to the ones
Immich already needs. The broker logs a warning at startup if OAuth is off in
Immich.

## Security notes

- Users never type a password here, but for a moment the broker holds a full
  Immich session (from the OAuth callback) before logging it out. It should be
  deployed by the Immich admin, behind HTTPS, ideally on the same domain as
  Immich. That trust requirement is the main reason this belongs inside Immich
  long-term.
- Device-flow phishing is a known risk with RFC 8628: an attacker starts a
  request and sends the victim the link. The approval page warns about this and
  shows the code so users can compare it with their screen.
- Approval pages can't be framed (`frame-ancestors 'none'`), aren't cached, and
  carry a per-request form token.
- If the broker is down when a key expires, the key keeps working until the
  broker comes back. Only Immich-side expiry fixes that (next section).

## Toward upstream

This would be simpler and safer inside Immich. Each workaround here maps to a
missing feature:

| Workaround in this PoC | What Immich could provide |
|---|---|
| Sweeper deletes keys on expiry; revoker key | `expiresAt` on API keys ([discussion #32325](https://github.com/immich-app/immich/discussions/32325)). Set `IMMICH_NATIVE_KEY_EXPIRY=true` once it exists: the broker sends `expiresAt` on both keys and Immich enforces expiry even if the broker is down. The field name is a guess and may need adjusting. |
| Separate service with its own OAuth round trip, holding a session briefly | A device-authorization endpoint and approval screen in Immich's web app, reusing the session the user already has (and working without OIDC). |
| Forbidden-permission list | A server-defined set of permissions third-party apps may request. |
| Key name carries the client and expiry | "Connected apps" metadata on keys (client name, created via, expiry). |

### Not yet verified against a real Immich

The mock mirrors the Immich v3 API from `@immich/sdk` 3.3.6, but these
behaviours should be confirmed on a live server:

- a key with only `apiKey.delete` can delete itself;
- deleting a nonexistent key returns 400 (`API Key not found`), which the broker
  treats as already deleted;
- `Authorization: Bearer <accessToken>` works for `POST /api-keys` and
  `POST /auth/logout` with the session returned by `POST /oauth/callback`;
- Immich accepts an OAuth `redirectUri` other than its own, and passes the
  PKCE challenge and `state` through as expected.

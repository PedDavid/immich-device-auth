import { createHash, randomBytes } from 'node:crypto';
import { getConnInfo } from '@hono/node-server/conninfo';
import { Hono, type Context } from 'hono';
import QRCode from 'qrcode';
import { FORBIDDEN_PERMISSIONS, KNOWN_PERMISSIONS, type Config } from './config.js';
import { DeviceRequests, formatUserCode, normalizeUserCode, type DeviceRequest } from './devices.js';
import type { GrantService, Sweeper } from './grants.js';
import { ImmichError, type ImmichClient, type LoginResult } from './immich.js';
import { approvePage, enterCodePage, resultPage } from './views.js';

const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const MAX_PERMISSIONS = 64;
const LOOKUP_WINDOW_MS = 10 * 60_000;

type Deps = {
  config: Config;
  immich: ImmichClient;
  grants: GrantService;
  sweeper: Sweeper;
};

/** RFC 6749 §5.2-style error body. */
const oauthError = (c: Context, error: string, description?: string, status: 400 | 401 | 429 = 400) =>
  c.json({ error, ...(description ? { error_description: description } : {}) }, status);

/** Accepts form-encoded (as RFC 8628 specifies) or JSON bodies. */
const readBody = async (c: Context): Promise<Record<string, unknown>> => {
  const type = c.req.header('content-type') ?? '';
  if (type.includes('application/json')) {
    const body = await c.req.json().catch(() => ({}));
    return typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {};
  }
  return (await c.req.parseBody()) as Record<string, unknown>;
};

const str = (value: unknown) => (typeof value === 'string' ? value : undefined);

const parsePermissions = (body: Record<string, unknown>): { permissions: string[] } | { error: string } => {
  let requested: unknown[] = [];
  if (Array.isArray(body.permissions)) requested = body.permissions;
  else if (typeof body.scope === 'string') requested = body.scope.split(/\s+/).filter(Boolean);
  else return { error: 'Provide the permissions to request as `scope` (space-separated) or `permissions` (array).' };

  const permissions = [...new Set(requested.map(String))];
  if (permissions.length === 0) return { error: 'At least one permission is required.' };
  if (permissions.length > MAX_PERMISSIONS) return { error: `At most ${MAX_PERMISSIONS} permissions can be requested.` };

  const unknown = permissions.filter((p) => !KNOWN_PERMISSIONS.has(p));
  if (unknown.length) return { error: `Unknown permissions: ${unknown.join(', ')}` };
  const forbidden = permissions.filter((p) => FORBIDDEN_PERMISSIONS.has(p));
  if (forbidden.length) return { error: `These permissions cannot be granted through device authorization: ${forbidden.join(', ')}` };

  return { permissions };
};

const cleanClientName = (value: unknown) => {
  // Shown to the user and used in the key name: printable characters only.
  const name = String(value ?? '').replace(/[\p{C}]/gu, '').trim();
  return name.length >= 1 && name.length <= 60 ? name : undefined;
};

const pkce = () => {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
};

export const createApp = ({ config, immich, grants, sweeper }: Deps) => {
  const devices = new DeviceRequests((grantId) => {
    grants.revokeSoon(grantId);
    void sweeper.runOnce();
  });
  const lookupFailures = new Map<string, { count: number; resetAt: number }>();

  const clientIp = (c: Context) => {
    if (config.trustProxy) {
      const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim();
      if (forwarded) return forwarded;
    }
    try {
      return getConnInfo(c).remote.address ?? 'unknown';
    } catch {
      return 'unknown';
    }
  };

  const lookupBlocked = (ip: string) => {
    const entry = lookupFailures.get(ip);
    return entry !== undefined && entry.resetAt > Date.now() && entry.count >= config.maxCodeLookupFailures;
  };

  const recordLookupFailure = (ip: string) => {
    const now = Date.now();
    const entry = lookupFailures.get(ip);
    if (!entry || entry.resetAt <= now) lookupFailures.set(ip, { count: 1, resetAt: now + LOOKUP_WINDOW_MS });
    else entry.count++;
  };

  /** Mints the grant with the fresh login, then ends that session so no full-access credential outlives this request. */
  const approve = async (request: DeviceRequest, login: LoginResult) => {
    const session = { kind: 'session' as const, token: login.accessToken };
    try {
      const { grant, secret } = await grants.issue({
        session,
        user: { id: login.userId, email: login.userEmail },
        clientName: request.clientName,
        permissions: request.permissions,
        ttlSeconds: request.ttlSeconds,
      });
      request.status = 'approved';
      request.result = { secret, expiresAt: grant.expiresAt, grantId: grant.id };
    } finally {
      await immich.logout(session).catch(() => {});
    }
  };

  const app = new Hono();

  app.use('*', async (c, next) => {
    await next();
    c.header('Cache-Control', 'no-store');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
  });

  app.get('/healthz', (c) => c.json({ ok: true }));

  // ---- Client-facing endpoints (RFC 8628) ---------------------------------

  app.post('/device/code', async (c) => {
    const body = await readBody(c);
    const clientName = cleanClientName(body.client_name ?? body.client_id);
    if (!clientName) return oauthError(c, 'invalid_request', '`client_name` is required (1 to 60 printable characters).');

    const parsed = parsePermissions(body);
    if ('error' in parsed) return oauthError(c, 'invalid_scope', parsed.error);

    const requestedTtl = Number(body.ttl ?? config.defaultTtl);
    if (!Number.isInteger(requestedTtl) || requestedTtl < 60) {
      return oauthError(c, 'invalid_request', '`ttl` must be a whole number of seconds, at least 60.');
    }
    const ttlSeconds = Math.min(requestedTtl, config.maxTtl);

    const request = devices.create({
      clientName,
      permissions: parsed.permissions,
      ttlSeconds,
      lifetimeSeconds: config.deviceCodeTtl,
      interval: config.pollInterval,
    });
    const userCode = formatUserCode(request.userCode);
    const verificationUri = `${config.publicUrl}/device`;
    const complete = `${verificationUri}?code=${encodeURIComponent(userCode)}`;

    return c.json({
      device_code: request.deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: complete,
      /** Not part of RFC 8628: an SVG QR code of verification_uri_complete, for clients that can't draw one. */
      verification_uri_complete_qr: `${config.publicUrl}/device/qr.svg?code=${encodeURIComponent(userCode)}`,
      expires_in: config.deviceCodeTtl,
      interval: request.interval,
      scope: request.permissions.join(' '),
      token_ttl: ttlSeconds,
    });
  });

  app.post('/device/token', async (c) => {
    const body = await readBody(c);
    if (str(body.grant_type) !== DEVICE_CODE_GRANT) {
      return oauthError(c, 'unsupported_grant_type', `grant_type must be ${DEVICE_CODE_GRANT}`);
    }
    const deviceCode = str(body.device_code);
    if (!deviceCode) return oauthError(c, 'invalid_request', '`device_code` is required.');

    const request = devices.byDevice(deviceCode);
    if (!request) return oauthError(c, 'expired_token', 'The device code expired or was already used. Start again.');

    const now = Date.now();
    const tooSoon = now - request.lastPollAt < request.interval * 1000;
    request.lastPollAt = now;

    if (request.status === 'denied') {
      devices.remove(request);
      return oauthError(c, 'access_denied', 'The user denied the request.');
    }
    if (request.status === 'approved' && request.result) {
      const { secret, expiresAt } = request.result;
      request.status = 'consumed';
      request.result = undefined;
      devices.remove(request);
      return c.json({
        access_token: secret,
        token_type: 'immich_api_key',
        expires_in: Math.max(0, Math.floor((expiresAt - now) / 1000)),
        expires_at: new Date(expiresAt).toISOString(),
        scope: request.permissions.join(' '),
        immich_url: config.immichPublicUrl,
        usage: 'Send as the x-api-key header to the Immich API.',
      });
    }
    if (tooSoon) {
      request.interval += 5; // RFC 8628 §3.5: back off by 5 seconds
      return oauthError(c, 'slow_down', `Poll at most every ${request.interval} seconds.`);
    }
    return oauthError(c, 'authorization_pending');
  });

  /** Early revocation by the client (shaped like RFC 7009: always 200). */
  app.post('/device/revoke', async (c) => {
    const body = await readBody(c);
    const token = str(body.token);
    const grant = token ? grants.findByClientSecret(token) : undefined;
    if (grant && grant.status === 'active') {
      grants.revokeSoon(grant.id);
      await sweeper.runOnce();
    }
    return c.body(null, 200);
  });

  app.get('/device/qr.svg', async (c) => {
    const code = normalizeUserCode(c.req.query('code') ?? '');
    if (!code) return c.text('code is required', 400);
    const url = `${config.publicUrl}/device?code=${encodeURIComponent(formatUserCode(code))}`;
    const svg = await QRCode.toString(url, { type: 'svg', margin: 2, errorCorrectionLevel: 'M' });
    return c.body(svg, 200, { 'content-type': 'image/svg+xml' });
  });

  // ---- User-facing approval pages ----------------------------------------

  app.get('/device', (c) => {
    const code = c.req.query('code');
    if (!code) return c.html(enterCodePage());

    const ip = clientIp(c);
    if (lookupBlocked(ip)) return c.html(enterCodePage('Too many attempts. Wait a few minutes and try again.'), 429);

    const request = devices.byUser(code);
    if (!request || request.status !== 'pending') {
      recordLookupFailure(ip);
      return c.html(enterCodePage('That code is not valid or has expired. Check the code on your device.'), 404);
    }
    return c.html(approvePage(request));
  });

  app.post('/device/deny', async (c) => {
    const body = await c.req.parseBody();
    const request = devices.byUser(str(body.code) ?? '');
    if (!request || request.status !== 'pending' || str(body.form_token) !== request.formToken) {
      return c.html(resultPage('invalid'), 400);
    }
    request.status = 'denied';
    return c.html(resultPage('denied'));
  });

  /**
   * "Approve" on the approval page: the user signs in to Immich through its
   * OAuth/OIDC provider, so their password never reaches this broker.
   */
  app.get('/device/oauth/start', async (c) => {
    const request = devices.byUser(c.req.query('code') ?? '');
    if (!request || request.status !== 'pending' || c.req.query('form_token') !== request.formToken) {
      return c.html(resultPage('invalid'), 400);
    }
    const state = randomBytes(24).toString('base64url');
    const { codeVerifier, codeChallenge } = pkce();
    devices.attachOAuthState(request, state, codeVerifier);
    try {
      const { url } = await immich.startOAuth({
        redirectUri: `${config.publicUrl}/device/oauth/callback`,
        state,
        codeChallenge,
      });
      return c.redirect(url, 302);
    } catch (error) {
      console.error('starting OAuth failed', error);
      return c.html(approvePage(request, { error: 'Could not start sign-in. Is OAuth enabled on this Immich server?' }), 502);
    }
  });

  app.get('/device/oauth/callback', async (c) => {
    const state = c.req.query('state') ?? '';
    const request = devices.byOAuth(state);
    if (!request?.oauth || request.status !== 'pending') return c.html(resultPage('invalid'), 400);

    // The identity provider refused or the user cancelled at the provider.
    if (c.req.query('error')) {
      return c.html(approvePage(request, { error: 'Sign-in was cancelled. You can try again or deny.' }), 400);
    }

    // Immich expects the full callback URL as the identity provider sent it.
    const incoming = new URL(c.req.url);
    const callbackUrl = `${config.publicUrl}/device/oauth/callback${incoming.search}`;
    let login: LoginResult;
    try {
      login = await immich.finishOAuth({ url: callbackUrl, state, codeVerifier: request.oauth.codeVerifier });
    } catch (error) {
      console.error('OAuth sign-in failed', error);
      return c.html(approvePage(request, { error: 'Sign-in failed. Try again.' }), 502);
    }
    try {
      await approve(request, login);
    } catch (error) {
      console.error('issuing grant failed', error);
      const detail = error instanceof ImmichError ? error.message : 'Unexpected error';
      return c.html(approvePage(request, { error: `Immich refused: ${detail}` }), 502);
    }
    return c.html(resultPage('approved'));
  });

  return { app, devices };
};

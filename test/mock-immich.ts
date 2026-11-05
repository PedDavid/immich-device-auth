/**
 * A tiny stand-in for the parts of the Immich API the broker uses, so the flow
 * can be tested and demoed without a real server. It mirrors Immich's
 * behaviour where it matters: unknown body fields are rejected (Immich
 * validates DTOs strictly), API-key auth is limited to the key's permissions,
 * and logged-out sessions stop working.
 *
 * Run standalone with: npm run mock-immich
 * Its fake OAuth provider signs everyone in as demo@immich.app without asking.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { serve, type ServerType } from '@hono/node-server';
import { Hono, type Context } from 'hono';

type Key = { id: string; secret: string; userId: string; name: string; permissions: string[]; expiresAt?: number };

export type MockImmich = {
  url: string;
  keys: Map<string, Key>;
  sessions: Map<string, string>;
  /** Simulate Immich being unreachable for key deletion. */
  failDeletes: boolean;
  close: () => Promise<void>;
};

const USERS = [{ id: 'user-1', email: 'demo@immich.app', name: 'Demo User' }];

export const startMockImmich = async (
  options: { port?: number; nativeExpiry?: boolean; oauth?: boolean } = {},
): Promise<MockImmich> => {
  const oauthEnabled = options.oauth ?? true;
  const keys = new Map<string, Key>();
  const sessions = new Map<string, string>(); // token -> userId
  const oauthCodes = new Map<string, string>(); // code -> userId
  const state = { failDeletes: false };

  const app = new Hono();
  const fail = (c: Context, status: 400 | 401 | 403 | 404 | 503, message: string) =>
    c.json({ message, statusCode: status }, status);

  type Auth = { userId: string; key?: Key };
  const authenticate = (c: Context): Auth | undefined => {
    const bearer = c.req.header('authorization')?.replace(/^Bearer /, '');
    if (bearer && sessions.has(bearer)) return { userId: sessions.get(bearer)! };
    const secret = c.req.header('x-api-key');
    if (secret) {
      const key = [...keys.values()].find((k) => k.secret === secret);
      if (key && (!key.expiresAt || key.expiresAt > Date.now())) return { userId: key.userId, key };
    }
    return undefined;
  };
  const allowed = (auth: Auth, permission: string) =>
    !auth.key || auth.key.permissions.includes('all') || auth.key.permissions.includes(permission);

  const loginResponse = (userId: string) => {
    const user = USERS.find((u) => u.id === userId)!;
    const accessToken = randomBytes(24).toString('hex');
    sessions.set(accessToken, user.id);
    return {
      accessToken,
      userId: user.id,
      userEmail: user.email,
      name: user.name,
      isAdmin: false,
      isOnboarded: true,
      profileImagePath: '',
      shouldChangePassword: false,
    };
  };

  app.get('/api/server/features', (c) => c.json({ oauth: oauthEnabled, oauthAutoLaunch: false, passwordLogin: true }));

  app.post('/api/auth/logout', (c) => {
    const bearer = c.req.header('authorization')?.replace(/^Bearer /, '');
    if (!bearer || !sessions.has(bearer)) return fail(c, 401, 'Authentication required');
    sessions.delete(bearer);
    return c.json({ successful: true, redirectUri: '/auth/login' });
  });

  app.post('/api/api-keys', async (c) => {
    const auth = authenticate(c);
    if (!auth) return fail(c, 401, 'Authentication required');
    if (!allowed(auth, 'apiKey.create')) return fail(c, 403, 'Missing required permission: apiKey.create');
    const body = await c.req.json();
    const extra = Object.keys(body).filter((k) => !['name', 'permissions', ...(options.nativeExpiry ? ['expiresAt'] : [])].includes(k));
    if (extra.length) return fail(c, 400, `property ${extra[0]} should not exist`);
    if (!Array.isArray(body.permissions) || body.permissions.length === 0) return fail(c, 400, 'permissions must be a non-empty array');
    const key: Key = {
      id: randomUUID(),
      secret: randomBytes(24).toString('base64url'),
      userId: auth.userId,
      name: body.name ?? 'API Key',
      permissions: body.permissions,
      expiresAt: body.expiresAt ? Date.parse(body.expiresAt) : undefined,
    };
    keys.set(key.id, key);
    const dto = { id: key.id, name: key.name, permissions: key.permissions, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    return c.json({ ...dto, apiKey: dto, secret: key.secret }, 201);
  });

  app.delete('/api/api-keys/:id', (c) => {
    const auth = authenticate(c);
    if (!auth) return fail(c, 401, 'Authentication required');
    if (!allowed(auth, 'apiKey.delete')) return fail(c, 403, 'Missing required permission: apiKey.delete');
    if (state.failDeletes) return fail(c, 503, 'Service unavailable');
    const key = keys.get(c.req.param('id'));
    if (!key || key.userId !== auth.userId) return fail(c, 400, 'API Key not found');
    keys.delete(key.id);
    return c.body(null, 204);
  });

  app.get('/api/users/me', (c) => {
    const auth = authenticate(c);
    if (!auth) return fail(c, 401, 'Authentication required');
    if (!allowed(auth, 'user.read')) return fail(c, 403, 'Missing required permission: user.read');
    const user = USERS.find((u) => u.id === auth.userId)!;
    return c.json({ id: user.id, email: user.email, name: user.name });
  });

  app.get('/api/albums', (c) => {
    const auth = authenticate(c);
    if (!auth) return fail(c, 401, 'Authentication required');
    if (!allowed(auth, 'album.read')) return fail(c, 403, 'Missing required permission: album.read');
    return c.json([{ id: 'album-1', albumName: 'Holidays', assetCount: 42 }]);
  });

  // Fake OIDC: /api/oauth/authorize points at a fake IdP page that immediately redirects back.
  app.post('/api/oauth/authorize', async (c) => {
    if (!oauthEnabled) return fail(c, 400, 'OAuth is not enabled');
    const { redirectUri, state: oauthState } = await c.req.json();
    const url = new URL('/idp/authorize', c.req.url);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', oauthState);
    return c.json({ url: url.toString() }, 201);
  });

  app.get('/idp/authorize', (c) => {
    const code = randomBytes(16).toString('hex');
    oauthCodes.set(code, USERS[0]!.id);
    const back = new URL(c.req.query('redirect_uri')!);
    back.searchParams.set('code', code);
    back.searchParams.set('state', c.req.query('state')!);
    return c.redirect(back.toString(), 302);
  });

  app.post('/api/oauth/callback', async (c) => {
    const { url } = await c.req.json();
    const code = new URL(url).searchParams.get('code') ?? '';
    const userId = oauthCodes.get(code);
    if (!userId) return fail(c, 401, 'Invalid OAuth code');
    oauthCodes.delete(code);
    return c.json(loginResponse(userId), 201);
  });

  const server: ServerType = await new Promise((resolve) => {
    const s = serve({ fetch: app.fetch, port: options.port ?? 0 }, () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://localhost:${port}`,
    keys,
    sessions,
    get failDeletes() {
      return state.failDeletes;
    },
    set failDeletes(value: boolean) {
      state.failDeletes = value;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const mock = await startMockImmich({ port: Number(process.env.PORT ?? 2283) });
  console.log(`Mock Immich on ${mock.url} (fake OAuth signs in as demo@immich.app)`);
}

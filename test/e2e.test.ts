import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { GrantService, Sweeper } from '../src/grants.js';
import { ImmichClient } from '../src/immich.js';
import { GrantStore } from '../src/store.js';
import { startMockImmich, type MockImmich } from './mock-immich.js';

const PUBLIC_URL = 'http://broker.test';
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

const harness = (mock: MockImmich, overrides: Partial<Config> = {}) => {
  process.env.IMMICH_URL = mock.url;
  process.env.PUBLIC_URL = PUBLIC_URL;
  process.env.DATABASE_PATH = ':memory:';
  const config = { ...loadConfig(), ...overrides };
  const store = new GrantStore(':memory:');
  const immich = new ImmichClient(config.immichApiUrl);
  const grants = new GrantService(config, immich, store);
  const sweeper = new Sweeper(grants, 60_000);
  const { app, devices } = createApp({ config, immich, grants, sweeper });

  const form = (path: string, body: Record<string, string>) =>
    app.request(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

  const requestCode = async (body: Record<string, string> = {}) => {
    const res = await form('/device/code', { client_name: 'Test Frame', scope: 'album.read asset.view', ...body });
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };

  const poll = async (deviceCode: string) => {
    const request = devices.byDevice(deviceCode);
    if (request) request.lastPollAt = 0; // skip the poll interval in tests
    const res = await form('/device/token', { grant_type: DEVICE_CODE_GRANT, device_code: deviceCode });
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };

  /** Opens the approval page like the phone would and returns the approve link and deny form fields. */
  const openApproval = async (verificationUriComplete: string) => {
    const url = new URL(verificationUriComplete);
    const res = await app.request(`${url.pathname}${url.search}`);
    const html = await res.text();
    const field = (name: string) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? '';
    const approveHref = (html.match(/href="(\/device\/oauth\/start[^"]*)"/)?.[1] ?? '').replaceAll('&amp;', '&');
    return { status: res.status, html, code: field('code'), formToken: field('form_token'), approveHref };
  };

  /** Taps Approve, signs in at the (fake) identity provider, and follows the redirect back to the broker. */
  const approve = async (verificationUriComplete: string) => {
    const page = await openApproval(verificationUriComplete);
    const start = await app.request(page.approveHref);
    if (start.status !== 302) return { status: start.status, html: await start.text() };
    const idp = await fetch(start.headers.get('location')!, { redirect: 'manual' });
    const callback = new URL(idp.headers.get('location')!);
    const done = await app.request(`${callback.pathname}${callback.search}`);
    return { status: done.status, html: await done.text(), callback };
  };

  const immichGet = (path: string, apiKey: string) => fetch(`${mock.url}/api${path}`, { headers: { 'x-api-key': apiKey } });

  return { app, config, store, grants, devices, form, requestCode, poll, openApproval, approve, immichGet };
};

describe('device authorization flow', () => {
  let mock: MockImmich;
  before(async () => {
    mock = await startMockImmich();
  });
  after(async () => {
    await mock.close();
  });

  test('approve via OAuth sign-in: client gets a scoped key, session is logged out', async () => {
    const h = harness(mock);
    const { status, json } = await h.requestCode();
    assert.equal(status, 200);
    assert.match(json.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    assert.equal(json.verification_uri, `${PUBLIC_URL}/device`);
    assert.equal(json.interval, 5);

    assert.equal((await h.poll(json.device_code)).json.error, 'authorization_pending');

    const page = await h.openApproval(json.verification_uri_complete);
    assert.equal(page.status, 200);
    assert.match(page.html, /Test Frame/);
    assert.match(page.html, /album/);
    assert.doesNotMatch(page.html, /type="password"/, 'the broker never asks for a password');

    const approved = await h.approve(json.verification_uri_complete);
    assert.equal(approved.status, 200);
    assert.match(approved.html, /All set/);
    assert.equal(approved.callback!.origin + approved.callback!.pathname, `${PUBLIC_URL}/device/oauth/callback`);

    const token = await h.poll(json.device_code);
    assert.equal(token.status, 200);
    assert.equal(token.json.token_type, 'immich_api_key');
    assert.equal(token.json.immich_url, mock.url);
    assert.ok(token.json.expires_in > 3500 && token.json.expires_in <= 3600);
    assert.equal(token.json.scope, 'album.read asset.view');

    // The key works for what was approved, and nothing else.
    assert.equal((await h.immichGet('/albums', token.json.access_token)).status, 200);
    assert.equal((await h.immichGet('/users/me', token.json.access_token)).status, 403);

    // The device code is single-use.
    assert.equal((await h.poll(json.device_code)).json.error, 'expired_token');

    // No full-access session survives the approval.
    assert.equal(mock.sessions.size, 0);

    // Two keys: the client's, and a revoker that can only delete keys.
    const userKeys = [...mock.keys.values()];
    const client = userKeys.find((k) => k.secret === token.json.access_token)!;
    assert.deepEqual(client.permissions, ['album.read', 'asset.view']);
    assert.equal(client.expiresAt, undefined, 'no expiresAt is sent unless native expiry is enabled');
    const revoker = userKeys.find((k) => k.name.includes('revoker'))!;
    assert.deepEqual(revoker.permissions, ['apiKey.delete']);
    mock.keys.clear();
  });

  test('polling too fast gets slow_down and a longer interval', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    const first = await h.form('/device/token', { grant_type: DEVICE_CODE_GRANT, device_code: json.device_code });
    assert.equal(((await first.json()) as any).error, 'authorization_pending');
    const second = await h.form('/device/token', { grant_type: DEVICE_CODE_GRANT, device_code: json.device_code });
    const body = (await second.json()) as any;
    assert.equal(body.error, 'slow_down');
    assert.equal(h.devices.byDevice(json.device_code)?.interval, 10);
  });

  test('deny: client gets access_denied and no key is created', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    const page = await h.openApproval(json.verification_uri_complete);
    const res = await h.form('/device/deny', { code: page.code, form_token: page.formToken });
    assert.match(await res.text(), /Request denied/);
    assert.equal((await h.poll(json.device_code)).json.error, 'access_denied');
    assert.equal(mock.keys.size, 0);
  });

  test('dangerous, unknown or missing permissions are rejected up front', async () => {
    const h = harness(mock);
    for (const scope of ['all', 'apiKey.create', 'album.read session.create', 'adminUser.read', 'pinCode.update']) {
      const { status, json } = await h.requestCode({ scope });
      assert.equal(status, 400, scope);
      assert.equal(json.error, 'invalid_scope', scope);
    }
    assert.equal((await h.requestCode({ scope: 'album.read nope.nope' })).json.error, 'invalid_scope');
    assert.equal((await h.requestCode({ scope: '' })).json.error, 'invalid_scope');
    assert.equal((await h.requestCode({ client_name: '' })).json.error, 'invalid_request');
  });

  test('requested ttl is capped at MAX_TTL_SECONDS', async () => {
    const h = harness(mock, { maxTtl: 600 });
    const { json } = await h.requestCode({ ttl: '999999' });
    assert.equal(json.token_ttl, 600);
  });

  test('a forged approve link or deny form is refused', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    const page = await h.openApproval(json.verification_uri_complete);
    const forgedApprove = await h.app.request(
      `/device/oauth/start?code=${encodeURIComponent(page.code)}&form_token=forged`,
    );
    assert.equal(forgedApprove.status, 400);
    const forgedDeny = await h.form('/device/deny', { code: page.code, form_token: 'forged' });
    assert.equal(forgedDeny.status, 400);
    assert.equal((await h.poll(json.device_code)).json.error, 'authorization_pending');
    assert.equal(mock.keys.size, 0);
  });

  test('cancelling at the identity provider leaves the request pending', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    const page = await h.openApproval(json.verification_uri_complete);
    const start = await h.app.request(page.approveHref);
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cancelled = await h.app.request(`/device/oauth/callback?error=access_denied&state=${encodeURIComponent(state)}`);
    assert.equal(cancelled.status, 400);
    assert.match(await cancelled.text(), /Sign-in was cancelled/);
    assert.equal((await h.poll(json.device_code)).json.error, 'authorization_pending');
    // The user can still approve afterwards.
    assert.match((await h.approve(json.verification_uri_complete)).html, /All set/);
    assert.equal((await h.poll(json.device_code)).status, 200);
    mock.keys.clear();
  });

  test('an unknown OAuth state is refused', async () => {
    const h = harness(mock);
    const res = await h.app.request('/device/oauth/callback?code=x&state=unknown');
    assert.equal(res.status, 400);
  });

  test('unknown codes are rate limited per IP', async () => {
    const h = harness(mock, { maxCodeLookupFailures: 3 });
    for (let i = 0; i < 3; i++) assert.equal((await h.app.request('/device?code=BBBB-BBBB')).status, 404);
    assert.equal((await h.app.request('/device?code=BBBB-BBBB')).status, 429);
  });

  test('expired grants are revoked: client key and revoker are both deleted', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode({ ttl: '60' });
    await h.approve(json.verification_uri_complete);
    const token = await h.poll(json.device_code);
    assert.equal(mock.keys.size, 2);

    await h.grants.sweep(Date.now()); // not expired yet
    assert.equal(mock.keys.size, 2);

    await h.grants.sweep(Date.now() + 61_000);
    assert.equal(mock.keys.size, 0);
    assert.equal((await h.immichGet('/albums', token.json.access_token)).status, 401);
    const grant = h.grants.findByClientSecret(token.json.access_token)!;
    assert.equal(grant.status, 'revoked');
    assert.equal(grant.revokerSecret, null, 'revoker secret is dropped after use');
  });

  test('client can revoke early', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    await h.approve(json.verification_uri_complete);
    const token = await h.poll(json.device_code);
    const res = await h.form('/device/revoke', { token: token.json.access_token });
    assert.equal(res.status, 200);
    assert.equal(mock.keys.size, 0);
    // Unknown tokens get the same answer, so the endpoint can't be used to probe keys.
    assert.equal((await h.form('/device/revoke', { token: 'nope' })).status, 200);
  });

  test('revocation retries while Immich is unavailable', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode({ ttl: '60' });
    await h.approve(json.verification_uri_complete);
    const token = await h.poll(json.device_code);
    const later = Date.now() + 61_000;

    mock.failDeletes = true;
    await h.grants.sweep(later);
    let grant = h.grants.findByClientSecret(token.json.access_token)!;
    assert.equal(grant.status, 'active');
    assert.equal(grant.attempts, 1);
    assert.match(grant.lastError ?? '', /503/);

    mock.failDeletes = false;
    await h.grants.sweep(later); // backoff not elapsed yet
    assert.equal(mock.keys.size, 2);
    await h.grants.sweep(later + 31_000);
    grant = h.grants.findByClientSecret(token.json.access_token)!;
    assert.equal(grant.status, 'revoked');
    assert.equal(mock.keys.size, 0);
  });

  test('a key the user already deleted in Immich still completes revocation', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode({ ttl: '60' });
    await h.approve(json.verification_uri_complete);
    const token = await h.poll(json.device_code);
    const client = [...mock.keys.values()].find((k) => k.secret === token.json.access_token)!;
    mock.keys.delete(client.id);
    await h.grants.sweep(Date.now() + 61_000);
    assert.equal(h.grants.findByClientSecret(token.json.access_token)!.status, 'revoked');
    assert.equal(mock.keys.size, 0);
  });

  test('approved but never collected: the key is revoked when the device code expires', async () => {
    const h = harness(mock, { deviceCodeTtl: 1 });
    const { json } = await h.requestCode();
    await h.approve(json.verification_uri_complete);
    assert.equal(mock.keys.size, 2);
    await new Promise((r) => setTimeout(r, 1100));
    h.devices.prune();
    await new Promise((r) => setTimeout(r, 100)); // the sweep runs asynchronously
    assert.equal(mock.keys.size, 0);
  });

  test('pages are protected against framing and caching', async () => {
    const h = harness(mock);
    const res = await h.app.request('/device');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.match(res.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  test('QR endpoint returns an SVG of the approval link', async () => {
    const h = harness(mock);
    const { json } = await h.requestCode();
    const qr = new URL(json.verification_uri_complete_qr);
    const res = await h.app.request(`${qr.pathname}${qr.search}`);
    assert.equal(res.headers.get('content-type'), 'image/svg+xml');
    assert.match(await res.text(), /^<svg/);
  });
});

describe('Immich without OAuth', () => {
  test('approving shows a clear error instead of signing in', async () => {
    const mock = await startMockImmich({ oauth: false });
    try {
      const h = harness(mock);
      const { json } = await h.requestCode();
      const approved = await h.approve(json.verification_uri_complete);
      assert.equal(approved.status, 502);
      assert.match(approved.html, /Is OAuth enabled on this Immich server/);
      assert.equal(mock.keys.size, 0);
    } finally {
      await mock.close();
    }
  });
});

describe('native key expiry (future Immich, #32325)', () => {
  test('keys are created with expiresAt and Immich-side expiry counts as revoked', async () => {
    const mock = await startMockImmich({ nativeExpiry: true });
    try {
      const h = harness(mock, { nativeKeyExpiry: true });
      const { json } = await h.requestCode({ ttl: '60' });
      await h.approve(json.verification_uri_complete);
      const token = await h.poll(json.device_code);
      for (const key of mock.keys.values()) assert.ok(key.expiresAt, 'every key carries expiresAt');

      // Immich has already expired both keys by the time the sweeper runs.
      for (const key of mock.keys.values()) key.expiresAt = Date.now() - 1;
      await h.grants.sweep(Date.now() + 61_000);
      assert.equal(h.grants.findByClientSecret(token.json.access_token)!.status, 'revoked');
    } finally {
      await mock.close();
    }
  });
});

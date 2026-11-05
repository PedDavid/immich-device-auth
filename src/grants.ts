import { randomUUID } from 'node:crypto';
import type { Config } from './config.js';
import { sha256 } from './devices.js';
import { ImmichError, type Credential, type ImmichClient } from './immich.js';
import type { Grant, GrantStore } from './store.js';

const log = (message: string, extra: Record<string, unknown> = {}) =>
  console.log(JSON.stringify({ time: new Date().toISOString(), message, ...extra }));

const describe = (error: unknown) =>
  error instanceof ImmichError ? `${error.status}: ${error.message}` : error instanceof Error ? error.message : String(error);

/**
 * Mints and revokes the Immich API keys behind each grant.
 *
 * Every grant creates two keys for the approving user:
 * - the client key, with exactly the permissions the user approved;
 * - a revoker key, with only `apiKey.delete`, kept by the broker so it can
 *   delete the client key later without holding a full user session.
 *
 * When Immich supports `expiresAt` on API keys, both keys are also created
 * with it, so Immich enforces expiry even if this broker is down.
 */
export class GrantService {
  constructor(
    private readonly config: Config,
    private readonly immich: ImmichClient,
    private readonly store: GrantStore,
  ) {}

  async issue(params: {
    session: Credential;
    user: { id: string; email: string };
    clientName: string;
    permissions: string[];
    ttlSeconds: number;
  }): Promise<{ grant: Grant; secret: string }> {
    const now = Date.now();
    const expiresAt = now + params.ttlSeconds * 1000;
    const expiresIso = new Date(expiresAt).toISOString();
    const nativeExpiry = this.config.nativeKeyExpiry ? { expiresAt: expiresIso } : {};

    const clientKey = await this.immich.createApiKey(params.session, {
      name: `${params.clientName} · device grant · expires ${expiresIso.slice(0, 16).replace('T', ' ')} UTC`,
      permissions: params.permissions,
      ...nativeExpiry,
    });

    let revoker;
    try {
      revoker = await this.immich.createApiKey(params.session, {
        name: `${params.clientName} · device grant revoker (do not use)`,
        permissions: ['apiKey.delete'],
        ...nativeExpiry,
      });
    } catch (error) {
      // Never hand out a key we could not take back.
      await this.immich.deleteApiKey(params.session, clientKey.id).catch(() => {});
      throw error;
    }

    const grant: Grant = {
      id: randomUUID(),
      userId: params.user.id,
      userEmail: params.user.email,
      clientName: params.clientName,
      permissions: params.permissions,
      apiKeyId: clientKey.id,
      clientKeyHash: sha256(clientKey.secret),
      revokerKeyId: revoker.id,
      revokerSecret: revoker.secret,
      createdAt: now,
      expiresAt,
      status: 'active',
      revokedAt: null,
      attempts: 0,
      nextAttemptAt: expiresAt,
      lastError: null,
    };
    this.store.insert(grant);
    log('grant issued', {
      grantId: grant.id,
      user: grant.userEmail,
      client: grant.clientName,
      permissions: grant.permissions,
      expiresAt: expiresIso,
    });
    return { grant, secret: clientKey.secret };
  }

  /** Early revocation, e.g. the client is done or the request was abandoned. */
  revokeSoon(grantId: string) {
    this.store.expireNow(grantId, Date.now());
  }

  findByClientSecret(secret: string) {
    return this.store.findByClientKeyHash(sha256(secret));
  }

  /** Deletes the keys of every expired grant. Not reentrant: Sweeper makes sure runs never overlap. */
  async sweep(now = Date.now()) {
    for (const grant of this.store.due(now)) {
      await this.revoke(grant, now);
    }
  }

  private async revoke(grant: Grant, now: number) {
    if (!grant.revokerKeyId || !grant.revokerSecret) {
      this.store.markFailed(grant.id, 'no revoker key stored');
      return;
    }
    const revoker: Credential = { kind: 'apiKey', secret: grant.revokerSecret };

    try {
      await this.immich.deleteApiKey(revoker, grant.apiKeyId);
    } catch (error) {
      const status = error instanceof ImmichError ? error.status : 0;
      if (status === 404 || status === 400) {
        // Already gone: the user deleted it in Immich, or Immich expired it natively.
        // (Immich answers 400 "API Key not found" for a key that doesn't exist.)
      } else if (status === 401 && this.config.nativeKeyExpiry) {
        // The revoker itself expired natively, so the client key did too.
      } else if (status === 401 || status === 403) {
        // The revoker was deleted or lost its permission. Retrying cannot help.
        this.store.markFailed(grant.id, `cannot delete client key: ${describe(error)}`);
        log('grant revocation failed permanently', { grantId: grant.id, user: grant.userEmail, error: describe(error) });
        return;
      } else {
        const delay = Math.min(2 ** grant.attempts * 30_000, 60 * 60_000);
        this.store.markRetry(grant.id, describe(error), now + delay);
        log('grant revocation will retry', { grantId: grant.id, error: describe(error), retryInMs: delay });
        return;
      }
    }

    // The revoker deletes itself last. If that fails it can only delete keys, so log and move on.
    try {
      await this.immich.deleteApiKey(revoker, grant.revokerKeyId);
    } catch (error) {
      const status = error instanceof ImmichError ? error.status : 0;
      if (status !== 404 && status !== 400 && status !== 401) {
        log('revoker key could not delete itself; remove it in Immich', {
          grantId: grant.id,
          revokerKeyId: grant.revokerKeyId,
          error: describe(error),
        });
      }
    }

    this.store.markRevoked(grant.id, now);
    log('grant revoked', { grantId: grant.id, user: grant.userEmail, client: grant.clientName });
  }
}

/** Runs GrantService.sweep on an interval, never overlapping. */
export class Sweeper {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;

  constructor(
    private readonly grants: GrantService,
    private readonly intervalMs: number,
  ) {}

  start() {
    this.timer = setInterval(() => void this.runOnce(), this.intervalMs);
    this.timer.unref();
    void this.runOnce();
  }

  runOnce(): Promise<void> {
    this.running ??= this.grants
      .sweep()
      .catch((error) => log('sweep failed', { error: describe(error) }))
      .finally(() => {
        this.running = undefined;
      });
    return this.running;
  }

  async stop() {
    if (this.timer) clearInterval(this.timer);
    await this.running;
  }
}

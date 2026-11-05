import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

/**
 * A grant is an Immich API key the broker minted for a client, plus what the
 * broker needs to delete it when it expires. The client's key secret is never
 * stored, only a hash so the client can revoke early.
 */
export type Grant = {
  id: string;
  userId: string;
  userEmail: string;
  clientName: string;
  permissions: string[];
  apiKeyId: string;
  clientKeyHash: string;
  /** Second key with only `apiKey.delete`, used to remove the client key on expiry. Null with native expiry. */
  revokerKeyId: string | null;
  revokerSecret: string | null;
  createdAt: number;
  expiresAt: number;
  status: 'active' | 'revoked' | 'failed';
  revokedAt: number | null;
  attempts: number;
  nextAttemptAt: number;
  lastError: string | null;
};

type Row = {
  id: string;
  user_id: string;
  user_email: string;
  client_name: string;
  permissions: string;
  api_key_id: string;
  client_key_hash: string;
  revoker_key_id: string | null;
  revoker_secret: string | null;
  created_at: number;
  expires_at: number;
  status: Grant['status'];
  revoked_at: number | null;
  attempts: number;
  next_attempt_at: number;
  last_error: string | null;
};

const fromRow = (row: Row): Grant => ({
  id: row.id,
  userId: row.user_id,
  userEmail: row.user_email,
  clientName: row.client_name,
  permissions: JSON.parse(row.permissions) as string[],
  apiKeyId: row.api_key_id,
  clientKeyHash: row.client_key_hash,
  revokerKeyId: row.revoker_key_id,
  revokerSecret: row.revoker_secret,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
  status: row.status,
  revokedAt: row.revoked_at,
  attempts: row.attempts,
  nextAttemptAt: row.next_attempt_at,
  lastError: row.last_error,
});

export class GrantStore {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        user_email TEXT NOT NULL,
        client_name TEXT NOT NULL,
        permissions TEXT NOT NULL,
        api_key_id TEXT NOT NULL,
        client_key_hash TEXT NOT NULL UNIQUE,
        revoker_key_id TEXT,
        revoker_secret TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        status TEXT NOT NULL,
        revoked_at INTEGER,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL,
        last_error TEXT
      );
      CREATE INDEX IF NOT EXISTS grants_due ON grants (status, expires_at, next_attempt_at);
    `);
  }

  insert(grant: Grant) {
    this.db
      .prepare(
        `INSERT INTO grants (id, user_id, user_email, client_name, permissions, api_key_id, client_key_hash,
           revoker_key_id, revoker_secret, created_at, expires_at, status, revoked_at, attempts, next_attempt_at, last_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        grant.id,
        grant.userId,
        grant.userEmail,
        grant.clientName,
        JSON.stringify(grant.permissions),
        grant.apiKeyId,
        grant.clientKeyHash,
        grant.revokerKeyId,
        grant.revokerSecret,
        grant.createdAt,
        grant.expiresAt,
        grant.status,
        grant.revokedAt,
        grant.attempts,
        grant.nextAttemptAt,
        grant.lastError,
      );
  }

  get(id: string): Grant | undefined {
    const row = this.db.prepare('SELECT * FROM grants WHERE id = ?').get(id) as Row | undefined;
    return row ? fromRow(row) : undefined;
  }

  findByClientKeyHash(hash: string): Grant | undefined {
    const row = this.db.prepare('SELECT * FROM grants WHERE client_key_hash = ?').get(hash) as Row | undefined;
    return row ? fromRow(row) : undefined;
  }

  /** Active grants that have expired and are due for a (re)try. */
  due(now: number): Grant[] {
    const rows = this.db
      .prepare(`SELECT * FROM grants WHERE status = 'active' AND expires_at <= ? AND next_attempt_at <= ? ORDER BY expires_at`)
      .all(now, now) as Row[];
    return rows.map(fromRow);
  }

  /** Brings the expiry forward, used for early revocation by the client. */
  expireNow(id: string, now: number) {
    this.db
      .prepare(`UPDATE grants SET expires_at = MIN(expires_at, ?), next_attempt_at = ? WHERE id = ? AND status = 'active'`)
      .run(now, now, id);
  }

  markRevoked(id: string, now: number) {
    // The revoker secret is useless after this point; drop it.
    this.db
      .prepare(`UPDATE grants SET status = 'revoked', revoked_at = ?, revoker_secret = NULL, last_error = NULL WHERE id = ?`)
      .run(now, id);
  }

  markRetry(id: string, error: string, nextAttemptAt: number) {
    this.db
      .prepare(`UPDATE grants SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?`)
      .run(error, nextAttemptAt, id);
  }

  markFailed(id: string, error: string) {
    this.db
      .prepare(`UPDATE grants SET status = 'failed', attempts = attempts + 1, last_error = ?, revoker_secret = NULL WHERE id = ?`)
      .run(error, id);
  }

  counts(): Record<Grant['status'], number> {
    const rows = this.db.prepare('SELECT status, COUNT(*) AS n FROM grants GROUP BY status').all() as {
      status: Grant['status'];
      n: number;
    }[];
    const result = { active: 0, revoked: 0, failed: 0 };
    for (const row of rows) result[row.status] = row.n;
    return result;
  }

  close() {
    this.db.close();
  }
}

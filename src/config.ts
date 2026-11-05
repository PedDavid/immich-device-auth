import { Permission } from '@immich/sdk';

const env = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
};

const int = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return value;
};

const bool = (name: string, fallback: boolean): boolean => {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
};

const trimSlash = (url: string) => url.replace(/\/+$/, '');

/**
 * Permissions a third-party client may never request through this broker,
 * whatever it asks for. These would let the client escalate (mint more keys,
 * take over sessions, change credentials) or act as an administrator.
 */
export const FORBIDDEN_PERMISSIONS: ReadonlySet<string> = new Set<string>([
  Permission.All,
  ...Object.values(Permission).filter(
    (p) =>
      p.startsWith('apiKey.') ||
      p.startsWith('session.') ||
      p.startsWith('auth.') ||
      p.startsWith('authDevice.') ||
      p.startsWith('pinCode.') ||
      p.startsWith('admin') ||
      p.startsWith('systemConfig.') ||
      p.startsWith('systemMetadata.') ||
      p.startsWith('serverLicense.') ||
      p.startsWith('plugin.') ||
      p.startsWith('workflow.') ||
      p.startsWith('queue') ||
      p.startsWith('job.') ||
      p.startsWith('library.') ||
      p.startsWith('backup.') ||
      p === Permission.Maintenance,
  ),
]);

export const KNOWN_PERMISSIONS: ReadonlySet<string> = new Set<string>(Object.values(Permission));

export type Config = ReturnType<typeof loadConfig>;

export const loadConfig = () => {
  const immichUrl = trimSlash(env('IMMICH_URL'));
  const publicUrl = trimSlash(env('PUBLIC_URL', `http://localhost:${int('PORT', 3080)}`));
  const defaultTtl = int('DEFAULT_TTL_SECONDS', 60 * 60);
  const maxTtl = int('MAX_TTL_SECONDS', 7 * 24 * 60 * 60);
  if (defaultTtl > maxTtl) {
    throw new Error('DEFAULT_TTL_SECONDS cannot be larger than MAX_TTL_SECONDS');
  }

  return {
    port: int('PORT', 3080),
    /** Immich base URL as reachable from this broker, including /api. */
    immichApiUrl: `${immichUrl}/api`,
    /** Immich base URL handed to clients (may differ from the internal one). */
    immichPublicUrl: trimSlash(env('IMMICH_PUBLIC_URL', immichUrl)),
    publicUrl,
    databasePath: env('DATABASE_PATH', './data/device-auth.db'),
    /** How long a device code stays valid while waiting for approval. */
    deviceCodeTtl: int('DEVICE_CODE_TTL_SECONDS', 10 * 60),
    /** Minimum seconds between token polls (RFC 8628 "interval"). */
    pollInterval: int('POLL_INTERVAL_SECONDS', 5),
    defaultTtl,
    maxTtl,
    /** How often expired grants are checked and revoked. */
    sweepInterval: int('SWEEP_INTERVAL_SECONDS', 30),
    /** Offer "Sign in with OAuth" on the approval page (needs an allowlisted redirect URI). */
    oauthEnabled: bool('OAUTH_ENABLED', false),
    /** Read the client IP from X-Forwarded-For (only behind a reverse proxy you control). */
    trustProxy: bool('TRUST_PROXY', false),
    /** Failed code lookups allowed per IP per 10 minutes, to stop guessing user codes. */
    maxCodeLookupFailures: int('MAX_CODE_LOOKUP_FAILURES', 20),
    /** Failed sign-ins allowed per device request before it is cancelled. */
    maxLoginFailures: int('MAX_LOGIN_FAILURES', 5),
    /**
     * Forward-looking switch for when Immich supports expiring API keys
     * (discussion #32325). When on, the broker sends `expiresAt` and lets Immich
     * enforce expiry instead of keeping a revocation key. Off by default because
     * no released Immich version supports it yet.
     */
    nativeKeyExpiry: bool('IMMICH_NATIVE_KEY_EXPIRY', false),
  };
};

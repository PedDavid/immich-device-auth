import { createHash, randomBytes, randomInt } from 'node:crypto';

/** RFC 8628 §6.1: consonants only, so codes can't spell words and are easy to read out. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';
const USER_CODE_LENGTH = 8;

export const newDeviceCode = () => randomBytes(32).toString('base64url');
export const newToken = () => randomBytes(24).toString('base64url');
export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

export const newUserCode = () => {
  let code = '';
  for (let i = 0; i < USER_CODE_LENGTH; i++) code += USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)];
  return code;
};

/** Accepts "bcdf-ghjk", "BCDF GHJK", etc. */
export const normalizeUserCode = (input: string) => input.toUpperCase().replace(/[^A-Z]/g, '');
export const formatUserCode = (code: string) => `${code.slice(0, 4)}-${code.slice(4)}`;

export type DeviceRequest = {
  deviceCode: string;
  userCode: string;
  clientName: string;
  permissions: string[];
  ttlSeconds: number;
  createdAt: number;
  expiresAt: number;
  interval: number;
  lastPollAt: number;
  loginFailures: number;
  status: 'pending' | 'approved' | 'denied' | 'consumed';
  /** Anti-CSRF token embedded in the approval form. */
  formToken: string;
  /** Set on approval, handed to the client on its next poll, then dropped. */
  result?: { secret: string; expiresAt: number; grantId: string };
  oauth?: { state: string; codeVerifier: string };
};

/**
 * Pending device requests live in memory: they last minutes, and if the broker
 * restarts mid-flow the client simply starts again. Only issued grants are
 * persisted.
 */
export class DeviceRequests {
  private readonly byDeviceCode = new Map<string, DeviceRequest>();
  private readonly byUserCode = new Map<string, DeviceRequest>();
  private readonly byOAuthState = new Map<string, DeviceRequest>();

  /**
   * @param onAbandoned called when an approved request expires before the
   * client collected its key, so the broker can revoke that key right away.
   */
  constructor(private readonly onAbandoned: (grantId: string) => void = () => {}) {}

  create(params: { clientName: string; permissions: string[]; ttlSeconds: number; lifetimeSeconds: number; interval: number }) {
    this.prune();
    let userCode = newUserCode();
    while (this.byUserCode.has(userCode)) userCode = newUserCode();

    const now = Date.now();
    const request: DeviceRequest = {
      deviceCode: newDeviceCode(),
      userCode,
      clientName: params.clientName,
      permissions: params.permissions,
      ttlSeconds: params.ttlSeconds,
      createdAt: now,
      expiresAt: now + params.lifetimeSeconds * 1000,
      interval: params.interval,
      lastPollAt: 0,
      loginFailures: 0,
      status: 'pending',
      formToken: newToken(),
    };
    this.byDeviceCode.set(request.deviceCode, request);
    this.byUserCode.set(request.userCode, request);
    return request;
  }

  byDevice(deviceCode: string) {
    return this.live(this.byDeviceCode.get(deviceCode));
  }

  byUser(userCode: string) {
    return this.live(this.byUserCode.get(normalizeUserCode(userCode)));
  }

  attachOAuthState(request: DeviceRequest, state: string, codeVerifier: string) {
    if (request.oauth) this.byOAuthState.delete(request.oauth.state);
    request.oauth = { state, codeVerifier };
    this.byOAuthState.set(state, request);
  }

  byOAuth(state: string) {
    return this.live(this.byOAuthState.get(state));
  }

  remove(request: DeviceRequest) {
    this.byDeviceCode.delete(request.deviceCode);
    this.byUserCode.delete(request.userCode);
    if (request.oauth) this.byOAuthState.delete(request.oauth.state);
  }

  private live(request: DeviceRequest | undefined, now = Date.now()) {
    if (!request) return undefined;
    if (request.expiresAt <= now) {
      this.expire(request);
      return undefined;
    }
    return request;
  }

  private expire(request: DeviceRequest) {
    this.remove(request);
    if (request.status === 'approved' && request.result) {
      const { grantId } = request.result;
      request.result = undefined;
      this.onAbandoned(grantId);
    }
  }

  /** Drops expired requests, including approved ones the client never collected. */
  prune(now = Date.now()) {
    for (const request of [...this.byDeviceCode.values()]) {
      if (request.expiresAt <= now) this.expire(request);
    }
  }
}

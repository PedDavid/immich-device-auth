/**
 * Minimal Immich REST client. Uses plain fetch instead of @immich/sdk's
 * functions because the SDK keeps credentials in a process-wide default, and
 * this broker acts for many users at once.
 */

export type Credential = { kind: 'session'; token: string } | { kind: 'apiKey'; secret: string };

export class ImmichError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
    message: string,
  ) {
    super(message);
  }
}

export type LoginResult = { accessToken: string; userId: string; userEmail: string; name: string };
export type CreatedKey = { id: string; secret: string };

export class ImmichClient {
  constructor(private readonly apiUrl: string) {}

  private async request<T>(
    method: string,
    path: string,
    options: { credential?: Credential; body?: unknown } = {},
  ): Promise<T> {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (options.body !== undefined) headers['content-type'] = 'application/json';
    if (options.credential?.kind === 'session') headers.authorization = `Bearer ${options.credential.token}`;
    if (options.credential?.kind === 'apiKey') headers['x-api-key'] = options.credential.secret;

    const response = await fetch(`${this.apiUrl}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: AbortSignal.timeout(15_000),
    });

    const text = await response.text();
    let body: unknown = undefined;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }

    if (!response.ok) {
      const message =
        typeof body === 'object' && body !== null && 'message' in body
          ? String((body as { message: unknown }).message)
          : `${method} ${path} failed with ${response.status}`;
      throw new ImmichError(response.status, body, message);
    }
    return body as T;
  }

  getFeatures() {
    return this.request<{ oauth: boolean; passwordLogin: boolean }>('GET', '/server/features');
  }

  startOAuth(params: { redirectUri: string; state: string; codeChallenge: string }) {
    return this.request<{ url: string }>('POST', '/oauth/authorize', { body: params });
  }

  finishOAuth(params: { url: string; state: string; codeVerifier: string }) {
    return this.request<LoginResult>('POST', '/oauth/callback', { body: params });
  }

  logout(credential: Credential) {
    return this.request<unknown>('POST', '/auth/logout', { credential });
  }

  async createApiKey(
    credential: Credential,
    params: { name: string; permissions: string[]; expiresAt?: string },
  ): Promise<CreatedKey> {
    const created = await this.request<{ id?: string; secret: string; apiKey?: { id: string } }>(
      'POST',
      '/api-keys',
      { credential, body: params },
    );
    // v3 returns the id both at the top level and under `apiKey`; older servers only under `apiKey`.
    const id = created.id ?? created.apiKey?.id;
    if (!id || !created.secret) {
      throw new ImmichError(502, created, 'Immich returned an API key without an id or secret');
    }
    return { id, secret: created.secret };
  }

  deleteApiKey(credential: Credential, id: string) {
    return this.request<unknown>('DELETE', `/api-keys/${encodeURIComponent(id)}`, { credential });
  }
}

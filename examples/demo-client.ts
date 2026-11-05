/**
 * What a third-party Immich app would do: ask the broker for a code, show it
 * as a QR code, poll until the user approves on their phone, then call Immich
 * with the short-lived key it received.
 *
 *   BROKER_URL=http://localhost:3080 npm run demo
 *   SCOPE="album.read asset.view" TTL=3600 npm run demo
 */
import QRCode from 'qrcode';

const brokerUrl = (process.env.BROKER_URL ?? 'http://localhost:3080').replace(/\/+$/, '');
const scope = process.env.SCOPE ?? 'album.read asset.view';
const ttl = process.env.TTL ?? '3600';
const clientName = process.env.CLIENT_NAME ?? 'Demo Photo Frame';
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

const post = async (path: string, body: Record<string, string>) => {
  const res = await fetch(`${brokerUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as Record<string, any> };
};

const sleep = (seconds: number) => new Promise((resolve) => setTimeout(resolve, seconds * 1000));

const code = await post('/device/code', { client_name: clientName, scope, ttl });
if (code.status !== 200) {
  console.error('Could not start authorization:', code.json);
  process.exit(1);
}

console.log(await QRCode.toString(code.json.verification_uri_complete, { type: 'terminal', small: true }));
console.log(`Scan the QR code with your phone, or open ${code.json.verification_uri}`);
console.log(`and enter the code ${code.json.user_code}\n`);
console.log(`Requesting: ${code.json.scope} for ${code.json.token_ttl}s. Waiting for approval…`);

let interval: number = code.json.interval;
const deadline = Date.now() + code.json.expires_in * 1000;
let token: Record<string, any> | undefined;

while (Date.now() < deadline) {
  await sleep(interval);
  const res = await post('/device/token', { grant_type: DEVICE_CODE_GRANT, device_code: code.json.device_code });
  if (res.status === 200) {
    token = res.json;
    break;
  }
  switch (res.json.error) {
    case 'authorization_pending':
      continue;
    case 'slow_down':
      interval += 5;
      continue;
    case 'access_denied':
      console.error('The request was denied.');
      process.exit(1);
    default:
      console.error('Authorization failed:', res.json);
      process.exit(1);
  }
}
if (!token) {
  console.error('Timed out waiting for approval.');
  process.exit(1);
}

console.log(`\nApproved. Key expires at ${token.expires_at} (${token.scope}).`);

// Use the key like any other Immich API key.
const albums = await fetch(`${token.immich_url}/api/albums`, { headers: { 'x-api-key': token.access_token } });
console.log(`GET /api/albums -> ${albums.status}`);
if (albums.ok) console.log(JSON.stringify(await albums.json(), null, 2));

if (process.env.REVOKE_AFTER === '1') {
  await post('/device/revoke', { token: token.access_token });
  const again = await fetch(`${token.immich_url}/api/albums`, { headers: { 'x-api-key': token.access_token } });
  console.log(`Revoked. GET /api/albums -> ${again.status}`);
}

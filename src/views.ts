import { formatUserCode, type DeviceRequest } from './devices.js';

const escape = (value: string) =>
  value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const STYLE = `
  :root { --bg: #f6f7fb; --card: #fff; --text: #1d1f27; --muted: #5d6170; --line: #e2e4ec;
          --accent: #4250af; --accent-text: #fff; --warn-bg: #fff5e0; --warn-text: #6b4a00; --danger: #b3261e; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #111318; --card: #1b1e26; --text: #e6e7ec; --muted: #a2a6b4; --line: #2c303b;
            --accent: #adc4ff; --accent-text: #0d1a40; --warn-bg: #3a2e12; --warn-text: #f3d48b; --danger: #ffb4ab; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 440px; margin: 0 auto; padding: 24px 16px 48px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 20px; }
  h1 { font-size: 1.3rem; margin: 0 0 4px; }
  p { margin: 8px 0; }
  .muted { color: var(--muted); font-size: .93rem; }
  .code { font: 600 1.4rem ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .08em; }
  .warn { background: var(--warn-bg); color: var(--warn-text); border-radius: 10px; padding: 10px 12px; font-size: .93rem; margin: 14px 0; }
  .error { color: var(--danger); font-weight: 600; }
  ul.perms { list-style: none; padding: 0; margin: 8px 0 0; border-top: 1px solid var(--line); }
  ul.perms li { padding: 8px 0; border-bottom: 1px solid var(--line); }
  ul.perms b { display: block; }
  ul.perms span { color: var(--muted); font-size: .9rem; }
  label { display: block; font-size: .9rem; color: var(--muted); margin: 14px 0 4px; }
  input { width: 100%; padding: 11px 12px; font: inherit; color: var(--text); background: var(--bg);
          border: 1px solid var(--line); border-radius: 10px; }
  input.code-input { text-transform: uppercase; letter-spacing: .12em; font-family: ui-monospace, monospace; }
  .row { display: flex; gap: 10px; margin-top: 18px; }
  button, a.button { flex: 1; display: inline-block; text-align: center; padding: 12px; font: 600 1rem system-ui, sans-serif;
           border-radius: 10px; border: 1px solid var(--line); background: transparent; color: var(--text); cursor: pointer; text-decoration: none; }
  button.primary, a.button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
  .divider { text-align: center; color: var(--muted); font-size: .85rem; margin: 18px 0 0; }
  footer { text-align: center; color: var(--muted); font-size: .8rem; margin-top: 20px; }
`;

const page = (title: string, body: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escape(title)}</title>
<style>${STYLE}</style>
</head>
<body><main>${body}<footer>Immich device authorization</footer></main></body>
</html>`;

const humanTtl = (seconds: number) => {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  return `${seconds} seconds`;
};

/** Groups "asset.read", "asset.view" into "asset: read, view". */
const groupPermissions = (permissions: string[]) => {
  const groups = new Map<string, string[]>();
  for (const permission of permissions) {
    const dot = permission.lastIndexOf('.');
    const resource = dot === -1 ? permission : permission.slice(0, dot);
    const action = dot === -1 ? '' : permission.slice(dot + 1);
    groups.set(resource, [...(groups.get(resource) ?? []), action].filter(Boolean));
  }
  return [...groups.entries()];
};

export const enterCodePage = (error?: string) =>
  page(
    'Connect an app to Immich',
    `<div class="card">
      <h1>Connect an app</h1>
      <p class="muted">Enter the code shown on the device you want to connect.</p>
      ${error ? `<p class="error">${escape(error)}</p>` : ''}
      <form method="get" action="/device">
        <label for="code">Code</label>
        <input id="code" name="code" class="code-input" autocomplete="off" autocapitalize="characters"
               inputmode="text" placeholder="XXXX-XXXX" required autofocus>
        <div class="row"><button class="primary" type="submit">Continue</button></div>
      </form>
    </div>`,
  );

export const approvePage = (request: DeviceRequest, options: { oauthEnabled: boolean; error?: string; email?: string }) => {
  const perms = groupPermissions(request.permissions)
    .map(([resource, actions]) => `<li><b>${escape(resource)}</b><span>${escape(actions.join(', ') || 'full')}</span></li>`)
    .join('');
  const code = formatUserCode(request.userCode);

  return page(
    `Approve ${request.clientName}?`,
    `<div class="card">
      <h1>Allow “${escape(request.clientName)}”?</h1>
      <p class="muted">It is asking for access to your Immich library for <b>${humanTtl(request.ttlSeconds)}</b>.
        Access ends automatically after that.</p>
      <p>Code: <span class="code">${escape(code)}</span></p>
      <div class="warn">Only continue if this code is on a screen in front of you and you just started connecting it.
        Someone who sent you this link could be trying to get into your library.</div>
      <p class="muted">It will be able to:</p>
      <ul class="perms">${perms}</ul>
      ${options.error ? `<p class="error">${escape(options.error)}</p>` : ''}
      <form method="post" action="/device/approve">
        <input type="hidden" name="code" value="${escape(request.userCode)}">
        <input type="hidden" name="form_token" value="${escape(request.formToken)}">
        <label for="email">Immich email</label>
        <input id="email" name="email" type="email" autocomplete="username" value="${escape(options.email ?? '')}" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <div class="row">
          <button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
          <button class="primary" type="submit" name="decision" value="approve">Approve</button>
        </div>
      </form>
      ${
        options.oauthEnabled
          ? `<p class="divider">or</p>
             <div class="row"><a class="button" href="/device/oauth/start?code=${encodeURIComponent(request.userCode)}&amp;form_token=${encodeURIComponent(request.formToken)}">Approve with OAuth sign-in</a></div>`
          : ''
      }
    </div>`,
  );
};

export const resultPage = (kind: 'approved' | 'denied' | 'invalid', detail?: string) => {
  const content: Record<typeof kind, { title: string; text: string }> = {
    approved: { title: 'All set', text: 'The app is connected. You can close this page and go back to your device.' },
    denied: { title: 'Request denied', text: 'The app was not given access. You can close this page.' },
    invalid: { title: 'This code is no longer valid', text: 'It may have expired or already been used. Start again on your device.' },
  };
  const { title, text } = content[kind];
  return page(
    title,
    `<div class="card"><h1>${escape(title)}</h1><p class="muted">${escape(detail ?? text)}</p>
     ${kind === 'invalid' ? '<div class="row"><a class="button" href="/device">Enter a code</a></div>' : ''}</div>`,
  );
};

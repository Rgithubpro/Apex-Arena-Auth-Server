// End-to-end tests against a throw-away local database (no Turso, no network).
// Run with:  npm test
import { generateKeyPairSync, createHash, randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

const dbFile = `/tmp/apex-auth-test-${process.pid}.db`;
process.env.TURSO_DATABASE_URL = `file:${dbFile}`;
process.env.ALLOWED_ORIGINS = 'https://game.example';
process.env.PUBLIC_URL = 'http://localhost:3001';
process.env.GAME_SERVER_SECRET = 'game-secret';
process.env.ADMIN_API_KEY = 'admin-secret';
process.env.USERNAME_RULES_REFRESH_SECONDS = '1';
process.env.GOOGLE_CLIENT_ID = 'google-id';
process.env.GOOGLE_CLIENT_SECRET = 'google-secret';
process.env.GITHUB_CLIENT_ID = 'gh-id';
process.env.GITHUB_CLIENT_SECRET = 'gh-secret';
process.env.ROBLOX_CLIENT_ID = 'rb-id';
process.env.ROBLOX_CLIENT_SECRET = 'rb-secret';
process.env.DISABLED_PROVIDERS = 'roblox';
process.env.STEAM_ENABLED = 'true';
process.env.AUTH_JWT_PRIVATE_KEY = Buffer.from(
  generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }),
).toString('base64');

const { buildApp, loadBans } = await import('../src/server.js');
const { db, initSchema } = await import('../src/db.js');
const { runCleanup } = await import('../src/cleanup.js');

await initSchema();
await loadBans();
const app = await buildApp({ logger: false });
const BASE = process.env.PUBLIC_URL;

// ---------------------------------------------------------------- helpers --
let passed = 0;
let failed = 0;
function check(name, condition, extra) {
  if (condition) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}`, extra === undefined ? '' : JSON.stringify(extra));
  }
}
const section = (title) => console.log(`\n${title}`);
const sha = (s) => createHash('sha256').update(s).digest('base64url');

async function newDevice() {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  return { privateKey, jwk: await exportJWK(publicKey) };
}

async function makeProof(device, method, path, token, overrides = {}) {
  const payload = {
    htm: method,
    htu: BASE + path,
    jti: randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    ...(token ? { ath: sha(token) } : {}),
    ...overrides,
  };
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: device.jwk })
    .sign(device.privateKey);
}

let ipCounter = 0;
async function call(device, method, path, { body, token, query, ip, proof, overrides } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `DPoP ${token}`;
  if (device) headers.dpop = proof ?? (await makeProof(device, method, path, token, overrides));
  const qs = query ? `?${new URLSearchParams(query)}` : '';
  const res = await app.inject({
    method,
    url: path + qs,
    headers,
    payload: body !== undefined ? JSON.stringify(body) : undefined,
    remoteAddress: ip ?? `10.1.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`,
  });
  let json = null;
  try {
    json = res.body ? JSON.parse(res.body) : null;
  } catch {
    /* not json */
  }
  return { status: res.statusCode, body: json, raw: res.body, headers: res.headers };
}

const rowOf = async (sql, args = []) => (await db.execute({ sql, args })).rows[0];

// ------------------------------------------------------------------ tests --
const dev = await newDevice();
const otherDev = await newDevice();

section('health + discovery');
{
  const r = await app.inject({ method: 'GET', url: '/health' });
  check('health ok without touching the database', r.statusCode === 200);
  const p = await call(null, 'GET', '/auth/providers');
  check('only configured, not-disabled providers are listed (Roblox is switched off)', JSON.stringify(p.body.providers) === '["google","github","steam"]', p.body);
  const jwks = await call(null, 'GET', '/.well-known/jwks.json');
  check('jwks publishes a public ES256 key', jwks.body.keys?.[0]?.alg === 'ES256' && !jwks.body.keys[0].d);
}

section('e-mail signup + availability');
let alice;
{
  const free = await call(null, 'GET', '/auth/check', { query: { username: 'Alice_1' } });
  check('free username is available', free.body.available === true, free.body);
  const bad = await call(null, 'GET', '/auth/check', { query: { username: 'a!' } });
  check('invalid username reported', bad.body.available === false && bad.body.reason === 'invalid_username', bad.body);
  const reserved = await call(null, 'GET', '/auth/check', { query: { username: 'Guest123456' } });
  check('Guest + digits is reserved for guests', reserved.body.available === false, reserved.body);

  const noProof = await call(null, 'POST', '/auth/signup', { body: { email: 'a@x.nl', password: 'Password123', username: 'Alice_1' } });
  check('signup without DPoP proof is rejected', noProof.status === 401 && noProof.body.error === 'dpop_required', noProof.body);

  const weak = await call(dev, 'POST', '/auth/signup', { body: { email: 'a@x.nl', password: 'short', username: 'Alice_1' } });
  check('weak password rejected', weak.status === 400 && weak.body.error === 'weak_password', weak.body);

  const ok = await call(dev, 'POST', '/auth/signup', { body: { email: 'Alice@X.nl', password: 'Password123', username: 'Alice_1' } });
  check('signup works', ok.status === 201 && ok.body.access_token && ok.body.refresh_token, ok.body);
  check('new account needs to accept terms', ok.body.user.tos_accepted === false && ok.body.user.method === 'email');
  alice = ok.body;

  const dupEmail = await call(otherDev, 'POST', '/auth/signup', { body: { email: 'alice@x.nl', password: 'Password123', username: 'Alice_2' } });
  check('same e-mail (any case) is refused', dupEmail.status === 409 && dupEmail.body.error === 'email_taken', dupEmail.body);
  const dupName = await call(otherDev, 'POST', '/auth/signup', { body: { email: 'b@x.nl', password: 'Password123', username: 'ALICE_1' } });
  check('same username (any case) is refused', dupName.status === 409 && dupName.body.error === 'username_taken', dupName.body);

  const taken = await call(null, 'GET', '/auth/check', { query: { username: 'alice_1' } });
  check('taken username reported', taken.body.available === false);
  const takenMail = await call(null, 'GET', '/auth/check', { query: { email: 'ALICE@x.nl' } });
  check('taken e-mail reported', takenMail.body.available === false);
}

section('e-mail login');
{
  const wrong = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'nope-nope-1' } });
  check('wrong password -> 401', wrong.status === 401 && wrong.body.error === 'invalid_credentials');
  const unknown = await call(dev, 'POST', '/auth/login', { body: { email: 'ghost@x.nl', password: 'whatever123' } });
  check('unknown e-mail gives the same answer', unknown.status === 401 && unknown.body.error === 'invalid_credentials');
  const ok = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'Password123' } });
  check('login works', ok.status === 200 && ok.body.is_new === false && ok.body.user.username === 'Alice_1', ok.body);
  alice = ok.body;

  // lock-out after repeated failures (per e-mail)
  let last;
  for (let i = 0; i < 9; i++) last = await call(dev, 'POST', '/auth/login', { body: { email: 'locked@x.nl', password: 'bad-bad-bad' } });
  check('repeated failures are locked out (429)', last.status === 429 && last.body.error === 'too_many_attempts', last.body);
}

section('DPoP proof rules');
{
  const proof = await makeProof(dev, 'GET', '/me', alice.access_token);
  const first = await app.inject({ method: 'GET', url: '/me', headers: { authorization: `DPoP ${alice.access_token}`, dpop: proof } });
  check('valid token + proof reaches /me', first.statusCode === 200, first.body);
  const replay = await app.inject({ method: 'GET', url: '/me', headers: { authorization: `DPoP ${alice.access_token}`, dpop: proof } });
  check('replaying the same proof is refused', replay.statusCode === 401 && JSON.parse(replay.body).error === 'dpop_replay', replay.body);

  const stolen = await call(otherDev, 'GET', '/me', { token: alice.access_token });
  check('stolen access token + other key is refused', stolen.status === 401, stolen.body);
  const noAth = await call(dev, 'GET', '/me', { token: alice.access_token, proof: await makeProof(dev, 'GET', '/me', null) });
  check('proof not bound to the token is refused', noAth.status === 401, noAth.body);
  const wrongUrl = await call(dev, 'GET', '/me', { token: alice.access_token, proof: await makeProof(dev, 'GET', '/other', alice.access_token) });
  check('proof for another URL is refused', wrongUrl.status === 401);
  const future = await call(dev, 'GET', '/me', { token: alice.access_token, overrides: { iat: Math.floor(Date.now() / 1000) + 3600 } });
  check('proof from the far future is refused', future.status === 401);
  const old = await call(dev, 'GET', '/me', { token: alice.access_token, overrides: { iat: Math.floor(Date.now() / 1000) - 3600 } });
  check('very old proof is refused', old.status === 401);
}

section('refresh rotation + theft detection');
{
  const r1 = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('refresh works and rotates the token', r1.status === 200 && r1.body.refresh_token !== alice.refresh_token, r1.body);
  const sid = alice.refresh_token.split('.')[0];

  const retry = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('retry of a lost response is tolerated inside the grace window', retry.status === 200, retry.body);

  // the retry rotated again, so r1's token is now stale; push the "previous" timestamp out of the window
  await db.execute({ sql: `UPDATE auth_sessions SET prev_at = prev_at - 1000 WHERE id = ?`, args: [sid] });
  const reuse = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('re-using an old refresh token is refused', reuse.status === 401, reuse.body);
  const afterReuse = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: retry.body.refresh_token } });
  check('...and it kills the whole session (thief and owner both out)', afterReuse.status === 401, afterReuse.body);

  const login = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'Password123' } });
  alice = login.body;
  const wrongKey = await call(otherDev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('valid refresh token + wrong device key is refused', wrongKey.status === 401);
  const afterTheft = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('...and the session is revoked', afterTheft.status === 401, afterTheft.body);

  const junk = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: 'abc.def' } });
  check('garbage refresh token -> 401', junk.status === 401);
  alice = (await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'Password123' } })).body;
}

section('terms, username, password');
{
  const t = await call(dev, 'POST', '/me/terms', { token: alice.access_token, body: {} });
  check('accepting the terms is stored', t.status === 200 && t.body.user.tos_accepted === true, t.body);

  const wrong = await call(dev, 'POST', '/me/password', { token: alice.access_token, body: { current_password: 'nope', new_password: 'NewPassword456' } });
  check('password change needs the current password', wrong.status === 403 && wrong.body.error === 'wrong_password', wrong.body);

  const second = (await call(otherDev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'Password123' } })).body;
  const ok = await call(dev, 'POST', '/me/password', { token: alice.access_token, body: { current_password: 'Password123', new_password: 'NewPassword456' } });
  check('password change works', ok.status === 200, ok.body);
  const other = await call(otherDev, 'POST', '/auth/refresh', { body: { refresh_token: second.refresh_token } });
  check('other devices are logged out after a password change', other.status === 401);
  const here = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('this device stays logged in', here.status === 200, here.body);
  alice = here.body;

  const oldLogin = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'Password123' } });
  check('old password no longer works', oldLogin.status === 401);
  alice = (await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'NewPassword456' } })).body;
}

section('guests (device-bound)');
{
  const guestDev = await newDevice();
  const g1 = await call(guestDev, 'POST', '/auth/guest', { body: { username_hint: 'Guest123456' }, ip: '10.9.9.9' });
  check('guest created, honouring the preview name', g1.status === 201 && g1.body.user.username === 'Guest123456' && g1.body.user.is_guest, g1.body);
  const g2 = await call(guestDev, 'POST', '/auth/guest', { body: {}, ip: '10.9.9.9' });
  check('same device gets the same guest back', g2.status === 200 && g2.body.user.id === g1.body.user.id && g2.body.is_new === false, g2.body);
  const g3 = await call(await newDevice(), 'POST', '/auth/guest', { body: {}, ip: '10.9.9.9' });
  check('a different device gets a different guest', g3.status === 201 && g3.body.user.id !== g1.body.user.id && /^Guest\d{6}$/.test(g3.body.user.username), g3.body);

  const rename = await call(guestDev, 'POST', '/me/username', { token: g2.body.access_token, body: { username: 'Hacker1' } });
  check('guests cannot rename', rename.status === 403);

  const asEmail = await call(guestDev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'NewPassword456' } });
  check('a guest device key can still be used for a normal login (separate account)', asEmail.status === 200 && asEmail.body.user.method === 'email');

  let limited;
  for (let i = 0; i < 5; i++) limited = await call(await newDevice(), 'POST', '/auth/guest', { body: {}, ip: '10.9.9.9' });
  check('guest creation is limited per IP', limited.status === 429 && limited.body.error === 'too_many_guests', limited.body);
}

section('join tickets');
{
  const t = await call(dev, 'POST', '/game/ticket', { token: alice.access_token, body: {} });
  check('ticket issued', t.status === 200 && t.body.ticket, t.body);
  const wrongSecret = await app.inject({ method: 'POST', url: '/game/ticket/redeem', headers: { 'content-type': 'application/json', 'x-game-server-key': 'nope' }, payload: JSON.stringify({ ticket: t.body.ticket }) });
  check('redeem needs the game-server secret', wrongSecret.statusCode === 401);
  const redeem = (ticket) => app.inject({ method: 'POST', url: '/game/ticket/redeem', headers: { 'content-type': 'application/json', 'x-game-server-key': 'game-secret' }, payload: JSON.stringify({ ticket }) });
  const ok = await redeem(t.body.ticket);
  check('redeem returns the player', ok.statusCode === 200 && JSON.parse(ok.body).username === 'Alice_1', ok.body);
  const again = await redeem(t.body.ticket);
  check('a ticket works only once', again.statusCode === 401);

  const t1 = await call(dev, 'POST', '/game/ticket', { token: alice.access_token, body: {} });
  const t2 = await call(dev, 'POST', '/game/ticket', { token: alice.access_token, body: {} });
  check('a newer ticket replaces the older one', (await redeem(t1.body.ticket)).statusCode === 401 && (await redeem(t2.body.ticket)).statusCode === 200);
}

section('bans');
{
  const target = (await call(dev, 'GET', '/me', { token: alice.access_token })).body.user.id;
  const noKey = await app.inject({ method: 'POST', url: '/admin/ban', headers: { 'content-type': 'application/json' }, payload: JSON.stringify({ user_id: target }) });
  check('admin routes need the admin key', noKey.statusCode === 401);

  const ban = await app.inject({ method: 'POST', url: '/admin/ban', headers: { 'content-type': 'application/json', 'x-admin-key': 'admin-secret' }, payload: JSON.stringify({ username: 'alice_1', reason: 'test' }) });
  check('ban works', ban.statusCode === 200, ban.body);

  const me = await call(dev, 'GET', '/me', { token: alice.access_token });
  check('banned player is blocked even with a valid access token', me.status === 403 && me.body.error === 'account_banned', me.body);
  const ref = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: alice.refresh_token } });
  check('banned player cannot refresh', ref.status === 401 || ref.status === 403, ref.body);
  const login = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'NewPassword456' } });
  check('banned player cannot log in', login.status === 403, login.body);
  const bans = await app.inject({ method: 'GET', url: '/game/bans', headers: { 'x-game-server-key': 'game-secret' } });
  check('game server can read the ban list', JSON.parse(bans.body).banned.includes(target));

  const unban = await app.inject({ method: 'POST', url: '/admin/unban', headers: { 'content-type': 'application/json', 'x-admin-key': 'admin-secret' }, payload: JSON.stringify({ user_id: target }) });
  check('unban works', unban.statusCode === 200);
  const back = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'NewPassword456' } });
  check('unbanned player can log in again', back.status === 200, back.body);
  alice = back.body;
}

section('third-party login (Google, with the provider mocked)');
{
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.includes('oauth2.googleapis.com/token')) return json({ access_token: 'provider-token' });
    if (u.includes('openidconnect.googleapis.com')) return json({ sub: 'g-123', email: 'gamer@gmail.com', email_verified: true });
    throw new Error(`unexpected fetch ${u}`);
  };

  const gdev = await newDevice();
  const bad = await call(gdev, 'POST', '/auth/oauth/google/prepare', { body: { return_to: 'https://evil.example/' } });
  check('return address must be on the allow-list', bad.status === 400 && bad.body.error === 'invalid_return_to', bad.body);
  const unconfigured = await call(gdev, 'POST', '/auth/oauth/discord/prepare', { body: { return_to: 'https://game.example/' } });
  check('unconfigured provider -> 503', unconfigured.status === 503, unconfigured.body);

  async function providerLogin(device) {
    const prep = await call(device, 'POST', '/auth/oauth/google/prepare', { body: { return_to: 'https://game.example/Apex-Arena/' } });
    const url = new URL(prep.body.url);
    const state = url.searchParams.get('state');
    const cb = await call(null, 'GET', '/auth/oauth/google/callback', { query: { code: 'provider-code', state } });
    const location = new URL(cb.headers.location);
    return { prep: url, cb, location, code: new URLSearchParams(location.hash.slice(1)).get('auth_code') };
  }

  const flow = await providerLogin(gdev);
  check('prepare builds a PKCE authorize URL', flow.prep.hostname === 'accounts.google.com' && flow.prep.searchParams.get('code_challenge_method') === 'S256');
  check('callback redirects back with the code in the #fragment', flow.cb.status === 302 && flow.location.origin === 'https://game.example' && !!flow.code, flow.cb.headers.location);

  const thief = await call(await newDevice(), 'POST', '/auth/oauth/exchange', { body: { code: flow.code } });
  check('a copied code is useless with a different device key', thief.status === 400, thief.body);

  const flow2 = await providerLogin(gdev);
  const ex = await call(gdev, 'POST', '/auth/oauth/exchange', { body: { code: flow2.code } });
  check('exchange creates the account', ex.status === 201 && ex.body.is_new === true && ex.body.user.method === 'google', ex.body);
  check('new provider player still has to pick a username', ex.body.user.needs_username === true && ex.body.user.username === null);
  const reuse = await call(gdev, 'POST', '/auth/oauth/exchange', { body: { code: flow2.code } });
  check('a code works only once', reuse.status === 400);

  const noName = await call(gdev, 'POST', '/game/ticket', { token: ex.body.access_token, body: {} });
  check('no join ticket before a username is chosen', noName.status === 403 && noName.body.error === 'username_required', noName.body);
  const clash = await call(gdev, 'POST', '/me/username', { token: ex.body.access_token, body: { username: 'Alice_1' } });
  check('username must be unique', clash.status === 409);
  const named = await call(gdev, 'POST', '/me/username', { token: ex.body.access_token, body: { username: 'Gamer_G' } });
  check('username can be chosen', named.status === 200 && named.body.user.username === 'Gamer_G' && !!named.body.access_token, named.body);

  const flow3 = await providerLogin(gdev);
  const again = await call(gdev, 'POST', '/auth/oauth/exchange', { body: { code: flow3.code } });
  check('logging in again finds the same account', again.status === 200 && again.body.is_new === false && again.body.user.username === 'Gamer_G', again.body);

  // delete needs a fresh provider login
  const del1 = await call(gdev, 'DELETE', '/me', { token: again.body.access_token, body: {} });
  check('deleting a provider account needs re-verification', del1.status === 403 && del1.body.error === 'reauth_required', del1.body);
  const prep = await call(gdev, 'POST', '/auth/oauth/google/prepare', { token: again.body.access_token, body: { return_to: 'https://game.example/', purpose: 'reauth' } });
  const cb = await call(null, 'GET', '/auth/oauth/google/callback', { query: { code: 'c', state: new URL(prep.body.url).searchParams.get('state') } });
  const rcode = new URLSearchParams(new URL(cb.headers.location).hash.slice(1)).get('auth_code');
  const rex = await call(gdev, 'POST', '/auth/oauth/exchange', { token: again.body.access_token, body: { code: rcode } });
  check('re-verification succeeds', rex.status === 200 && rex.body.reauth === true, rex.body);
  const del2 = await call(gdev, 'DELETE', '/me', { token: again.body.access_token, body: {} });
  check('account can then be deleted', del2.status === 200 && del2.body.deleted === true, del2.body);
  check('...and is really gone', !(await rowOf(`SELECT 1 AS x FROM auth_users WHERE provider_uid = 'g-123'`)));

  globalThis.fetch = realFetch;
}

section('GitHub, Steam (OpenID 2.0) and provider switches');
{
  const realFetch = globalThis.fetch;
  let steamAnswer = 'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n';
  globalThis.fetch = async (url) => {
    const u = String(url);
    const json = (o) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.startsWith('https://steamcommunity.com/openid/login')) return new Response(steamAnswer, { status: 200 });
    if (u.includes('github.com/login/oauth/access_token')) return json({ access_token: 'gh-token' });
    if (u.includes('api.github.com/user')) return json({ id: 4242, login: 'octo' });
    throw new Error(`unexpected fetch ${u}`);
  };

  async function steamFlow(device, mutate = (q) => q) {
    const prep = await call(device, 'POST', '/auth/oauth/steam/prepare', { body: { return_to: 'https://game.example/Apex-Arena/' } });
    const st = new URL(new URL(prep.body.url).searchParams.get('openid.return_to')).searchParams.get('state');
    const id = 'https://steamcommunity.com/openid/id/76561198000000001';
    const query = mutate({
      state: st, 'openid.ns': 'http://specs.openid.net/auth/2.0', 'openid.mode': 'id_res',
      'openid.op_endpoint': 'https://steamcommunity.com/openid/login', 'openid.claimed_id': id, 'openid.identity': id,
      'openid.return_to': `${BASE}/auth/oauth/steam/callback?state=${st}`,
      'openid.response_nonce': new Date().toISOString().replace(/\.\d+Z$/, 'Z') + 'abc', 'openid.assoc_handle': '1234',
      'openid.signed': 'signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle', 'openid.sig': 'x',
    });
    const cb = await call(null, 'GET', '/auth/oauth/steam/callback', { query });
    return { prep: new URL(prep.body.url), params: new URLSearchParams(new URL(cb.headers.location).hash.slice(1)) };
  }

  const sdev = await newDevice();
  const ok = await steamFlow(sdev);
  check('steam: prepare builds an OpenID URL', ok.prep.hostname === 'steamcommunity.com' && ok.prep.searchParams.get('openid.mode') === 'checkid_setup');
  const code = ok.params.get('auth_code');
  check('steam: a valid answer hands back a one-time code', !!code, ok.params.toString());
  const ex = await call(sdev, 'POST', '/auth/oauth/exchange', { body: { code } });
  check('steam: exchange creates a steam account (no e-mail needed)', ex.status === 201 && ex.body.user.method === 'steam' && ex.body.user.needs_username, ex.body);

  const bad = async (name, mutate) => check(`steam: ${name}`, (await steamFlow(await newDevice(), mutate)).params.get('auth_error') === 'provider_error');
  await bad('wrong return_to is refused', (q) => ({ ...q, 'openid.return_to': `${BASE}/auth/oauth/steam/callback?state=other` }));
  await bad('a forged id outside the signature is refused', (q) => ({ ...q, 'openid.signed': 'signed,op_endpoint,return_to,response_nonce' }));
  await bad('an old nonce is refused', (q) => ({ ...q, 'openid.response_nonce': '2020-01-01T00:00:00Zabc' }));
  await bad('a non-steam id is refused', (q) => ({ ...q, 'openid.claimed_id': 'https://evil.example/id/76561198000000001' }));
  steamAnswer = 'ns:http://specs.openid.net/auth/2.0\nis_valid:false\n';
  await bad('steam saying "not valid" is refused', (q) => q);
  steamAnswer = 'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n';
  const cancelPrep = await call(await newDevice(), 'POST', '/auth/oauth/steam/prepare', { body: { return_to: 'https://game.example/' } });
  const cst = new URL(new URL(cancelPrep.body.url).searchParams.get('openid.return_to')).searchParams.get('state');
  const cancel = await call(null, 'GET', '/auth/oauth/steam/callback', { query: { state: cst, 'openid.mode': 'cancel' } });
  check('steam: cancelling is reported as access_denied', new URLSearchParams(new URL(cancel.headers.location).hash.slice(1)).get('auth_error') === 'access_denied');

  const gdev = await newDevice();
  const gp = await call(gdev, 'POST', '/auth/oauth/github/prepare', { body: { return_to: 'https://game.example/' } });
  const gurl = new URL(gp.body.url);
  check('github: no extra permissions requested, PKCE sent', gurl.hostname === 'github.com' && !gurl.searchParams.has('scope') && gurl.searchParams.get('code_challenge_method') === 'S256', gp.body);
  const gcb = await call(null, 'GET', '/auth/oauth/github/callback', { query: { code: 'c', state: gurl.searchParams.get('state') } });
  const gcode = new URLSearchParams(new URL(gcb.headers.location).hash.slice(1)).get('auth_code');
  const gex = await call(gdev, 'POST', '/auth/oauth/exchange', { body: { code: gcode } });
  check('github: exchange creates a github account', gex.status === 201 && gex.body.user.method === 'github', gex.body);

  const off = await call(await newDevice(), 'POST', '/auth/oauth/roblox/prepare', { body: { return_to: 'https://game.example/' } });
  check('roblox is switched off by DISABLED_PROVIDERS even though its credentials are set', off.status === 503, off.body);

  globalThis.fetch = realFetch;
}

section('delete e-mail account');
{
  const wrong = await call(dev, 'DELETE', '/me', { token: alice.access_token, body: { password: 'nope' } });
  check('needs the password', wrong.status === 403);
  const ok = await call(dev, 'DELETE', '/me', { token: alice.access_token, body: { password: 'NewPassword456' } });
  check('deleted with the right password', ok.status === 200);
  const login = await call(dev, 'POST', '/auth/login', { body: { email: 'alice@x.nl', password: 'NewPassword456' } });
  check('cannot log in afterwards', login.status === 401);
}

section('cleanup (180-day guests) + logout');
{
  const now = Math.floor(Date.now() / 1000);
  const mk = (id, last) => db.execute({ sql: `INSERT INTO auth_users (id, method, provider_uid, username, username_lower, created_at, last_seen_at) VALUES (?, 'guest', ?, ?, ?, ?, ?)`, args: [id, id, id, id.toLowerCase(), last, last] });
  await mk('OldGuest1', now - 200 * 86400);
  await mk('NewGuest1', now - 10 * 86400);
  const result = await runCleanup();
  check('inactive guest removed', result.guestsDeleted === 1 && !(await rowOf(`SELECT 1 AS x FROM auth_users WHERE id = 'OldGuest1'`)), result);
  check('recently active guest kept', !!(await rowOf(`SELECT 1 AS x FROM auth_users WHERE id = 'NewGuest1'`)));

  const u = (await call(dev, 'POST', '/auth/signup', { body: { email: 'bob@x.nl', password: 'Password123', username: 'Bob_1' } })).body;
  const lo = await call(dev, 'POST', '/auth/logout', { body: { refresh_token: u.refresh_token } });
  const after = await call(dev, 'POST', '/auth/refresh', { body: { refresh_token: u.refresh_token } });
  check('logout revokes the session', lo.status === 200 && after.status === 401);
}

section('username filter');
{
  const admin = (method, path, body) =>
    app.inject({
      method,
      url: path,
      headers: { 'x-admin-key': 'admin-secret', ...(body ? { 'content-type': 'application/json' } : {}) },
      payload: body ? JSON.stringify(body) : undefined,
    });
  const verdict = async (name) => (await call(null, 'GET', '/auth/check', { query: { username: name } })).body;
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  check('blocked word hidden with underscores', (await verdict('F_u_c_k_Me')).reason === 'blocked_username');
  check('blocked word stretched out', (await verdict('fuuuuuck22')).reason === 'blocked_username');
  check('number-for-letter tricks', (await verdict('Sh1t_Lord')).reason === 'blocked_username' && (await verdict('5h1t_5how')).reason === 'blocked_username');
  check('built-in reserved names are caught first', (await verdict('Admin')).reason === 'reserved_username');
  check('exact rule from the table blocks "Official" (and Off1c1al)', (await verdict('Official')).reason === 'blocked_username' && (await verdict('Off1c1al')).reason === 'blocked_username');
  check('no false alarms: "Badminton", "Admin_Fan2"', (await verdict('Badminton')).available === true && (await verdict('Admin_Fan2')).available === true);
  check('allow-list lets "Shiitake_Fan" through', (await verdict('Shiitake_Fan')).available === true);

  const su = await call(await newDevice(), 'POST', '/auth/signup', { body: { email: 'bad@x.nl', password: 'Password123', username: 'N4zi_Boy' } });
  check('signup refuses a blocked username', su.status === 400 && su.body.error === 'blocked_username', su.body);

  const carol = await call(await newDevice(), 'POST', '/auth/signup', { body: { email: 'carol@x.nl', password: 'Password123', username: 'Carol_1' } });
  const carolDev = await newDevice();
  const carolLogin = await call(carolDev, 'POST', '/auth/login', { body: { email: 'carol@x.nl', password: 'Password123' } });
  const rename = await call(carolDev, 'POST', '/me/username', { token: carolLogin.body.access_token, body: { username: 'Hitler_Jr' } });
  check('renaming to a blocked username is refused', carol.status === 201 && rename.status === 400 && rename.body.error === 'blocked_username', rename.body);

  const noKey = await app.inject({ method: 'GET', url: '/admin/username-rules' });
  check('rules admin needs the admin key', noKey.statusCode === 401);
  check('invalid regex is refused', (await admin('POST', '/admin/username-rules', { kind: 'regex', pattern: '([' })).statusCode === 400);

  const add = await admin('POST', '/admin/username-rules', { kind: 'contains', pattern: 'zzzbad', note: 'test' });
  const ruleId = JSON.parse(add.body).id;
  check('admin adds a rule and it works at once', add.statusCode === 200 && (await verdict('xZzzBad_1')).reason === 'blocked_username', add.body);
  check('rule tester agrees', JSON.parse((await admin('POST', '/admin/username-rules/test', { username: 'zzzbad99' })).body).allowed === false);
  check('rules can be listed', JSON.parse((await admin('GET', '/admin/username-rules')).body).rules.some((r) => r.id === ruleId));
  const del = await admin('DELETE', `/admin/username-rules/${ruleId}`);
  check('admin removes a rule', JSON.parse(del.body).deleted === 1 && (await verdict('zzzbad99')).available === true);

  const rx = await admin('POST', '/admin/username-rules', { kind: 'regex', pattern: '^x{3}' });
  check('regex rules work', (await verdict('xxxabc')).reason === 'blocked_username' && (await verdict('xxabc')).available === true);
  await admin('DELETE', `/admin/username-rules/${JSON.parse(rx.body).id}`);

  // Edits made straight in the database (e.g. Turso dashboard) go live by themselves.
  await db.execute(`INSERT INTO auth_username_rules (kind, pattern, note) VALUES ('contains', 'dashbad', 'added straight in the database')`);
  await wait(1300);
  check('a rule inserted directly in the table goes live on its own', (await verdict('MyDashBad')).reason === 'blocked_username');
  await db.execute(`UPDATE auth_username_rules SET enabled = 0 WHERE pattern = 'dashbad'`);
  await wait(1300);
  check('disabling a rule in the table goes live too', (await verdict('MyDashBad')).available === true);
}

section('ban reasons, heartbeat, deletion, schema upgrade');
{
  const admin = (method, path, body) =>
    app.inject({
      method,
      url: path,
      headers: { 'x-admin-key': 'admin-secret', ...(body ? { 'content-type': 'application/json' } : {}) },
      payload: body ? JSON.stringify(body) : undefined,
    });
  const dA = await newDevice();
  const dB = await newDevice();

  const dave = await call(dA, 'POST', '/auth/signup', { body: { email: 'dave@x.nl', password: 'Password123', username: 'Dave_1' } });
  const daveB = await call(dB, 'POST', '/auth/login', { body: { email: 'dave@x.nl', password: 'Password123' } });
  const ok = await call(dB, 'GET', '/me/status', { token: daveB.body.access_token });
  check('heartbeat is fine for a normal player', ok.status === 200 && ok.body.ok === true, ok.body);

  const ban = await admin('POST', '/admin/ban', { username: 'dave_1', public_reason: 'Cheating in matches', private_reason: 'seen by mod Sam, clip 1234' });
  check('ban with a public and a private reason', ban.statusCode === 200, ban.body);

  const hb = await call(dB, 'GET', '/me/status', { token: daveB.body.access_token });
  check('the other device learns about the ban at its next heartbeat (public reason only)',
    hb.status === 403 && hb.body.error === 'account_banned' && hb.body.public_reason === 'Cheating in matches' && !JSON.stringify(hb.body).includes('Sam'), hb.body);
  const refresh = await call(dA, 'POST', '/auth/refresh', { body: { refresh_token: dave.body.refresh_token } });
  check('refreshing a banned session says "banned", not a generic error', refresh.status === 403 && refresh.body.public_reason === 'Cheating in matches', refresh.body);
  const login = await call(dA, 'POST', '/auth/login', { body: { email: 'dave@x.nl', password: 'Password123' } });
  check('login shows the public reason and never the private one', login.status === 403 && login.body.public_reason === 'Cheating in matches' && !JSON.stringify(login.body).includes('clip'), login.body);
  const info = JSON.parse((await admin('GET', '/admin/user?username=Dave_1')).body).user;
  check('admin lookup shows both reasons', info.ban_public_reason === 'Cheating in matches' && info.ban_reason.includes('clip 1234'), info);

  await admin('POST', '/admin/unban', { username: 'Dave_1' });
  const cleared = JSON.parse((await admin('GET', '/admin/user?username=Dave_1')).body).user;
  check('unban clears both reasons', cleared.ban_reason === null && cleared.ban_public_reason === null, cleared);

  await admin('POST', '/admin/ban', { username: 'Dave_1', reason: 'old style' });
  const legacy = await call(dA, 'POST', '/auth/login', { body: { email: 'dave@x.nl', password: 'Password123' } });
  const legacyInfo = JSON.parse((await admin('GET', '/admin/user?username=Dave_1')).body).user;
  check('a plain "reason" is private (nothing shown to the player)', legacy.status === 403 && legacy.body.public_reason === null && legacyInfo.ban_reason === 'old style', legacy.body);
  await admin('POST', '/admin/unban', { username: 'Dave_1' });

  // ---- deletion reaches the other devices and the game server
  const eve = await call(dA, 'POST', '/auth/signup', { body: { email: 'eve@x.nl', password: 'Password123', username: 'Eve_1' } });
  const eveB = await call(dB, 'POST', '/auth/login', { body: { email: 'eve@x.nl', password: 'Password123' } });
  const del = await call(dA, 'DELETE', '/me', { token: eve.body.access_token, body: { password: 'Password123' } });
  check('delete works', del.status === 200, del.body);
  const gone = await call(dB, 'GET', '/me/status', { token: eveB.body.access_token });
  check('the other device is told the account is gone', gone.status === 401 && gone.body.error === 'account_deleted', gone.body);
  const noTicket = await call(dB, 'POST', '/game/ticket', { token: eveB.body.access_token, body: {} });
  check('...and cannot get a join ticket any more', noTicket.status === 401, noTicket.body);
  const bans = JSON.parse((await app.inject({ method: 'GET', url: '/game/bans', headers: { 'x-game-server-key': 'game-secret' } })).body);
  check('the game server list includes the deleted account', bans.deleted.includes(eve.body.user.id), bans);

  // ---- game data tables listed in src/user-data.js are wiped in the same transaction
  const { USER_DATA_TABLES } = await import('../src/user-data.js');
  await db.execute(`CREATE TABLE test_player_data (user_id TEXT, score INTEGER)`);
  USER_DATA_TABLES.push({ table: 'test_player_data', column: 'user_id' });
  const fay = await call(dA, 'POST', '/auth/signup', { body: { email: 'fay@x.nl', password: 'Password123', username: 'Fay_1' } });
  await db.execute({ sql: `INSERT INTO test_player_data VALUES (?, 5)`, args: [fay.body.user.id] });
  const delFay = await call(dA, 'DELETE', '/me', { token: fay.body.access_token, body: { password: 'Password123' } });
  const left = await rowOf(`SELECT COUNT(*) AS n FROM test_player_data`);
  check('deleting an account also clears the listed game-data tables', delFay.status === 200 && Number(left.n) === 0, left);
  USER_DATA_TABLES.length = 0;

  // ---- an install on the previous schema version is upgraded in place
  await db.execute(`ALTER TABLE auth_users DROP COLUMN ban_public_reason`);
  await db.execute(`UPDATE auth_meta SET value = '2' WHERE key = 'schema_version'`);
  await initSchema();
  const columns = (await db.execute(`PRAGMA table_info(auth_users)`)).rows.map((r) => r.name);
  const version = await rowOf(`SELECT value FROM auth_meta WHERE key = 'schema_version'`);
  await db.execute(`INSERT INTO auth_users (id, method, provider_uid, created_at, last_seen_at) VALUES ('mig-test', 'twitch', 'tw-1', 1, 1)`);
  check('an install on schema v2 gets the new column and the new version', columns.includes('ban_public_reason') && version.value === '4', { columns, version });
}

section('database cost: every hot query must use an index');
{
  const queries = {
    'login lookup': [`SELECT * FROM auth_users WHERE method = ? AND provider_uid = ?`, ['email', 'x']],
    'username check': [`SELECT 1 FROM auth_users WHERE username_lower = ? LIMIT 1`, ['x']],
    'refresh (join)': [`SELECT s.user_id, u.id FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id WHERE s.id = ?`, ['x']],
    'revoke other devices': [`UPDATE auth_sessions SET revoked_at = 1 WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`, ['x', 'y']],
    'ban list at startup': [`SELECT id, ban_public_reason FROM auth_users WHERE banned = 1`, []],
    'guest cleanup': [`DELETE FROM auth_users WHERE method = 'guest' AND last_seen_at < ? AND banned = 0`, [1]],
    'pending cleanup': [`DELETE FROM auth_users WHERE username IS NULL AND created_at < ? AND banned = 0`, [1]],
    'expired sessions': [`DELETE FROM auth_sessions WHERE expires_at < ?`, [1]],
    'revoked sessions': [`DELETE FROM auth_sessions WHERE revoked_at IS NOT NULL AND revoked_at < ?`, [1]],
    'delete account tokens': [`DELETE FROM auth_email_tokens WHERE user_id = ?`, ['x']],
    'username rules version poll': [`SELECT value FROM auth_meta WHERE key = ?`, ['username_rules_version']],
  };
  for (const [name, [sql, args]] of Object.entries(queries)) {
    const plan = (await db.execute({ sql: `EXPLAIN QUERY PLAN ${sql}`, args })).rows.map((r) => r.detail).join(' | ');
    // Scanning the partial index that only holds banned players is fine: it reads nothing else.
    check(`${name}: ${plan}`, !/\bSCAN\b/.test(plan) || /INDEX auth_users_banned/.test(plan));
  }
}

await app.close();
rmSync(dbFile, { force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

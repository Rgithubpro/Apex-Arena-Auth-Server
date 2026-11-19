import { config } from './config.js';
import { httpError } from './errors.js';

// ---------------------------------------------------------------------------
// Third-party logins. Google, Discord, GitHub, Twitch and Roblox use the OAuth
// authorization-code flow (with PKCE where the provider is known to support it);
// Steam uses OpenID 2.0. Only the provider's stable user id (and the e-mail,
// when given) is kept; provider tokens are thrown away immediately.
//
// To add another standard OAuth provider: add an entry below, add its
// credentials to config.js, and list it in the login page. That is all.
// ---------------------------------------------------------------------------

const STEAM_ENDPOINT = 'https://steamcommunity.com/openid/login';

const DEFINITIONS = {
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scope: 'openid email profile',
    extraParams: { prompt: 'select_account' },
    parse: (u) => ({ uid: u.sub, email: u.email ?? null, emailVerified: u.email_verified === true }),
  },
  discord: {
    authorizeUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userinfoUrl: 'https://discord.com/api/users/@me',
    scope: 'identify email',
    extraParams: { prompt: 'consent' },
    parse: (u) => ({ uid: u.id, email: u.email ?? null, emailVerified: u.verified === true }),
  },
  github: {
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userinfoUrl: 'https://api.github.com/user',
    scope: '', // no extra permissions: the public profile (with its id) is enough
    extraParams: {},
    parse: (u) => ({ uid: u.id, email: u.email ?? null, emailVerified: false }),
  },
  twitch: {
    authorizeUrl: 'https://id.twitch.tv/oauth2/authorize',
    tokenUrl: 'https://id.twitch.tv/oauth2/token',
    userinfoUrl: 'https://id.twitch.tv/oauth2/userinfo',
    scope: 'openid',
    pkce: false, // not documented for Twitch, so it is not sent
    extraParams: { force_verify: 'true' }, // lets the player pick which Twitch account
    parse: (u) => ({ uid: u.sub, email: null, emailVerified: false }),
  },
  roblox: {
    authorizeUrl: 'https://apis.roblox.com/oauth/v1/authorize',
    tokenUrl: 'https://apis.roblox.com/oauth/v1/token',
    userinfoUrl: 'https://apis.roblox.com/oauth/v1/userinfo',
    scope: 'openid',
    extraParams: {},
    parse: (u) => ({ uid: u.sub, email: null, emailVerified: false }),
  },
  steam: { type: 'openid2' }, // no client id/secret; switched on with STEAM_ENABLED=true
};

export const PROVIDER_NAMES = Object.keys(DEFINITIONS);
export const enabledProviders = () => PROVIDER_NAMES.filter((name) => !!config.providers[name]);
export const isOpenIdProvider = (name) => DEFINITIONS[name]?.type === 'openid2';
export const redirectUriFor = (provider) => `${config.publicUrl}/auth/oauth/${provider}/callback`;

export function getProvider(name) {
  const def = DEFINITIONS[name];
  if (!def) throw httpError(404, 'unknown_provider', 'Unknown login provider');
  const creds = config.providers[name];
  if (!creds) throw httpError(503, 'provider_not_configured', `Login with ${name} is not available`);
  return { def, creds };
}

export function buildAuthorizeUrl(name, { state, codeChallenge }) {
  const { def, creds } = getProvider(name);

  if (def.type === 'openid2') {
    const url = new URL(STEAM_ENDPOINT);
    url.search = new URLSearchParams({
      'openid.ns': 'http://specs.openid.net/auth/2.0',
      'openid.mode': 'checkid_setup',
      'openid.return_to': `${redirectUriFor(name)}?state=${state}`, // the state travels inside return_to
      'openid.realm': config.publicUrl,
      'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
      'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
    }).toString();
    return url.toString();
  }

  const params = {
    client_id: creds.clientId,
    redirect_uri: redirectUriFor(name),
    response_type: 'code',
    state,
    ...def.extraParams,
  };
  if (def.scope) params.scope = def.scope;
  if (def.pkce !== false) Object.assign(params, { code_challenge: codeChallenge, code_challenge_method: 'S256' });
  const url = new URL(def.authorizeUrl);
  url.search = new URLSearchParams(params).toString();
  return url.toString();
}

async function fetchJson(url, init) {
  const res = await fetch(url, {
    ...init,
    headers: { Accept: 'application/json', 'User-Agent': 'ApexArena-AuthServer', ...init?.headers },
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = null; }
  if (!res.ok || !body) throw new Error(`provider responded ${res.status}`);
  return body;
}

// Steam signs the whole answer; we check what it says AND ask Steam to confirm the signature.
async function verifySteam(query, state) {
  const get = (k) => (typeof query[k] === 'string' ? query[k] : '');
  const signed = get('openid.signed').split(',');
  const id = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/.exec(get('openid.claimed_id'));
  const nonceTime = Date.parse(get('openid.response_nonce').slice(0, 20));

  if (
    get('openid.mode') !== 'id_res' ||
    get('openid.op_endpoint') !== STEAM_ENDPOINT ||
    get('openid.return_to') !== `${redirectUriFor('steam')}?state=${state}` ||
    !id ||
    !['claimed_id', 'return_to', 'response_nonce'].every((f) => signed.includes(f)) || // these must be covered by the signature
    !nonceTime || Math.abs(Date.now() - nonceTime) > 5 * 60_000
  ) {
    throw new Error('invalid steam response');
  }

  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (key.startsWith('openid.') && typeof value === 'string') form.set(key, value);
  form.set('openid.mode', 'check_authentication');
  const res = await fetch(STEAM_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'ApexArena-AuthServer' },
    body: form.toString(),
    signal: AbortSignal.timeout(10_000),
  });
  if (!/is_valid\s*:\s*true/.test(await res.text())) throw new Error('steam did not confirm the login');
  return { uid: id[1], email: null, emailVerified: false };
}

/** Turns what the provider sent back into the player's verified provider identity. */
export async function fetchProviderIdentity(name, { code, codeVerifier, query, state }) {
  const { def, creds } = getProvider(name);
  if (def.type === 'openid2') return verifySteam(query || {}, state);

  const form = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUriFor(name),
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
  };
  if (def.pkce !== false) form.code_verifier = codeVerifier;

  const tokens = await fetchJson(def.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
  if (!tokens.access_token) throw new Error('provider returned no access token');

  const profile = await fetchJson(def.userinfoUrl, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  const identity = def.parse(profile);
  if (!identity.uid) throw new Error('provider returned no user id');
  return { ...identity, uid: String(identity.uid) };
}

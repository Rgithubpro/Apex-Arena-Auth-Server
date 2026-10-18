import { config } from './config.js';
import { httpError } from './errors.js';

// ---------------------------------------------------------------------------
// Google / Microsoft / Discord, all via the authorization-code flow with PKCE.
// After the provider sends the player back, we swap the code for an access
// token and ask the provider's userinfo endpoint who the player is. Only the
// stable provider id (and the e-mail, when given) is kept; provider tokens
// are thrown away immediately.
// ---------------------------------------------------------------------------

const microsoftTenant = config.providers.microsoft?.tenant ?? 'common';

const DEFINITIONS = {
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scope: 'openid email profile',
    extraParams: { prompt: 'select_account' },
    parse: (u) => ({ uid: u.sub, email: u.email ?? null, emailVerified: u.email_verified === true }),
  },
  microsoft: {
    authorizeUrl: `https://login.microsoftonline.com/${microsoftTenant}/oauth2/v2.0/authorize`,
    tokenUrl: `https://login.microsoftonline.com/${microsoftTenant}/oauth2/v2.0/token`,
    userinfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
    scope: 'openid email profile',
    extraParams: { prompt: 'select_account' },
    parse: (u) => ({ uid: u.sub, email: u.email ?? null, emailVerified: false }),
  },
  discord: {
    authorizeUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userinfoUrl: 'https://discord.com/api/users/@me',
    scope: 'identify email',
    extraParams: { prompt: 'consent' },
    parse: (u) => ({ uid: u.id, email: u.email ?? null, emailVerified: u.verified === true }),
  },
};

export const PROVIDER_NAMES = Object.keys(DEFINITIONS);

export function enabledProviders() {
  return PROVIDER_NAMES.filter((name) => !!config.providers[name]);
}

export const redirectUriFor = (provider) => `${config.publicUrl}/auth/oauth/${provider}/callback`;

export function getProvider(name) {
  const def = DEFINITIONS[name];
  if (!def) throw httpError(404, 'unknown_provider', 'Unknown login provider');
  const creds = config.providers[name];
  if (!creds) throw httpError(503, 'provider_not_configured', `Login with ${name} is not configured on the server`);
  return { def, creds };
}

export function buildAuthorizeUrl(name, { state, codeChallenge }) {
  const { def, creds } = getProvider(name);
  const url = new URL(def.authorizeUrl);
  url.search = new URLSearchParams({
    client_id: creds.clientId,
    redirect_uri: redirectUriFor(name),
    response_type: 'code',
    scope: def.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    ...def.extraParams,
  }).toString();
  return url.toString();
}

async function fetchJson(url, init) {
  const res = await fetch(url, {
    ...init,
    headers: { Accept: 'application/json', 'User-Agent': 'ApexArena-AuthServer (+https://github.com)', ...init?.headers },
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  if (!res.ok || !body) throw new Error(`provider responded ${res.status}`);
  return body;
}

/** Swaps the one-time code for the player's verified provider identity. */
export async function fetchProviderIdentity(name, { code, codeVerifier }) {
  const { def, creds } = getProvider(name);

  const tokens = await fetchJson(def.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUriFor(name),
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      code_verifier: codeVerifier,
    }).toString(),
  });
  if (!tokens.access_token) throw new Error('provider returned no access token');

  const profile = await fetchJson(def.userinfoUrl, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const identity = def.parse(profile);
  if (!identity.uid) throw new Error('provider returned no user id');
  return { ...identity, uid: String(identity.uid) };
}

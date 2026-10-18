import 'dotenv/config';

// ---------------------------------------------------------------------------
// Everything secret or environment-specific comes from environment variables
// (set them in the Render dashboard, or in a local .env file for development).
// Harmless tunables have defaults here and can be overridden by env vars too.
// ---------------------------------------------------------------------------

const isProd = process.env.NODE_ENV === 'production';

function required(name) {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required environment variable: ${name}`);
  return val;
}

function intEnv(name, fallback, min = 0) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isInteger(n) || n < min) throw new Error(`${name} must be an integer >= ${min}`);
  return n;
}

// ---- Origins (the websites allowed to call this server) --------------------
const developmentOrigins = ['http://localhost:5500', 'http://127.0.0.1:5500'];

if (isProd && !process.env.ALLOWED_ORIGINS) {
  throw new Error('ALLOWED_ORIGINS must explicitly list trusted production origins');
}

const rawOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : developmentOrigins;

if (rawOrigins.includes('*')) throw new Error('ALLOWED_ORIGINS must not contain a wildcard');

const allowedOrigins = rawOrigins.map((o) => {
  try {
    const u = new URL(o);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('bad protocol');
    return u.origin; // normalises trailing slashes / paths away
  } catch {
    throw new Error(`ALLOWED_ORIGINS contains an invalid origin: "${o}"`);
  }
});

// ---- Public URL of THIS server (used for OAuth redirect URIs + DPoP checks) -
const publicUrl = (process.env.PUBLIC_URL || (isProd ? '' : 'http://localhost:3001')).replace(/\/+$/, '');
if (!publicUrl) throw new Error('PUBLIC_URL must be set in production (e.g. https://apex-arena-auth-server.onrender.com)');
if (isProd && !publicUrl.startsWith('https://')) throw new Error('PUBLIC_URL must be https in production');

// ---- Token signing key (ES256, PKCS8 PEM; PEM text with \n escapes or base64) -
function parsePem(value) {
  const text = value.trim();
  if (text.includes('BEGIN')) return text.replace(/\\n/g, '\n');
  return Buffer.from(text, 'base64').toString('utf8');
}

// ---- Third-party login providers (each is optional) ------------------------
function oauthProvider(prefix, extra = {}) {
  const clientId = process.env[`${prefix}_CLIENT_ID`];
  const clientSecret = process.env[`${prefix}_CLIENT_SECRET`];
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret, ...extra };
}

const trustProxyHops = intEnv('TRUST_PROXY_HOPS', 0);

const tursoUrl = required('TURSO_DATABASE_URL');

export const config = {
  isProd,
  port: intEnv('PORT', 3001, 1),
  trustProxyHops, // Render puts one proxy in front of the service: set TRUST_PROXY_HOPS=1

  tursoUrl,
  // A local file: database (used by the tests) needs no auth token.
  tursoAuthToken: tursoUrl.startsWith('file:') ? process.env.TURSO_AUTH_TOKEN : required('TURSO_AUTH_TOKEN'),

  allowedOrigins,
  publicUrl,

  signingKeyPem: parsePem(required('AUTH_JWT_PRIVATE_KEY')),

  // Optional secrets: routes that need them fail closed (503) when unset.
  adminApiKey: process.env.ADMIN_API_KEY || undefined,
  gameServerSecret: process.env.GAME_SERVER_SECRET || undefined,

  providers: {
    google: oauthProvider('GOOGLE'),
    microsoft: oauthProvider('MICROSOFT', { tenant: process.env.MICROSOFT_TENANT || 'common' }),
    discord: oauthProvider('DISCORD'),
  },

  // ---- Tokens & sessions ----
  // Longer access tokens = fewer refreshes = fewer database reads/writes.
  accessTtlSeconds: intEnv('ACCESS_TTL_SECONDS', 30 * 60, 60),
  sessionTtlDays: intEnv('SESSION_TTL_DAYS', 60, 1), // sliding: extended on every refresh
  sessionMaxDays: intEnv('SESSION_MAX_DAYS', 180, 1), // hard cap since the login itself
  refreshGraceSeconds: intEnv('REFRESH_GRACE_SECONDS', 10, 0), // retry window if a refresh response got lost
  ticketTtlSeconds: intEnv('TICKET_TTL_SECONDS', 30, 5),

  // ---- Accounts ----
  guestInactivityDays: intEnv('GUEST_INACTIVITY_DAYS', 180, 1),
  guestCreatesPerIpPerDay: intEnv('GUEST_CREATES_PER_IP_PER_DAY', 5, 1),
  pendingAccountDays: intEnv('PENDING_ACCOUNT_DAYS', 7, 1), // provider logins that never picked a username
  usernameRulesRefreshSeconds: intEnv('USERNAME_RULES_REFRESH_SECONDS', 60, 1), // how often the username filter checks for rule changes
  tosVersion: process.env.TOS_VERSION || '1', // bump to make everyone accept new terms
  password: { minLength: 8, maxLength: 128 },

  cleanupIntervalHours: intEnv('CLEANUP_INTERVAL_HOURS', 12, 1),

  // ---- Rate limits (in memory, per IP unless noted) ----
  rateLimits: {
    global: { max: 120, timeWindow: '1 minute' },
    login: { max: 10, timeWindow: '1 minute' },
    signup: { max: 5, timeWindow: '1 minute' },
    guest: { max: 10, timeWindow: '1 minute' },
    refresh: { max: 30, timeWindow: '1 minute' },
    check: { max: 30, timeWindow: '1 minute' },
    oauth: { max: 20, timeWindow: '1 minute' },
    authed: { max: 30, timeWindow: '1 minute' },
    ticket: { max: 20, timeWindow: '1 minute' },
  },
  loginFailures: { max: 8, windowMs: 15 * 60 * 1000 }, // per e-mail address

  maxPayloadBytes: 16 * 1024,
};

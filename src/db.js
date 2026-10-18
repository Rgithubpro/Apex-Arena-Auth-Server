import { createClient } from '@libsql/client';
import { config } from './config.js';

// Same Turso database as the data server, but the auth tables are prefixed
// "auth_" and are never listed in the data server's tables.config.js, so its
// public /data API can never read or write them.
export const db = createClient({
  url: config.tursoUrl,
  authToken: config.tursoAuthToken,
});

export const nowSeconds = () => Math.floor(Date.now() / 1000);

export function isUniqueViolation(err, columnFragment) {
  const msg = String(err?.message || '');
  return /unique|constraint/i.test(msg) && msg.includes(columnFragment);
}

// ---------------------------------------------------------------------------
// Schema. Every lookup the server does is served by an index below, because
// Turso bills by rows SCANNED: a query without a matching index would read
// the whole table. The schema only runs when auth_meta says it is out of date.
// ---------------------------------------------------------------------------
const SCHEMA_VERSION = 2;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS auth_users (
     id TEXT PRIMARY KEY,
     method TEXT NOT NULL CHECK (method IN ('email','google','microsoft','discord','guest')),
     provider_uid TEXT NOT NULL,
     email TEXT,
     email_verified INTEGER NOT NULL DEFAULT 0,
     password_hash TEXT,
     username TEXT,
     username_lower TEXT,
     created_at INTEGER NOT NULL,
     last_seen_at INTEGER NOT NULL,
     tos_version TEXT,
     tos_accepted_at INTEGER,
     banned INTEGER NOT NULL DEFAULT 0,
     ban_reason TEXT
   )`,
  // One account per login method: e-mail address / provider id / guest device key.
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_users_method_uid ON auth_users(method, provider_uid)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_users_username ON auth_users(username_lower)`,
  `CREATE INDEX IF NOT EXISTS auth_users_method_seen ON auth_users(method, last_seen_at)`,
  `CREATE INDEX IF NOT EXISTS auth_users_pending ON auth_users(created_at) WHERE username IS NULL`,
  `CREATE INDEX IF NOT EXISTS auth_users_banned ON auth_users(id) WHERE banned = 1`,

  `CREATE TABLE IF NOT EXISTS auth_sessions (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL,
     device_jkt TEXT NOT NULL,
     current_hash TEXT NOT NULL,
     prev_hash TEXT,
     prev_at INTEGER,
     created_at INTEGER NOT NULL,
     last_used_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     revoked_at INTEGER
   )`,
  `CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS auth_sessions_expires ON auth_sessions(expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_sessions_revoked ON auth_sessions(revoked_at) WHERE revoked_at IS NOT NULL`,

  // Prepared for e-mail verification and password reset (not used yet).
  `CREATE TABLE IF NOT EXISTS auth_email_tokens (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL,
     purpose TEXT NOT NULL CHECK (purpose IN ('verify','reset')),
     token_hash TEXT NOT NULL,
     expires_at INTEGER NOT NULL,
     used_at INTEGER
   )`,
  `CREATE INDEX IF NOT EXISTS auth_email_tokens_hash ON auth_email_tokens(token_hash)`,
  `CREATE INDEX IF NOT EXISTS auth_email_tokens_expires ON auth_email_tokens(expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_email_tokens_user ON auth_email_tokens(user_id)`,

  // Username filter rules (see src/username-filter.js). Edit this table any time:
  // the triggers below bump a version number that the server polls, so changes
  // go live within about a minute, with no redeploy.
  `CREATE TABLE IF NOT EXISTS auth_username_rules (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL CHECK (kind IN ('contains','exact','regex','allow')),
     pattern TEXT NOT NULL,
     note TEXT,
     enabled INTEGER NOT NULL DEFAULT 1,
     created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
   )`,
  `INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('username_rules_version', '1')`,
  `CREATE TRIGGER IF NOT EXISTS auth_username_rules_ins AFTER INSERT ON auth_username_rules
   BEGIN UPDATE auth_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'username_rules_version'; END`,
  `CREATE TRIGGER IF NOT EXISTS auth_username_rules_upd AFTER UPDATE ON auth_username_rules
   BEGIN UPDATE auth_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'username_rules_version'; END`,
  `CREATE TRIGGER IF NOT EXISTS auth_username_rules_del AFTER DELETE ON auth_username_rules
   BEGIN UPDATE auth_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'username_rules_version'; END`,

  // A short starter list: official-looking names and a few obvious words. It is
  // meant to be extended (add rows in Turso or via POST /admin/username-rules).
  // Fixed ids make this safe to run more than once.
  `INSERT OR IGNORE INTO auth_username_rules (id, kind, pattern, note) VALUES
     (1,  'exact',    'admin',         'starter: impersonation'),
     (2,  'exact',    'administrator', 'starter: impersonation'),
     (3,  'exact',    'moderator',     'starter: impersonation'),
     (4,  'exact',    'mod',           'starter: impersonation'),
     (5,  'exact',    'staff',         'starter: impersonation'),
     (6,  'exact',    'support',       'starter: impersonation'),
     (7,  'exact',    'official',      'starter: impersonation'),
     (8,  'exact',    'owner',         'starter: impersonation'),
     (9,  'exact',    'root',          'starter: impersonation'),
     (10, 'exact',    'system',        'starter: impersonation'),
     (11, 'exact',    'apex',          'starter: impersonation'),
     (12, 'contains', 'apexarena',     'starter: impersonation'),
     (13, 'contains', 'moderator',     'starter: impersonation'),
     (14, 'contains', 'fuck',          'starter: profanity'),
     (15, 'contains', 'shit',          'starter: profanity'),
     (16, 'contains', 'bitch',         'starter: profanity'),
     (17, 'contains', 'cunt',          'starter: profanity'),
     (18, 'contains', 'nazi',          'starter: hate'),
     (19, 'contains', 'hitler',        'starter: hate'),
     (20, 'allow',    'shiitake',      'starter: harmless word containing a blocked one')`,
];

export async function initSchema() {
  await db.execute(`CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  const result = await db.execute({ sql: `SELECT value FROM auth_meta WHERE key = ?`, args: ['schema_version'] });
  const current = result.rows.length ? Number(result.rows[0].value) : 0;
  if (current >= SCHEMA_VERSION) return;

  await db.batch(
    [
      ...SCHEMA,
      {
        sql: `INSERT INTO auth_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        args: ['schema_version', String(SCHEMA_VERSION)],
      },
    ],
    'write',
  );
}

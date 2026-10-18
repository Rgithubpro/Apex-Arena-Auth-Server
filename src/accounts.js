import { randomUUID } from 'node:crypto';
import { config } from './config.js';
import { db, nowSeconds } from './db.js';
import { randomToken, sha256, safeEqual } from './crypto.js';
import { httpError } from './errors.js';
import { signAccessToken } from './tokens.js';
import { bannedUsers } from './memory-stores.js';

const DAY = 86_400;

// ---------------------------------------------------------------------------
// Validation (mirrors the rules already used by the welcome page)
// ---------------------------------------------------------------------------
export const USERNAME_RE = /^[a-zA-Z0-9_]{3,16}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESERVED_NAMES = new Set([
  'admin', 'administrator', 'moderator', 'mod', 'support', 'staff', 'system',
  'owner', 'apexarena', 'apex', 'null', 'undefined', 'root', 'guest',
]);

/** Returns the username, or throws a 400. "Guest" + digits is reserved for real guests. */
export function validateUsername(raw, { guest = false } = {}) {
  const name = String(raw ?? '').trim();
  if (!USERNAME_RE.test(name)) {
    throw httpError(400, 'invalid_username', 'Username must be 3-16 characters: letters, numbers, underscore');
  }
  const lower = name.toLowerCase();
  const looksLikeGuest = /^guest\d*$/.test(lower);
  if (RESERVED_NAMES.has(lower) || (looksLikeGuest && !guest)) {
    throw httpError(400, 'reserved_username', 'That username is not allowed');
  }
  return name;
}

export function normalizeEmail(raw) {
  const email = String(raw ?? '').trim().toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email)) throw httpError(400, 'invalid_email', 'Enter a valid e-mail address');
  return email;
}

export function validatePassword(raw) {
  const pw = typeof raw === 'string' ? raw : '';
  if (pw.length < config.password.minLength) {
    throw httpError(400, 'weak_password', `Password must be at least ${config.password.minLength} characters`);
  }
  if (pw.length > config.password.maxLength) {
    throw httpError(400, 'invalid_password', `Password must be at most ${config.password.maxLength} characters`);
  }
  return pw;
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------
export function publicUser(row) {
  return {
    id: row.id,
    username: row.username ?? null,
    method: row.method,
    is_guest: row.method === 'guest',
    needs_username: !row.username,
    tos_accepted: !!row.tos_accepted_at && row.tos_version === config.tosVersion,
    email_verified: !!row.email_verified,
  };
}

export async function findUser(method, providerUid) {
  const rs = await db.execute({
    sql: `SELECT * FROM auth_users WHERE method = ? AND provider_uid = ?`,
    args: [method, providerUid],
  });
  return rs.rows[0];
}

export async function getUserById(id) {
  const rs = await db.execute({ sql: `SELECT * FROM auth_users WHERE id = ?`, args: [id] });
  return rs.rows[0];
}

export async function usernameTaken(lower) {
  const rs = await db.execute({ sql: `SELECT 1 FROM auth_users WHERE username_lower = ? LIMIT 1`, args: [lower] });
  return rs.rows.length > 0;
}

export async function emailTaken(lower) {
  const rs = await db.execute({
    sql: `SELECT 1 FROM auth_users WHERE method = 'email' AND provider_uid = ? LIMIT 1`,
    args: [lower],
  });
  return rs.rows.length > 0;
}

/** Builds the user object + the INSERT statement, so it can run in the same batch as the session insert. */
export function newUser({ method, providerUid, email = null, emailVerified = false, passwordHash = null, username = null }) {
  const now = nowSeconds();
  const user = {
    id: randomUUID(),
    method,
    provider_uid: providerUid,
    email,
    email_verified: emailVerified ? 1 : 0,
    password_hash: passwordHash,
    username,
    username_lower: username ? username.toLowerCase() : null,
    created_at: now,
    last_seen_at: now,
    tos_version: null,
    tos_accepted_at: null,
    banned: 0,
  };
  const stmt = {
    sql: `INSERT INTO auth_users
            (id, method, provider_uid, email, email_verified, password_hash, username, username_lower, created_at, last_seen_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      user.id, user.method, user.provider_uid, user.email, user.email_verified, user.password_hash,
      user.username, user.username_lower, user.created_at, user.last_seen_at,
    ],
  };
  return { user, stmt };
}

// ---------------------------------------------------------------------------
// Sessions. ONE row per logged-in device. A refresh rewrites that row (one
// small UPDATE) instead of adding a new row every time, which keeps database
// writes low. The row stores only hashes of the refresh token.
// ---------------------------------------------------------------------------
const invalidGrant = () => httpError(401, 'invalid_grant', 'Session is no longer valid, please log in again');

function sessionExpiry(createdAt, now) {
  return Math.min(now + config.sessionTtlDays * DAY, createdAt + config.sessionMaxDays * DAY);
}

export async function buildTokens(user, sessionId, refreshToken, jkt) {
  const accessToken = await signAccessToken({
    userId: user.id,
    sessionId,
    jkt,
    username: user.username,
    method: user.method,
  });
  return {
    token_type: 'DPoP',
    access_token: accessToken,
    expires_in: config.accessTtlSeconds,
    refresh_token: refreshToken,
    user: publicUser(user),
  };
}

/**
 * Creates a session for `user` bound to the device key `jkt`.
 * `extra` statements (e.g. the INSERT of a brand-new user) run in the same
 * transaction, so it is one database round trip.
 */
export async function startSession(user, jkt, extra = []) {
  const now = nowSeconds();
  const sessionId = randomToken(12);
  const secret = randomToken(32);

  const statements = [
    ...extra,
    // One live session per user per device: a fresh login replaces the old one.
    {
      sql: `UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND device_jkt = ? AND revoked_at IS NULL`,
      args: [now, user.id, jkt],
    },
    {
      sql: `INSERT INTO auth_sessions (id, user_id, device_jkt, current_hash, created_at, last_used_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [sessionId, user.id, jkt, sha256(secret), now, now, sessionExpiry(now, now)],
    },
  ];
  // Only touch last_seen_at about once a day: it just powers guest-expiry cleanup.
  if (now - Number(user.last_seen_at) > DAY) {
    statements.push({ sql: `UPDATE auth_users SET last_seen_at = ? WHERE id = ?`, args: [now, user.id] });
    user.last_seen_at = now;
  }

  await db.batch(statements, 'write');
  return buildTokens(user, sessionId, `${sessionId}.${secret}`, jkt);
}

export async function revokeSession(sessionId) {
  await db.execute({
    sql: `UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
    args: [nowSeconds(), sessionId],
  });
}

export async function revokeAllSessions(userId, exceptSessionId = null) {
  await db.execute(
    exceptSessionId
      ? { sql: `UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`, args: [nowSeconds(), userId, exceptSessionId] }
      : { sql: `UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, args: [nowSeconds(), userId] },
  );
}

/** Logout: only works if the caller knows the real refresh token. */
export async function logoutWithRefreshToken(refreshToken) {
  const [sessionId, secret] = String(refreshToken || '').split('.');
  if (!sessionId || !secret || secret.length > 100) return;
  const hash = sha256(secret);
  await db.execute({
    sql: `UPDATE auth_sessions SET revoked_at = ?
          WHERE id = ? AND revoked_at IS NULL AND (current_hash = ? OR prev_hash = ?)`,
    args: [nowSeconds(), sessionId, hash, hash],
  });
}

/**
 * Exchanges a refresh token for a new access token + a NEW refresh token.
 * Cost: 2 rows read (session + user via one join) and 1 row written.
 *
 *  - Using an already-replaced token again (outside a short retry window)
 *    means someone copied it, so the whole session is revoked.
 *  - The request must be signed by the same device key the session was
 *    created with; a valid token with the wrong key also revokes the session.
 */
export async function refreshSession(refreshToken, jkt) {
  const parts = String(refreshToken || '').split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1] || parts[1].length > 100) throw invalidGrant();
  const [sessionId, secret] = parts;

  const rs = await db.execute({
    sql: `SELECT s.user_id, s.device_jkt, s.current_hash, s.prev_hash, s.prev_at,
                 s.created_at AS session_created_at, s.expires_at, s.revoked_at,
                 u.id, u.method, u.username, u.email_verified, u.last_seen_at,
                 u.tos_version, u.tos_accepted_at, u.banned
          FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id
          WHERE s.id = ?`,
    args: [sessionId],
  });
  const row = rs.rows[0];
  if (!row) throw invalidGrant();

  const now = nowSeconds();
  if (row.revoked_at || row.expires_at <= now) throw invalidGrant();

  const hash = sha256(secret);
  const isCurrent = safeEqual(hash, row.current_hash);
  const isPrevious = !isCurrent && !!row.prev_hash && safeEqual(hash, row.prev_hash);
  if (!isCurrent && !isPrevious) throw invalidGrant(); // a guess, not a leaked token: nothing to revoke

  if (row.device_jkt !== jkt) {
    await revokeSession(sessionId);
    throw invalidGrant();
  }
  if (row.banned || bannedUsers.has(row.user_id)) {
    await revokeSession(sessionId);
    throw httpError(403, 'account_banned', 'This account is banned');
  }
  if (isPrevious) {
    const withinRetryWindow = row.prev_at && now - row.prev_at <= config.refreshGraceSeconds;
    if (!withinRetryWindow) {
      await revokeSession(sessionId);
      throw invalidGrant();
    }
  }

  const expiresAt = sessionExpiry(row.session_created_at, now);
  if (expiresAt <= now) throw invalidGrant();

  const newSecret = randomToken(32);
  const newHash = sha256(newSecret);

  // Compare-and-swap on the current hash: if two requests race, only one wins.
  const statements = [
    isCurrent
      ? {
          sql: `UPDATE auth_sessions
                SET current_hash = ?, prev_hash = ?, prev_at = ?, last_used_at = ?, expires_at = ?
                WHERE id = ? AND current_hash = ? AND revoked_at IS NULL`,
          args: [newHash, row.current_hash, now, now, expiresAt, sessionId, row.current_hash],
        }
      : {
          // Retry of a response that got lost: hand out a new token, keep the old retry window.
          sql: `UPDATE auth_sessions
                SET current_hash = ?, last_used_at = ?, expires_at = ?
                WHERE id = ? AND current_hash = ? AND revoked_at IS NULL`,
          args: [newHash, now, expiresAt, sessionId, row.current_hash],
        },
  ];
  if (now - Number(row.last_seen_at) > DAY) {
    statements.push({ sql: `UPDATE auth_users SET last_seen_at = ? WHERE id = ?`, args: [now, row.user_id] });
  }

  const results = await db.batch(statements, 'write');
  if (results[0].rowsAffected !== 1) throw invalidGrant();

  return buildTokens(row, sessionId, `${sessionId}.${newSecret}`, jkt);
}

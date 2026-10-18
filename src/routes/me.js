import { config } from '../config.js';
import { db, isUniqueViolation, nowSeconds } from '../db.js';
import { hashPassword, verifyPassword } from '../crypto.js';
import { httpError } from '../errors.js';
import { requireAuth, signAccessToken } from '../tokens.js';
import {
  getUserById, publicUser, validateUsername, validatePassword, revokeAllSessions,
} from '../accounts.js';
import { loginFailures, reauth } from '../memory-stores.js';
import { assertUsernameAllowed } from '../username-filter.js';

const opts = { preHandler: requireAuth, config: { rateLimit: config.rateLimits.authed } };

function body(request) {
  const b = request.body;
  return b && typeof b === 'object' && !Array.isArray(b) ? b : {};
}

async function loadUser(request) {
  const user = await getUserById(request.auth.userId);
  if (!user) throw httpError(404, 'account_not_found', 'This account no longer exists');
  return user;
}

/** Checks the current password, with the same lock-out as the login form. */
async function checkPassword(user, password) {
  const key = `pw:${user.id}`;
  if (loginFailures.blocked(key)) throw httpError(429, 'too_many_attempts', 'Too many failed attempts. Try again later.');
  const ok = typeof password === 'string' && (await verifyPassword(password.slice(0, 256), user.password_hash));
  if (!ok) {
    loginFailures.add(key);
    throw httpError(403, 'wrong_password', 'Wrong password');
  }
  loginFailures.clear(key);
}

export default async function meRoutes(app) {
  app.get('/me', opts, async (request) => {
    const user = await loadUser(request);
    return { user: publicUser(user), email: user.email, created_at: user.created_at };
  });

  // Provider logins pick their username here after the first sign-in.
  app.post('/me/username', opts, async (request) => {
    if (request.auth.method === 'guest') throw httpError(403, 'guest_cannot_rename', 'Guest names cannot be changed');
    const username = validateUsername(body(request).username);
    await assertUsernameAllowed(username);

    let row;
    try {
      const rs = await db.execute({
        sql: `UPDATE auth_users SET username = ?, username_lower = ? WHERE id = ? RETURNING *`,
        args: [username, username.toLowerCase(), request.auth.userId],
      });
      row = rs.rows[0];
    } catch (err) {
      if (isUniqueViolation(err, 'username_lower')) throw httpError(409, 'username_taken', 'Username is taken');
      throw err;
    }
    if (!row) throw httpError(404, 'account_not_found', 'This account no longer exists');

    // The username is baked into the access token, so hand out a fresh one.
    const accessToken = await signAccessToken({
      userId: row.id, sessionId: request.auth.sessionId, jkt: request.auth.jkt, username: row.username, method: row.method,
    });
    return { user: publicUser(row), access_token: accessToken, expires_in: config.accessTtlSeconds };
  });

  // Called when the player ticks "I accept" on the terms screen.
  app.post('/me/terms', opts, async (request) => {
    const rs = await db.execute({
      sql: `UPDATE auth_users SET tos_version = ?, tos_accepted_at = ? WHERE id = ? RETURNING *`,
      args: [config.tosVersion, nowSeconds(), request.auth.userId],
    });
    if (!rs.rows[0]) throw httpError(404, 'account_not_found', 'This account no longer exists');
    return { user: publicUser(rs.rows[0]) };
  });

  // Sensitive: needs the current password again.
  app.post('/me/password', opts, async (request) => {
    const b = body(request);
    const user = await loadUser(request);
    if (user.method !== 'email') throw httpError(400, 'not_password_account', 'This account has no password');

    await checkPassword(user, b.current_password);
    const newPassword = validatePassword(b.new_password);
    const hash = await hashPassword(newPassword);

    await db.batch(
      [
        { sql: `UPDATE auth_users SET password_hash = ? WHERE id = ?`, args: [hash, user.id] },
        // Every other device is logged out; this one stays.
        { sql: `UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`, args: [nowSeconds(), user.id, request.auth.sessionId] },
      ],
      'write',
    );
    return { ok: true };
  });

  app.post('/me/logout-all', opts, async (request) => {
    await revokeAllSessions(request.auth.userId);
    return { ok: true };
  });

  // Sensitive: password again (e-mail), a fresh provider login (Google/...), nothing extra for guests.
  app.delete('/me', opts, async (request) => {
    const user = await loadUser(request);
    if (user.banned) throw httpError(403, 'account_banned', 'Banned accounts cannot be deleted');

    if (user.method === 'email') {
      await checkPassword(user, body(request).password);
    } else if (user.method !== 'guest' && !reauth.get(request.auth.sessionId)) {
      throw httpError(403, 'reauth_required', `Log in with ${user.method} again to confirm`);
    }

    await db.batch(
      [
        { sql: `DELETE FROM auth_sessions WHERE user_id = ?`, args: [user.id] },
        { sql: `DELETE FROM auth_email_tokens WHERE user_id = ?`, args: [user.id] },
        { sql: `DELETE FROM auth_users WHERE id = ?`, args: [user.id] },
      ],
      'write',
    );
    reauth.delete(request.auth.sessionId);
    return { deleted: true };
  });
}

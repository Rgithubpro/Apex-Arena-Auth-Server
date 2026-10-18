import { config } from './config.js';
import { db, nowSeconds } from './db.js';

const DAY = 86_400;

/**
 * Deletes old data. Every statement is a range scan on an index, so when there
 * is nothing to delete it reads (almost) no rows.
 */
export async function runCleanup() {
  const now = nowSeconds();
  const guestCutoff = now - config.guestInactivityDays * DAY;
  const pendingCutoff = now - config.pendingAccountDays * DAY;
  const revokedCutoff = now - 7 * DAY;

  const results = await db.batch(
    [
      // Guests nobody has opened for guestInactivityDays (180 by default).
      { sql: `DELETE FROM auth_sessions WHERE user_id IN (SELECT id FROM auth_users WHERE method = 'guest' AND last_seen_at < ? AND banned = 0)`, args: [guestCutoff] },
      { sql: `DELETE FROM auth_users WHERE method = 'guest' AND last_seen_at < ? AND banned = 0`, args: [guestCutoff] },
      // Provider logins that never picked a username.
      { sql: `DELETE FROM auth_sessions WHERE user_id IN (SELECT id FROM auth_users WHERE username IS NULL AND created_at < ? AND banned = 0)`, args: [pendingCutoff] },
      { sql: `DELETE FROM auth_users WHERE username IS NULL AND created_at < ? AND banned = 0`, args: [pendingCutoff] },
      // Dead sessions and used / expired e-mail tokens.
      { sql: `DELETE FROM auth_sessions WHERE expires_at < ?`, args: [now] },
      { sql: `DELETE FROM auth_sessions WHERE revoked_at IS NOT NULL AND revoked_at < ?`, args: [revokedCutoff] },
      { sql: `DELETE FROM auth_email_tokens WHERE expires_at < ?`, args: [now] },
    ],
    'write',
  );

  return {
    guestsDeleted: results[1].rowsAffected,
    pendingDeleted: results[3].rowsAffected,
    sessionsDeleted: results[0].rowsAffected + results[2].rowsAffected + results[4].rowsAffected + results[5].rowsAffected,
  };
}

/** Runs shortly after boot, then every few hours while the server is awake. */
export function startCleanupLoop(log) {
  const run = () =>
    runCleanup()
      .then((r) => {
        if (r.guestsDeleted || r.pendingDeleted || r.sessionsDeleted) log.info(r, 'cleanup removed old rows');
      })
      .catch((err) => log.error({ err: err.message }, 'cleanup failed'));

  setTimeout(run, 60_000).unref();
  setInterval(run, config.cleanupIntervalHours * 3_600_000).unref();
}

import { config } from '../config.js';
import { db } from '../db.js';
import { httpError } from '../errors.js';
import { requireAdmin } from '../guards.js';
import { bannedUsers, banState } from '../memory-stores.js';
import { getUserById, revokeAllSessions } from '../accounts.js';
import { reloadUsernameRules, usernameRuleStats, isUsernameAllowed } from '../username-filter.js';

const RULE_KINDS = ['contains', 'exact', 'regex', 'allow'];

async function resolveTarget(b) {
  if (typeof b.user_id === 'string') return getUserById(b.user_id);
  if (typeof b.username === 'string') {
    const rs = await db.execute({ sql: `SELECT * FROM auth_users WHERE username_lower = ?`, args: [b.username.toLowerCase()] });
    return rs.rows[0];
  }
  throw httpError(400, 'bad_request', 'Provide user_id or username');
}

export default async function adminRoutes(app) {
  const opts = { preHandler: requireAdmin, config: { rateLimit: config.rateLimits.authed } };

  // ---------------------------------------------------------------- players
  app.get('/admin/user', opts, async (request) => {
    const user = await resolveTarget(request.query || {});
    if (!user) throw httpError(404, 'user_not_found', 'No such user');
    const { password_hash, ...safe } = user; // never hand out the hash
    return { user: safe };
  });

  app.post('/admin/ban', opts, async (request) => {
    const b = request.body || {};
    const user = await resolveTarget(b);
    if (!user) throw httpError(404, 'user_not_found', 'No such user');

    const reason = typeof b.reason === 'string' ? b.reason.slice(0, 200) : null;
    await db.execute({ sql: `UPDATE auth_users SET banned = 1, ban_reason = ? WHERE id = ?`, args: [reason, user.id] });
    await revokeAllSessions(user.id);
    bannedUsers.add(user.id);
    banState.version++;
    return { banned: user.id };
  });

  app.post('/admin/unban', opts, async (request) => {
    const user = await resolveTarget(request.body || {});
    if (!user) throw httpError(404, 'user_not_found', 'No such user');

    await db.execute({ sql: `UPDATE auth_users SET banned = 0, ban_reason = NULL WHERE id = ?`, args: [user.id] });
    bannedUsers.delete(user.id);
    banState.version++;
    return { unbanned: user.id };
  });

  // --------------------------------------------------------- username rules
  // You can also edit the auth_username_rules table directly in Turso: other
  // server instances / this one pick the change up within about a minute.
  app.get('/admin/username-rules', opts, async () => {
    const rs = await db.execute(`SELECT id, kind, pattern, note, enabled, created_at FROM auth_username_rules ORDER BY id`);
    return { rules: rs.rows, loaded: usernameRuleStats() };
  });

  app.post('/admin/username-rules', opts, async (request) => {
    const b = request.body || {};
    const pattern = typeof b.pattern === 'string' ? b.pattern.trim() : '';
    if (!RULE_KINDS.includes(b.kind)) throw httpError(400, 'bad_request', `kind must be one of: ${RULE_KINDS.join(', ')}`);
    if (!pattern || pattern.length > 100) throw httpError(400, 'bad_request', 'pattern must be 1-100 characters');
    if (b.kind === 'regex') {
      try {
        new RegExp(pattern, 'i');
      } catch {
        throw httpError(400, 'bad_request', 'pattern is not a valid regular expression');
      }
    }
    const note = typeof b.note === 'string' ? b.note.slice(0, 200) : null;

    const rs = await db.execute({
      sql: `INSERT INTO auth_username_rules (kind, pattern, note) VALUES (?, ?, ?) RETURNING id`,
      args: [b.kind, pattern, note],
    });
    await reloadUsernameRules(); // takes effect on this server immediately
    return { id: Number(rs.rows[0].id) };
  });

  app.delete('/admin/username-rules/:id', opts, async (request) => {
    const id = Number(request.params.id);
    if (!Number.isInteger(id)) throw httpError(400, 'bad_request', 'Invalid rule id');
    const rs = await db.execute({ sql: `DELETE FROM auth_username_rules WHERE id = ?`, args: [id] });
    await reloadUsernameRules();
    return { deleted: rs.rowsAffected };
  });

  // Handy for trying a rule out before telling anyone: is this name allowed right now?
  app.post('/admin/username-rules/test', opts, async (request) => {
    const username = request.body?.username;
    if (typeof username !== 'string') throw httpError(400, 'bad_request', 'Provide username');
    return { allowed: await isUsernameAllowed(username) };
  });
}

import { config } from '../config.js';
import { randomToken } from '../crypto.js';
import { httpError } from '../errors.js';
import { requireGameServer } from '../guards.js';
import { jwks, requireAuth } from '../tokens.js';
import { tickets, ticketOfUser, bannedUsers, banState } from '../memory-stores.js';

export default async function gameRoutes(app) {
  // Public key set: the game server can verify access tokens by itself with this.
  app.get('/.well-known/jwks.json', { config: { rateLimit: config.rateLimits.check } }, async (request, reply) => {
    reply.header('Cache-Control', 'public, max-age=3600');
    return jwks;
  });

  // -------------------------------------------------------------------------
  // Join tickets. The browser trades its access token for a single-use ticket
  // that lives ~30 seconds, and shows only that ticket to the game server.
  // The long-lived tokens never leave the browser <-> auth server connection.
  // Tickets live in memory: issuing and redeeming one costs no database access.
  // -------------------------------------------------------------------------
  app.post('/game/ticket', { preHandler: requireAuth, config: { rateLimit: config.rateLimits.ticket } }, async (request) => {
    const { userId, username, method, sessionId } = request.auth;
    if (!username) throw httpError(403, 'username_required', 'Choose a username first');

    const previous = ticketOfUser.get(userId);
    if (previous) tickets.delete(previous); // only the newest ticket per player is valid

    const ticket = randomToken(24);
    tickets.set(ticket, { userId, username, method, sessionId });
    ticketOfUser.set(userId, ticket);
    return { ticket, expires_in: config.ticketTtlSeconds };
  });

  // Called by the GAME SERVER (never by browsers) when a player tries to join.
  app.post('/game/ticket/redeem', { preHandler: requireGameServer, config: { rateLimit: false } }, async (request) => {
    const ticketId = request.body?.ticket;
    const ticket = typeof ticketId === 'string' ? tickets.take(ticketId) : undefined;
    if (!ticket) throw httpError(401, 'invalid_ticket', 'Ticket is invalid, expired or already used');
    if (ticketOfUser.get(ticket.userId) === ticketId) ticketOfUser.delete(ticket.userId);
    if (bannedUsers.has(ticket.userId)) throw httpError(403, 'account_banned', 'This account is banned');
    return { user_id: ticket.userId, username: ticket.username, method: ticket.method, session_id: ticket.sessionId };
  });

  // The game server polls this (e.g. once a minute) and kicks anyone listed.
  app.get('/game/bans', { preHandler: requireGameServer, config: { rateLimit: false } }, async () => ({
    version: banState.version,
    banned: [...bannedUsers],
  }));
}

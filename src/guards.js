import { config } from './config.js';
import { safeEqual } from './crypto.js';
import { httpError } from './errors.js';

// Fails closed (503) when the secret is not configured, like the data server's admin routes.
function requireSecret(headerName, configured, label) {
  return async (request) => {
    if (!configured) throw httpError(503, 'not_configured', `${label} is not configured on the server`);
    const provided = request.headers[headerName];
    if (typeof provided !== 'string' || !safeEqual(provided, configured)) {
      throw httpError(401, 'unauthorized', `Invalid ${label}`);
    }
  };
}

/** For calls made by the game server (Colyseus), never by browsers. */
export const requireGameServer = requireSecret('x-game-server-key', config.gameServerSecret, 'GAME_SERVER_SECRET');

/** For calls made by you (ban, unban, username rules). */
export const requireAdmin = requireSecret('x-admin-key', config.adminApiKey, 'ADMIN_API_KEY');

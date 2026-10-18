import { randomInt } from 'node:crypto';
import { config } from '../config.js';
import { isUniqueViolation } from '../db.js';
import { randomToken, sha256, hashPassword, verifyPassword, burnPasswordTime } from '../crypto.js';
import { httpError } from '../errors.js';
import { verifyProof, requireAuth } from '../tokens.js';
import {
  normalizeEmail, validatePassword, validateUsername,
  findUser, getUserById, usernameTaken, emailTaken, newUser, startSession,
  refreshSession, logoutWithRefreshToken,
} from '../accounts.js';
import {
  enabledProviders, getProvider, buildAuthorizeUrl, fetchProviderIdentity,
} from '../oauth.js';
import { oauthStates, oauthCodes, loginFailures, guestCreates, reauth } from '../memory-stores.js';
import { assertUsernameAllowed, isUsernameAllowed } from '../username-filter.js';

const rl = (name) => ({ rateLimit: config.rateLimits[name] });

function body(request) {
  const b = request.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw httpError(400, 'bad_request', 'Request body must be a JSON object');
  return b;
}

function bannedCheck(user) {
  if (user.banned) throw httpError(403, 'account_banned', 'This account is banned');
}

/** Only addresses on the allow-list may receive a login (stops open redirects). */
function validateReturnTo(raw) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    throw httpError(400, 'invalid_return_to', 'Invalid return address');
  }
  if (!config.allowedOrigins.includes(url.origin)) {
    throw httpError(400, 'invalid_return_to', 'Return address is not allowed');
  }
  url.hash = '';
  return url.toString();
}

export default async function authRoutes(app) {
  // -------------------------------------------------------------------------
  // Which third-party logins are switched on (costs no database access).
  // -------------------------------------------------------------------------
  app.get('/auth/providers', { config: rl('check') }, async () => ({ providers: enabledProviders() }));

  // -------------------------------------------------------------------------
  // Live availability checks for the signup form: 1 indexed row read each.
  // Note: answering "e-mail is taken" tells anyone which addresses have an
  // account, so this route is rate-limited per IP.
  // -------------------------------------------------------------------------
  app.get('/auth/check', { config: rl('check') }, async (request) => {
    const { username, email } = request.query || {};

    if (typeof username === 'string') {
      let name;
      try {
        name = validateUsername(username);
      } catch (err) {
        return { available: false, reason: err.code };
      }
      if (!(await isUsernameAllowed(name))) return { available: false, reason: 'blocked_username' };
      return { available: !(await usernameTaken(name.toLowerCase())) };
    }
    if (typeof email === 'string') {
      let normalized;
      try {
        normalized = normalizeEmail(email);
      } catch (err) {
        return { available: false, reason: err.code };
      }
      return { available: !(await emailTaken(normalized)) };
    }
    throw httpError(400, 'bad_request', 'Provide ?username= or ?email=');
  });

  // -------------------------------------------------------------------------
  // E-mail + password
  // -------------------------------------------------------------------------
  app.post('/auth/signup', { config: rl('signup') }, async (request, reply) => {
    const { jkt } = await verifyProof(request);
    const b = body(request);
    const email = normalizeEmail(b.email);
    const password = validatePassword(b.password);
    const username = validateUsername(b.username);
    await assertUsernameAllowed(username);

    const passwordHash = await hashPassword(password);
    const { user, stmt } = newUser({ method: 'email', providerUid: email, email, passwordHash, username });

    try {
      const tokens = await startSession(user, jkt, [stmt]);
      reply.code(201);
      return { ...tokens, is_new: true };
    } catch (err) {
      if (isUniqueViolation(err, 'username_lower')) throw httpError(409, 'username_taken', 'Username is taken');
      if (isUniqueViolation(err, 'provider_uid')) throw httpError(409, 'email_taken', 'An account already uses this e-mail');
      throw err;
    }
  });

  app.post('/auth/login', { config: rl('login') }, async (request, reply) => {
    const { jkt } = await verifyProof(request);
    const b = body(request);
    const email = normalizeEmail(b.email);
    const password = typeof b.password === 'string' ? b.password.slice(0, 256) : '';
    if (!password) throw httpError(400, 'bad_request', 'Password is required');

    const failureKey = `login:${email}`;
    if (loginFailures.blocked(failureKey)) {
      reply.header('Retry-After', String(loginFailures.retryAfterSeconds(failureKey)));
      throw httpError(429, 'too_many_attempts', 'Too many failed attempts. Try again later.');
    }

    const user = await findUser('email', email);
    let ok = false;
    if (user) ok = await verifyPassword(password, user.password_hash);
    else await burnPasswordTime(password); // same timing whether or not the account exists

    if (!ok) {
      loginFailures.add(failureKey);
      throw httpError(401, 'invalid_credentials', 'Wrong e-mail or password');
    }
    loginFailures.clear(failureKey);
    bannedCheck(user);

    return { ...(await startSession(user, jkt)), is_new: false };
  });

  // Placeholders until the e-mail provider is chosen (see src/mailer.js).
  for (const path of ['/auth/password/forgot', '/auth/password/reset', '/auth/email/verify']) {
    app.post(path, { config: rl('login') }, async () => {
      throw httpError(501, 'email_not_configured', 'E-mail features are not switched on yet');
    });
  }

  // -------------------------------------------------------------------------
  // Guests. The device key IS the account: one browser key = one guest.
  // The key cannot be copied out of the browser, so the account cannot move.
  // -------------------------------------------------------------------------
  app.post('/auth/guest', { config: rl('guest') }, async (request, reply) => {
    const { jkt } = await verifyProof(request);
    const b = request.body && typeof request.body === 'object' ? request.body : {};

    const existing = await findUser('guest', jkt);
    if (existing) {
      bannedCheck(existing);
      return { ...(await startSession(existing, jkt)), is_new: false };
    }

    if (guestCreates.blocked(request.ip)) {
      reply.header('Retry-After', String(guestCreates.retryAfterSeconds(request.ip)));
      throw httpError(429, 'too_many_guests', 'Too many guest accounts created from this network. Try again tomorrow.');
    }
    guestCreates.add(request.ip);

    const hint = typeof b.username_hint === 'string' && /^Guest\d{6}$/.test(b.username_hint) ? b.username_hint : null;

    for (let attempt = 0; attempt < 6; attempt++) {
      const username = attempt === 0 && hint ? hint : `Guest${String(randomInt(0, 1_000_000)).padStart(6, '0')}`;
      const { user, stmt } = newUser({ method: 'guest', providerUid: jkt, username });
      try {
        const tokens = await startSession(user, jkt, [stmt]);
        reply.code(201);
        return { ...tokens, is_new: true };
      } catch (err) {
        if (isUniqueViolation(err, 'username_lower')) continue; // name collision: try another number
        if (isUniqueViolation(err, 'provider_uid')) {
          // Two requests from the same browser raced; use the account that won.
          const winner = await findUser('guest', jkt);
          if (winner) return { ...(await startSession(winner, jkt)), is_new: false };
        }
        throw err;
      }
    }
    throw httpError(503, 'try_again', 'Could not create a guest account, please try again');
  });

  // -------------------------------------------------------------------------
  // Refresh + logout
  // -------------------------------------------------------------------------
  app.post('/auth/refresh', { config: rl('refresh') }, async (request) => {
    const { jkt } = await verifyProof(request);
    return refreshSession(body(request).refresh_token, jkt);
  });

  app.post('/auth/logout', { config: rl('refresh') }, async (request) => {
    await logoutWithRefreshToken(body(request).refresh_token);
    return { ok: true };
  });

  // -------------------------------------------------------------------------
  // Third-party login (Google / Microsoft / Discord)
  //
  //  1. POST  /auth/oauth/:provider/prepare   -> { url }   (page navigates to it)
  //  2. provider -> GET /auth/oauth/:provider/callback     (server side)
  //  3. redirect back to the game page with  #auth_code=...
  //  4. POST  /auth/oauth/exchange  { code }  -> tokens
  //
  // The code in step 3 only works for the browser key that started step 1,
  // so a code copied out of the address bar is useless to anyone else.
  // -------------------------------------------------------------------------
  app.post('/auth/oauth/:provider/prepare', { config: rl('oauth') }, async (request) => {
    const { provider } = request.params;
    getProvider(provider); // 404 unknown / 503 not configured
    const b = body(request);
    const purpose = b.purpose === 'reauth' ? 'reauth' : 'login';
    const returnTo = validateReturnTo(b.return_to);

    let jkt;
    let auth = null;
    if (purpose === 'reauth') {
      await requireAuth(request); // proves who is asking, and that they hold the key
      auth = request.auth;
      jkt = auth.jkt;
    } else {
      ({ jkt } = await verifyProof(request));
    }

    const state = randomToken(24);
    const codeVerifier = randomToken(48);
    oauthStates.set(state, {
      provider, returnTo, jkt, codeVerifier, purpose,
      userId: auth?.userId, sessionId: auth?.sessionId,
    });
    return { url: buildAuthorizeUrl(provider, { state, codeChallenge: sha256(codeVerifier) }) };
  });

  app.get('/auth/oauth/:provider/callback', { config: rl('oauth') }, async (request, reply) => {
    const { provider } = request.params;
    const { state, code, error } = request.query || {};

    const pending = typeof state === 'string' ? oauthStates.take(state) : undefined;
    if (!pending || pending.provider !== provider) {
      return reply
        .code(400)
        .type('text/plain')
        .send('This login link has expired. Please close this tab and try again from the game.');
    }

    const back = (params) => {
      const url = new URL(pending.returnTo);
      url.hash = new URLSearchParams(params).toString();
      return reply.redirect(url.toString(), 302);
    };

    if (error || typeof code !== 'string') {
      return back({ auth_error: error === 'access_denied' ? 'access_denied' : 'provider_error' });
    }

    let identity;
    try {
      identity = await fetchProviderIdentity(provider, { code, codeVerifier: pending.codeVerifier });
    } catch (err) {
      request.log.warn({ provider, err: err.message }, 'provider login failed');
      return back({ auth_error: 'provider_error' });
    }

    const handoff = randomToken(24);
    oauthCodes.set(handoff, {
      provider, identity, jkt: pending.jkt, purpose: pending.purpose,
      userId: pending.userId, sessionId: pending.sessionId,
    });
    return back({ auth_code: handoff });
  });

  app.post('/auth/oauth/exchange', { config: rl('oauth') }, async (request, reply) => {
    const code = body(request).code;
    const peek = typeof code === 'string' ? oauthCodes.get(code) : undefined;
    if (!peek) throw httpError(400, 'invalid_code', 'This login code is invalid or has expired');

    let jkt;
    if (peek.purpose === 'reauth') {
      await requireAuth(request);
      jkt = request.auth.jkt;
    } else {
      ({ jkt } = await verifyProof(request));
    }

    const record = oauthCodes.take(code);
    if (!record || record.jkt !== jkt) throw httpError(400, 'invalid_code', 'This login code is invalid or has expired');
    const { provider, identity } = record;

    // Re-verification before a sensitive action (e.g. deleting the account).
    if (record.purpose === 'reauth') {
      if (request.auth.userId !== record.userId || request.auth.sessionId !== record.sessionId) {
        throw httpError(403, 'wrong_account', 'This login belongs to a different session');
      }
      const user = await getUserById(record.userId);
      if (!user || user.method !== provider || user.provider_uid !== identity.uid) {
        throw httpError(403, 'wrong_account', `Log in with the same ${provider} account you signed up with`);
      }
      reauth.set(record.sessionId, true);
      return { reauth: true };
    }

    const existing = await findUser(provider, identity.uid);
    if (existing) {
      bannedCheck(existing);
      return { ...(await startSession(existing, jkt)), is_new: false };
    }

    const { user, stmt } = newUser({
      method: provider,
      providerUid: identity.uid,
      email: identity.email,
      emailVerified: identity.emailVerified,
    });
    try {
      const tokens = await startSession(user, jkt, [stmt]);
      reply.code(201);
      return { ...tokens, is_new: true };
    } catch (err) {
      if (isUniqueViolation(err, 'provider_uid')) {
        const winner = await findUser(provider, identity.uid);
        if (winner) return { ...(await startSession(winner, jkt)), is_new: false };
      }
      throw err;
    }
  });
}

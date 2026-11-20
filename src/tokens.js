import { createPrivateKey, createPublicKey } from 'node:crypto';
import { SignJWT, jwtVerify, EmbeddedJWK, exportJWK, calculateJwkThumbprint } from 'jose';
import { config } from './config.js';
import { sha256, safeEqual } from './crypto.js';
import { httpError } from './errors.js';
import { proofReplay, bannedUsers, deletedUsers, bannedError } from './memory-stores.js';

const AUDIENCE = 'apex-arena';

// ---------------------------------------------------------------------------
// Signing key. Access tokens are signed with ES256 (asymmetric): the game
// server only ever needs the PUBLIC key (served at /.well-known/jwks.json)
// to verify them, so a leak of the game server cannot forge logins.
// ---------------------------------------------------------------------------
const privateKey = createPrivateKey(config.signingKeyPem);
if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
  throw new Error('AUTH_JWT_PRIVATE_KEY must be an ES256 (P-256) key. Run: npm run generate-keys');
}
const publicKey = createPublicKey(privateKey);
const publicJwk = await exportJWK(publicKey);
const kid = await calculateJwkThumbprint(publicJwk);

export const jwks = { keys: [{ ...publicJwk, kid, use: 'sig', alg: 'ES256' }] };

export async function signAccessToken({ userId, sessionId, jkt, username, method }) {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: sessionId, cnf: { jkt }, un: username ?? null, m: method })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid })
    .setIssuer(config.publicUrl)
    .setAudience(AUDIENCE)
    .setSubject(userId)
    .setIssuedAt(iat)
    .setExpirationTime(iat + config.accessTtlSeconds)
    .sign(privateKey);
}

export async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: config.publicUrl,
    audience: AUDIENCE,
    algorithms: ['ES256'],
    typ: 'at+jwt',
  });
  if (!payload.sub || !payload.sid || !payload.cnf?.jkt) throw new Error('malformed access token');
  return payload;
}

// ---------------------------------------------------------------------------
// DPoP proofs. The browser holds a NON-EXTRACTABLE key pair. Every request
// carries a small JWT signed with the private key, naming the exact method
// and URL, with a unique id and a timestamp. Stolen tokens are useless
// without the key, and a captured proof cannot be replayed.
// ---------------------------------------------------------------------------
export async function verifyProof(request, { accessToken } = {}) {
  const proof = request.headers.dpop;
  if (!proof || typeof proof !== 'string') throw httpError(401, 'dpop_required', 'Missing DPoP proof');

  // Proofs must be stamped within about a minute of THIS server's clock. A request that carries the secret
  // DEV_BYPASS_KEY skips that one check (for local development). The key, signature, URL, replay protection
  // and everything after this point still apply, so a leaked dev key cannot log anyone in.
  const devKey = request.headers['x-dev-key'];
  const timeChecks =
    config.devBypassKey && typeof devKey === 'string' && safeEqual(devKey, config.devBypassKey)
      ? {}
      : { clockTolerance: 60, maxTokenAge: 120 };

  let payload;
  let protectedHeader;
  try {
    ({ payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: ['ES256'],
      ...timeChecks,
      requiredClaims: ['iat', 'jti', 'htm', 'htu'],
    }));
  } catch {
    throw httpError(401, 'invalid_dpop', 'Invalid DPoP proof');
  }

  const path = request.url.split('?')[0];
  if (payload.htm !== request.method || payload.htu !== config.publicUrl + path) {
    throw httpError(401, 'invalid_dpop', 'DPoP proof does not match this request');
  }
  if (typeof payload.jti !== 'string' || payload.jti.length > 100) {
    throw httpError(401, 'invalid_dpop', 'Invalid DPoP proof id');
  }
  if (proofReplay.has(payload.jti)) throw httpError(401, 'dpop_replay', 'DPoP proof was already used');
  proofReplay.set(payload.jti, true);

  if (accessToken !== undefined && payload.ath !== sha256(accessToken)) {
    throw httpError(401, 'invalid_dpop', 'DPoP proof is not bound to this access token');
  }

  const jkt = await calculateJwkThumbprint(protectedHeader.jwk);
  return { jkt };
}

/** preHandler for routes that need a logged-in player. Sets request.auth. */
export async function requireAuth(request) {
  const [scheme, token] = String(request.headers.authorization || '').split(' ');
  if (scheme?.toLowerCase() !== 'dpop' || !token) throw httpError(401, 'unauthorized', 'Missing access token');

  let claims;
  try {
    claims = await verifyAccessToken(token);
  } catch {
    throw httpError(401, 'invalid_token', 'Access token is invalid or expired');
  }

  const { jkt } = await verifyProof(request, { accessToken: token });
  if (jkt !== claims.cnf.jkt) throw httpError(401, 'invalid_dpop', 'DPoP key does not match the access token');
  if (bannedUsers.has(claims.sub)) throw bannedError(claims.sub);
  if (deletedUsers.has(claims.sub)) throw httpError(401, 'account_deleted', 'This account was deleted');

  request.auth = {
    userId: claims.sub,
    sessionId: claims.sid,
    jkt,
    username: claims.un,
    method: claims.m,
    token,
  };
}
import { randomBytes, scrypt as scryptCb, createHash, timingSafeEqual } from 'node:crypto';

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const sha256 = (value) => createHash('sha256').update(value).digest('base64url');

export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

// ---------------------------------------------------------------------------
// Passwords: scrypt (built into Node, no native packages to break on Render).
// Parameters are stored inside each hash, so they can be raised later without
// invalidating existing passwords. N=2^15,r=8 uses ~32 MB per hash, so only
// a couple run at once to keep a small free-tier instance from running out
// of memory when many people log in at the same moment.
// ---------------------------------------------------------------------------
const N = 32768;
const R = 8;
const P = 1;
const KEYLEN = 32;
const MAXMEM = 96 * 1024 * 1024;
const MAX_CONCURRENT = 2;

let active = 0;
const waiters = [];

async function acquire() {
  if (active < MAX_CONCURRENT) {
    active++;
    return;
  }
  await new Promise((resolve) => waiters.push(resolve)); // slot is handed over on release
}

function release() {
  const next = waiters.shift();
  if (next) next();
  else active--;
}

function scryptAsync(password, salt, n, r, p) {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, KEYLEN, { N: n, r, p, maxmem: MAXMEM }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

const normalise = (pw) => String(pw).normalize('NFKC');

export async function hashPassword(password) {
  await acquire();
  try {
    const salt = randomBytes(16);
    const key = await scryptAsync(normalise(password), salt, N, R, P);
    return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`;
  } finally {
    release();
  }
}

export async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, keyB64] = parts;
  await acquire();
  try {
    const expected = Buffer.from(keyB64, 'base64');
    const key = await scryptAsync(normalise(password), Buffer.from(saltB64, 'base64'), Number(n), Number(r), Number(p));
    return key.length === expected.length && timingSafeEqual(key, expected);
  } catch {
    return false;
  } finally {
    release();
  }
}

// Used when an e-mail address is unknown, so "no such account" and
// "wrong password" take the same amount of time.
let dummyHash = null;
export async function burnPasswordTime(password) {
  dummyHash ??= await hashPassword('apex-arena-dummy-password');
  await verifyPassword(password, dummyHash);
}

import { config } from './config.js';

// ---------------------------------------------------------------------------
// Short-lived things live in RAM instead of Turso on purpose: they expire in
// seconds or minutes, so persisting them would cost database writes for no
// benefit. If the server restarts, an unfinished login or join ticket simply
// has to be retried. This assumes ONE running instance (true on Render's
// free tier); with several instances these would need a shared store.
// ---------------------------------------------------------------------------

export class TtlMap {
  constructor(ttlMs, maxEntries = 50_000) {
    this.ttlMs = ttlMs;
    this.max = maxEntries;
    this.map = new Map();
  }

  set(key, value, ttlMs = this.ttlMs) {
    if (this.map.size >= this.max && !this.map.has(key)) {
      this.map.delete(this.map.keys().next().value); // drop the oldest entry
    }
    this.map.set(key, { value, expires: Date.now() + ttlMs });
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expires <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  /** Read and remove in one step (single-use values). */
  take(key) {
    const value = this.get(key);
    this.map.delete(key);
    return value;
  }

  delete(key) {
    this.map.delete(key);
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.map) if (entry.expires <= now) this.map.delete(key);
  }
}

/** Fixed-window counter, e.g. "8 failed logins per 15 minutes per e-mail". */
export class Counter {
  constructor(max, windowMs, maxEntries = 50_000) {
    this.max = max;
    this.windowMs = windowMs;
    this.maxEntries = maxEntries;
    this.map = new Map();
  }

  #live(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.resetAt <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return entry;
  }

  add(key) {
    let entry = this.#live(key);
    if (!entry) {
      if (this.map.size >= this.maxEntries) this.map.delete(this.map.keys().next().value);
      entry = { count: 0, resetAt: Date.now() + this.windowMs };
      this.map.set(key, entry);
    }
    entry.count++;
  }

  blocked(key) {
    const entry = this.#live(key);
    return !!entry && entry.count >= this.max;
  }

  retryAfterSeconds(key) {
    const entry = this.#live(key);
    return entry ? Math.max(1, Math.ceil((entry.resetAt - Date.now()) / 1000)) : 0;
  }

  clear(key) {
    this.map.delete(key);
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.map) if (entry.resetAt <= now) this.map.delete(key);
  }
}

const MINUTE = 60_000;

export const oauthStates = new TtlMap(10 * MINUTE, 10_000); // state -> pending provider login
export const oauthCodes = new TtlMap(2 * MINUTE, 10_000); // one-time handoff code -> verified provider identity
export const tickets = new TtlMap(config.ticketTtlSeconds * 1000, 20_000); // join ticket -> player
export const ticketOfUser = new TtlMap(config.ticketTtlSeconds * 1000, 20_000); // userId -> their newest ticket
export const proofReplay = new TtlMap(5 * MINUTE, 100_000); // DPoP proof ids already used
export const reauth = new TtlMap(5 * MINUTE, 10_000); // sessionId -> recently re-verified with their provider

export const loginFailures = new Counter(config.loginFailures.max, config.loginFailures.windowMs);
export const guestCreates = new Counter(config.guestCreatesPerIpPerDay, 24 * 60 * MINUTE);

/** Banned user ids. Loaded once at startup, kept in sync by the admin routes. */
export const bannedUsers = new Set();
export const banState = { version: 0 };

const all = [oauthStates, oauthCodes, tickets, ticketOfUser, proofReplay, reauth, loginFailures, guestCreates];
setInterval(() => all.forEach((s) => s.sweep()), MINUTE).unref();

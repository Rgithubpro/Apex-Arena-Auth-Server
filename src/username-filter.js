import { db } from './db.js';
import { config } from './config.js';
import { httpError } from './errors.js';

// ---------------------------------------------------------------------------
// Username filter. The rules live in the auth_username_rules table in Turso,
// so they can be changed without redeploying:
//
//   kind       what it does
//   exact      the whole name (after cleaning, see below) equals the pattern
//   contains   the cleaned name contains the pattern anywhere
//   regex      the lower-cased name matches the regular expression
//   allow      harmless words that would otherwise trip a "contains" rule
//              (e.g. allow "shiitake" while "shit" is blocked)
//
// Cleaning, so simple tricks do not work: lower case, 0->o 3->e 4->a 5->s
// 7->t 8->b 9->g, 1 counts as both "i" and "l", underscores are dropped and
// repeated letters collapse ("f_u_c_k", "fuuuck" and "fu<k" style names all
// end up as "fuck"). Patterns are cleaned the same way when they are loaded.
//
// Cost: the server keeps the compiled rules in memory and checks ONE row (a
// version number) at most once per USERNAME_RULES_REFRESH_SECONDS, and only
// while someone is actually picking a username. The full rule list is read
// again only when that number changed. A database trigger bumps the number on
// every INSERT/UPDATE/DELETE, so editing the table directly in the Turso
// dashboard works too.
// ---------------------------------------------------------------------------

const VERSION_KEY = 'username_rules_version';
const LEET = { 0: 'o', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 9: 'g' };

function clean(text, one) {
  let out = '';
  for (const ch of String(text).toLowerCase()) {
    if (ch === '_') continue;
    out += ch === '1' ? one : (LEET[ch] ?? ch);
  }
  return out.replace(/(.)\1+/g, '$1');
}

const variants = (text) => [...new Set([clean(text, 'i'), clean(text, 'l')])];

function compile(rows) {
  const rules = { allow: [], exact: new Set(), contains: [], regex: [] };
  for (const { kind, pattern } of rows) {
    const p = String(pattern ?? '').trim();
    if (!p) continue;
    if (kind === 'regex') {
      try {
        rules.regex.push(new RegExp(p, 'i'));
      } catch {
        console.warn(`[username-filter] ignoring invalid regex rule: ${p}`);
      }
      continue;
    }
    const cleaned = clean(p, 'i');
    if (!cleaned) continue;
    if (kind === 'allow') rules.allow.push(cleaned);
    else if (kind === 'exact') rules.exact.add(cleaned);
    else if (kind === 'contains') rules.contains.push(cleaned);
  }
  rules.allow.sort((a, b) => b.length - a.length); // longest phrase first
  return rules;
}

/** True when the name passes the given rules. */
export function evaluate(name, rules) {
  const lower = String(name).toLowerCase();
  for (const re of rules.regex) if (re.test(lower)) return false;

  for (let text of variants(name)) {
    if (rules.exact.has(text)) return false;
    for (const phrase of rules.allow) text = text.split(phrase).join(' ');
    for (const bad of rules.contains) if (text.includes(bad)) return false;
  }
  return true;
}

let current = compile([]);
let loadedVersion = null;
let lastCheckedAt = 0;
let inflight = null;

async function refresh(force) {
  const rs = await db.execute({ sql: `SELECT value FROM auth_meta WHERE key = ?`, args: [VERSION_KEY] });
  const version = String(rs.rows[0]?.value ?? '0');
  if (force || version !== loadedVersion) {
    const rules = await db.execute(`SELECT kind, pattern FROM auth_username_rules WHERE enabled = 1`);
    current = compile(rules.rows);
    loadedVersion = version;
  }
}

export async function ensureRulesFresh({ force = false } = {}) {
  const due = force || loadedVersion === null || Date.now() - lastCheckedAt >= config.usernameRulesRefreshSeconds * 1000;
  if (!due) return;
  inflight ??= refresh(force)
    .catch((err) => console.warn(`[username-filter] could not refresh rules, keeping the old ones: ${err.message}`))
    .finally(() => {
      lastCheckedAt = Date.now();
      inflight = null;
    });
  await inflight;
}

export async function isUsernameAllowed(name) {
  await ensureRulesFresh();
  return evaluate(name, current);
}

export async function assertUsernameAllowed(name) {
  if (!(await isUsernameAllowed(name))) throw httpError(400, 'blocked_username', 'That username is not allowed');
}

export const reloadUsernameRules = () => ensureRulesFresh({ force: true });

export const usernameRuleStats = () => ({
  version: loadedVersion,
  exact: current.exact.size,
  contains: current.contains.length,
  regex: current.regex.length,
  allow: current.allow.length,
});

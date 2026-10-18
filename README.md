# Apex Arena auth server

E-mail + password, guest accounts, and Google / Microsoft / Discord login for Apex Arena.
Runs on Render, stores accounts in your existing Turso database (tables prefixed `auth_`, never listed in the data server's `tables.config.js`).

## How logins stay safe

- The browser makes a **non-extractable key** (WebCrypto) and signs every request with it (DPoP). A stolen token is useless on another device.
- **Access token** (30 min, kept in memory) + **refresh token** (rotated on every use, kept in IndexedDB). Re-using an old refresh token logs the session out everywhere.
- **Guests** = that browser key. One key, one guest account; it cannot be copied to another device or upgraded to e-mail.
- **Join tickets**: to enter a match the browser trades its token for a single-use ticket (30 s). The game server never sees long-lived tokens.
- **Bans** are instant for joining (checked when the ticket is redeemed) and pushed to the game server by polling `/game/bans`.
- Sensitive actions (change password, delete account) need the password again, or a fresh Google/Microsoft/Discord login.

## Deploy on Render

1. Put the contents of this folder (see *Folder structure*) in its own GitHub repo. Render → New → **Web Service** → that repo.
2. Build command `npm install`, start command `npm start`, health check path `/ping`.
3. Run `npm run generate-keys` locally and copy the three values it prints.
4. Environment variables (see `.env.example`):

| Variable | Value |
|---|---|
| `NODE_ENV` | `production` |
| `TRUST_PROXY_HOPS` | `1` |
| `PUBLIC_URL` | this service's own URL, e.g. `https://apex-arena-auth-server.onrender.com` |
| `ALLOWED_ORIGINS` | `https://rgithubpro.github.io` (origins only, comma separated; add every site that hosts the game) |
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | same values as the data server |
| `AUTH_JWT_PRIVATE_KEY`, `GAME_SERVER_SECRET`, `ADMIN_API_KEY` | from `npm run generate-keys` |
| `GOOGLE_*`, `MICROSOFT_*`, `DISCORD_*` | from the steps below (each provider switches on when both of its values are set) |

The tables are created automatically on first start.

## Provider setup (menus change over time, the idea stays the same)

Redirect URI to register at every provider: `PUBLIC_URL` + `/auth/oauth/<provider>/callback`

- **Google**: console.cloud.google.com → APIs & Services → OAuth consent screen (External; scopes `openid`, `email`, `profile`; **publish the app**, otherwise only test users can log in) → Credentials → Create OAuth client ID → *Web application* → add the redirect URI `…/auth/oauth/google/callback`. Copy Client ID + secret into `GOOGLE_CLIENT_ID/SECRET`.
- **Microsoft**: portal.azure.com → Microsoft Entra ID → App registrations → New registration → supported accounts: *any organizational directory and personal Microsoft accounts* → Redirect URI type **Web**: `…/auth/oauth/microsoft/callback` → Certificates & secrets → New client secret (copy the **Value**). Application (client) ID + secret into `MICROSOFT_CLIENT_ID/SECRET`.
- **Discord**: discord.com/developers/applications → New Application → OAuth2 → add redirect `…/auth/oauth/discord/callback` → copy Client ID, Reset Secret → `DISCORD_CLIENT_ID/SECRET`.

## Folder structure

The `auth-server` folder IS the repo root: copy its contents into a new GitHub repo as they are.

```
apex-arena-auth-server/        its own GitHub repo, deployed to Render
├── package.json               dependencies + start / test scripts
├── package-lock.json
├── .env.example               list of all settings (copy to .env locally, never commit .env)
├── .gitignore
├── README.md
├── scripts/
│   ├── generate-keys.js       prints the secrets for Render (run once)
│   └── test.js                `npm test`: 100+ checks on a throw-away local database
└── src/
    ├── server.js              entry point (`npm start`): app setup, CORS, rate limits
    ├── config.js              reads every environment variable
    ├── db.js                  Turso connection + tables and indexes (created automatically)
    ├── tokens.js              access tokens, public key (JWKS), DPoP proof checks
    ├── accounts.js            users + sessions: signup, refresh rotation, revoking
    ├── crypto.js              password hashing, random tokens
    ├── oauth.js               Google / Microsoft / Discord details
    ├── username-filter.js     username rules from Turso (see below)
    ├── guards.js              secret-header checks for game-server and admin calls
    ├── memory-stores.js       short-lived data kept in RAM (tickets, OAuth state, ...)
    ├── cleanup.js             deletes inactive guests and dead sessions
    ├── mailer.js              e-mail sending (prepared, off for now)
    ├── errors.js
    └── routes/
        ├── auth.js            signup, login, guest, refresh, logout, OAuth, availability check
        ├── me.js              the player's own account: username, terms, password, delete
        ├── game.js            join tickets, public key, ban list for the game server
        └── admin.js           ban / unban, username rules
```

## Frontend files (your assets repo)

| File | Where |
|---|---|
| `auth.js` (new) | `js/data/auth.js`, next to `localstorage.js`. It uses `export`, so list it in `manifest.config.json` as `"js/data/auth.js": "module"` (not `script`). Set `PROD_AUTH_URL` at the top. |
| `welcome.js`, `welcome.html`, `welcome.css`, `home.js` | same place as your current copies (replace) |
| `loading.js` | same place as your current copy (replace) |

`loading.js` loads it with `resolveModuleUrl('js/data/auth.js', assetsVersion)`, exactly like `localstorage.js`, so the normal asset versioning applies. Make sure the service worker does not intercept or cache requests to the auth server's origin.

## Joining a match (for when the game server exists)

Browser: `const { ticket } = await Auth.getJoinTicket(); client.joinOrCreate('battle', { ticket });`

Colyseus room:

```js
import { Room, ServerError } from 'colyseus';

const AUTH_URL = process.env.AUTH_SERVER_URL;
const SECRET = process.env.GAME_SERVER_SECRET;
const activeByUser = new Map(); // one connection per account (single game-server process)

export class BattleRoom extends Room {
  async onAuth(client, options) {
    const res = await fetch(`${AUTH_URL}/game/ticket/redeem`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-game-server-key': SECRET },
      body: JSON.stringify({ ticket: options?.ticket }),
    });
    if (!res.ok) throw new ServerError(401, 'Not logged in');
    return res.json(); // { user_id, username, method, session_id } -> client.auth
  }

  onJoin(client) {
    const previous = activeByUser.get(client.auth.user_id);
    if (previous && previous !== client) previous.leave(4001); // logged in somewhere else
    activeByUser.set(client.auth.user_id, client);
  }

  onLeave(client) {
    if (activeByUser.get(client.auth.user_id) === client) activeByUser.delete(client.auth.user_id);
  }
}

// Every minute: kick anyone who got banned while playing.
setInterval(async () => {
  const res = await fetch(`${AUTH_URL}/game/bans`, { headers: { 'x-game-server-key': SECRET } });
  const { banned } = await res.json();
  for (const id of banned) activeByUser.get(id)?.leave(4003);
}, 60_000);
```

Ban from anywhere: `POST /admin/ban` with header `x-admin-key` and body `{ "username": "SomeName", "reason": "..." }` (also `/admin/unban`, `GET /admin/user?username=`).

## Username filter

Rules live in the `auth_username_rules` table in Turso, so you can change them without redeploying. A short starter list is created automatically (official-looking names plus a few obvious words); extend it yourself.

| kind | meaning |
|---|---|
| `exact` | the whole cleaned name equals the pattern |
| `contains` | the cleaned name contains the pattern |
| `regex` | the lower-case name matches the regular expression |
| `allow` | a harmless word that would otherwise trip a `contains` rule (e.g. allow `shiitake` while `shit` is blocked) |

Names are cleaned before matching: lower case, `0 3 4 5 7 8 9` read as `o e a s t b g`, `1` counts as `i` and `l`, underscores are dropped and repeated letters collapse, so `F_u_c_k`, `fuuuck` and `Sh1t` all match `fuck` / `shit`. The same cleaning is applied to your patterns.

Add or change rules either in the Turso dashboard / SQL:

```sql
INSERT INTO auth_username_rules (kind, pattern, note) VALUES ('contains', 'somebadword', 'added by me');
UPDATE auth_username_rules SET enabled = 0 WHERE id = 14;
```

or through the admin API:

```
curl -X POST   $PUBLIC_URL/admin/username-rules      -H "x-admin-key: $ADMIN_API_KEY" -H "content-type: application/json" -d '{"kind":"contains","pattern":"somebadword"}'
curl           $PUBLIC_URL/admin/username-rules      -H "x-admin-key: $ADMIN_API_KEY"
curl -X DELETE $PUBLIC_URL/admin/username-rules/21   -H "x-admin-key: $ADMIN_API_KEY"
curl -X POST   $PUBLIC_URL/admin/username-rules/test -H "x-admin-key: $ADMIN_API_KEY" -H "content-type: application/json" -d '{"username":"Some_Name"}'
```

How fast changes go live: a database trigger bumps a version number on every change; the server looks at that one row at most once per `USERNAME_RULES_REFRESH_SECONDS` (60) and only while someone is picking a username, and re-reads the rules only when the number changed. Admin API changes apply immediately on the running server.

The filter runs when a name is checked on the signup form, at signup, and when a name is chosen or changed. It does not re-check names that already exist; no slur list is included, add the terms you want to block.

## Database cost (rows, as Turso counts them)

| Action | Rows read | Rows written |
|---|---|---|
| Opening the game with a saved login (refresh) | 2 | 1 |
| E-mail login | 1 (+ your own old sessions) | 1-2 |
| Sign up | 0 | 2 |
| Guest: first time / coming back | 1 | 2 / 1-2 |
| Username or e-mail availability check | 1 | 0 |
| Username filter (only while people are picking names) | 1 per minute (version check); the full rule list only after a change | 0 |
| Access-token checks, join tickets, ban list, OAuth state | 0 | 0 |
| Refresh while playing (every 30 min) | 2 | 1 |
| Cleanup (every 12 h, only while awake) | about 0 | the rows it deletes |

Every query is index-backed (`npm test` fails if one needs a table scan). `last_seen_at` is written at most once a day per player. `/ping` and `/health` never touch the database. Raise `ACCESS_TTL_SECONDS` to refresh less often.

## Good to know

- Short-lived data (tickets, OAuth state, replay protection, ban list) lives in the server's memory. That assumes **one running instance**, which is the Render free tier. With several instances those parts would need a shared store.
- The free tier sleeps after idle time; the client retries for up to ~75 s and `Auth.warmUp()` wakes it early.
- The signup form's "e-mail already used" hint tells anyone which addresses have an account (rate-limited per IP). Removing the live check removes that.
- A banned *guest* can create a fresh guest by clearing browser data; bans hold for e-mail and provider accounts.
- E-mail verification and password reset are prepared (`src/mailer.js`, `auth_email_tokens`, the 501 routes in `src/routes/auth.js`) but off until a provider is chosen.
- `npm test` runs the full test suite (100+ checks) against a throw-away local database.

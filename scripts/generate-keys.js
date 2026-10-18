// Prints the secrets the auth server needs. Run once:  npm run generate-keys
// Copy each value into the Render dashboard (Environment). Never commit them.
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });

console.log('# Token signing key (single line, base64 of the PEM)');
console.log(`AUTH_JWT_PRIVATE_KEY=${Buffer.from(pem).toString('base64')}\n`);
console.log('# Shared secret between the auth server and the (future) game server');
console.log(`GAME_SERVER_SECRET=${randomBytes(32).toString('base64url')}\n`);
console.log('# Key for the /admin routes (ban / unban)');
console.log(`ADMIN_API_KEY=${randomBytes(32).toString('base64url')}`);

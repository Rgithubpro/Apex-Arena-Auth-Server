import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { config } from './config.js';
import { db, initSchema } from './db.js';
import { HttpError } from './errors.js';
import { enabledProviders } from './oauth.js';
import { bannedUsers, banState } from './memory-stores.js';
import { startCleanupLoop } from './cleanup.js';
import authRoutes from './routes/auth.js';
import meRoutes from './routes/me.js';
import gameRoutes from './routes/game.js';
import adminRoutes from './routes/admin.js';

export async function buildApp({ logger = true } = {}) {
  const app = Fastify({
    logger: logger
      ? {
          level: process.env.LOG_LEVEL || (config.isProd ? 'info' : 'debug'),
          // Never write tokens or secrets into the logs.
          redact: ['req.headers.authorization', 'req.headers.dpop', 'req.headers["x-admin-key"]', 'req.headers["x-game-server-key"]'],
          transport: config.isProd ? undefined : { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss' } },
        }
      : false,
    bodyLimit: config.maxPayloadBytes,
    trustProxy: config.trustProxyHops,
  });

  await app.register(cors, {
    origin: config.allowedOrigins,
    methods: ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'DPoP'],
    exposedHeaders: ['Date', 'Retry-After'], // Date lets the browser correct its clock for DPoP proofs
    credentials: false,
    maxAge: 600,
  });

  await app.register(rateLimit, {
    global: true,
    max: config.rateLimits.global.max,
    timeWindow: config.rateLimits.global.timeWindow,
    keyGenerator: (request) => request.ip,
    errorResponseBuilder: (request, context) => ({
      statusCode: 429,
      error: 'rate_limited',
      message: `Too many requests. Try again in ${context.after}.`,
    }),
  });

  app.addHook('onSend', async (request, reply) => {
    if (!reply.hasHeader('cache-control')) reply.header('Cache-Control', 'no-store');
    reply.header('X-Content-Type-Options', 'nosniff');
  });

  app.setErrorHandler((err, request, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code, message: err.message });
    }
    if (err.statusCode && err.statusCode < 500) {
      // Fastify's own client errors (bad JSON, body too large, rate limit...)
      return reply.code(err.statusCode).send({ error: err.code || 'bad_request', message: err.message });
    }
    request.log.error({ err }, 'unhandled error');
    return reply.code(500).send({ error: 'internal_error', message: 'Something went wrong' });
  });

  app.setNotFoundHandler((request, reply) => reply.code(404).send({ error: 'not_found', message: 'No such route' }));

  // Health checks never touch the database, so uptime pings cost no reads.
  app.get('/ping', { config: { rateLimit: false } }, async () => ({ status: 'ok' }));
  app.get('/health', { config: { rateLimit: false } }, async () => ({
    status: 'ok',
    uptimeSeconds: Math.round(process.uptime()),
    providers: enabledProviders(),
  }));

  await app.register(authRoutes);
  await app.register(meRoutes);
  await app.register(gameRoutes);
  await app.register(adminRoutes);

  return app;
}

/** Loads the (small) list of banned players into memory. */
export async function loadBans() {
  const rs = await db.execute(`SELECT id FROM auth_users WHERE banned = 1`);
  bannedUsers.clear();
  for (const row of rs.rows) bannedUsers.add(row.id);
  banState.version++;
}

async function start() {
  await initSchema();
  await loadBans();
  const app = await buildApp();
  startCleanupLoop(app.log);

  const shutdown = async (signal) => {
    app.log.info({ signal }, 'shutting down');
    await app.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  try {
    await app.listen({ port: config.port, host: '0.0.0.0' });
    app.log.info({ providers: enabledProviders(), origins: config.allowedOrigins }, 'auth server ready');
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) start();

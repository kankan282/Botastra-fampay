import crypto from 'node:crypto';

function boolEnv(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function intEnv(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function csv(value, fallback = []) {
  const source = value === undefined ? fallback.join(',') : String(value);
  return source.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
}

export function loadConfig(overrides = {}) {
  const production = (overrides.nodeEnv ?? process.env.NODE_ENV ?? 'development') === 'production';
  const developmentSecret = crypto.createHash('sha256').update('botastra-local-development-only').digest('hex');

  const config = {
    nodeEnv: overrides.nodeEnv ?? process.env.NODE_ENV ?? 'development',
    production,
    port: Number(overrides.port ?? process.env.PORT ?? 3000),
    appUrl: overrides.appUrl ?? process.env.APP_URL ?? '',
    databaseUrl: overrides.databaseUrl ?? process.env.DATABASE_URL ?? '',
    databaseSsl: overrides.databaseSsl ?? boolEnv(process.env.DATABASE_SSL, production),
    encryptionKey: overrides.encryptionKey ?? process.env.ENCRYPTION_KEY ?? developmentSecret,
    sessionSecret: overrides.sessionSecret ?? process.env.SESSION_SECRET ?? developmentSecret,
    adminPassword: overrides.adminPassword ?? process.env.ADMIN_PASSWORD ?? (production ? '' : 'change-me-now'),
    adminToken: overrides.adminToken ?? process.env.ADMIN_TOKEN ?? (production ? '' : 'dev-admin-token-change-me'),
    publicKeyCreation: overrides.publicKeyCreation ?? boolEnv(process.env.PUBLIC_KEY_CREATION, true),
    setupAccessCode: overrides.setupAccessCode ?? process.env.SETUP_ACCESS_CODE ?? '',
    publicKeyMaxTtlDays: overrides.publicKeyMaxTtlDays ?? intEnv(process.env.PUBLIC_KEY_MAX_TTL_DAYS, 30, 1, 365),
    defaultKeyTtlDays: overrides.defaultKeyTtlDays ?? intEnv(process.env.DEFAULT_KEY_TTL_DAYS, 7, 1, 365),
    defaultAllowedSenders: overrides.defaultAllowedSenders ?? csv(process.env.DEFAULT_ALLOWED_SENDERS, ['fampay.in', 'famapp.in']),
    requireAuthenticatedEmail: overrides.requireAuthenticatedEmail ?? boolEnv(process.env.REQUIRE_AUTHENTICATED_EMAIL, true),
    creditKeywords: overrides.creditKeywords ?? csv(process.env.PAYMENT_CREDIT_KEYWORDS, ['received', 'credited', 'added']),
    dynamicWindowMinutes: overrides.dynamicWindowMinutes ?? intEnv(process.env.DYNAMIC_PAYMENT_WINDOW_MINUTES, 15, 1, 120),
    utrLookbackDays: overrides.utrLookbackDays ?? intEnv(process.env.UTR_LOOKBACK_DAYS, 30, 1, 365),
    maxEmailsToScan: overrides.maxEmailsToScan ?? intEnv(process.env.MAX_EMAILS_TO_SCAN, 150, 10, 1000),
    apiRateLimit: overrides.apiRateLimit ?? intEnv(process.env.API_RATE_LIMIT, 120, 10, 10000),
    verifyRateLimit: overrides.verifyRateLimit ?? intEnv(process.env.VERIFY_RATE_LIMIT, 30, 1, 1000),
    keyCreationRateLimit: overrides.keyCreationRateLimit ?? intEnv(process.env.KEY_CREATION_RATE_LIMIT, 10, 1, 100),
    sessionHours: overrides.sessionHours ?? 8,
  };

  if (!Number.isFinite(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }

  if (production) {
    if (String(config.encryptionKey).length < 32) throw new Error('ENCRYPTION_KEY must contain at least 32 characters in production.');
    if (String(config.sessionSecret).length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
    if (!config.adminPassword && !config.adminToken) throw new Error('Set ADMIN_PASSWORD or ADMIN_TOKEN in production.');
    if (!config.databaseUrl) throw new Error('DATABASE_URL is required in production.');
  }

  return config;
}

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { createAdminAuth, createApiKeyAuth, requireScope } from './auth.js';
import { createAdminSession, encryptJson, generateApiKey, hashApiKey, hashIp, keyPrefix, safeEqual } from './crypto.js';
import { keyStatus } from './db.js';
import { generatePaymentQr, normalizeAllowedSenders, verifyPaymentViaGmail } from './payment.js';
import { adminKeySchema, extendSchema, publicKeySchema, qrSchema, rotateSchema, verifySchema, zodError } from './validation.js';
import { openApiDocument } from './openapi.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function sendValidation(res, parsed) {
  return res.status(400).json({
    ok: false,
    error: { code: 'VALIDATION_ERROR', message: 'Please correct the request fields.', details: zodError(parsed.error) },
  });
}

function maskEmail(email) {
  if (!email || !email.includes('@')) return null;
  const [name, domain] = email.split('@');
  return `${name.slice(0, 1)}${'*'.repeat(Math.min(6, Math.max(2, name.length - 1)))}@${domain}`;
}

function serializeKey(key) {
  const status = keyStatus(key);
  return {
    id: key.id,
    label: key.label,
    contact_email: key.contact_email,
    gmail_hint: key.gmail_hint,
    key_prefix: key.key_prefix,
    scopes: key.scopes,
    status,
    expires_at: key.expires_at,
    expires_in_seconds: Math.max(0, Math.floor((new Date(key.expires_at).getTime() - Date.now()) / 1000)),
    revoked_at: key.revoked_at,
    created_at: key.created_at,
    last_used_at: key.last_used_at,
    requests_count: key.requests_count,
    created_by: key.created_by,
    verifier_configured: Boolean(key.config_enc && key.gmail_hint),
  };
}

async function issueKey({ store, config, data, createdBy, ttlHours, scopes }) {
  const plaintext = generateApiKey();
  const id = crypto.randomUUID();
  const allowedSenders = normalizeAllowedSenders(data.allowed_senders, config.defaultAllowedSenders);
  const hasConfig = Boolean(data.gmail || data.default_upi_id || data.payee_name);
  const encryptedConfig = hasConfig ? encryptJson({
    gmail: data.gmail || '',
    gmailAppPassword: data.gmail_app_password || '',
    defaultUpiId: data.default_upi_id || '',
    payeeName: data.payee_name || '',
    allowedSenders,
  }, config.encryptionKey) : null;
  const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString();
  const key = await store.createKey({
    id,
    label: data.label,
    contact_email: data.contact_email || null,
    gmail_hint: maskEmail(data.gmail),
    key_hash: hashApiKey(plaintext),
    key_prefix: keyPrefix(plaintext),
    config_enc: encryptedConfig,
    scopes,
    expires_at: expiresAt,
    created_by: createdBy,
  });
  return { plaintext, key };
}

function baseUrlFor(req, config) {
  return (config.appUrl || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}

export function createApp({ store, config }) {
  const app = express();
  const adminAuth = createAdminAuth(config);
  const apiKeyAuth = createApiKeyAuth({ store, config });

  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.set('view engine', 'ejs');
  app.set('views', path.join(rootDir, 'views'));

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));
  app.use(cookieParser());
  app.use('/assets', express.static(path.join(rootDir, 'public'), { maxAge: config.production ? '1d' : 0, etag: true }));

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: config.apiRateLimit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skip: (req) => req.path === '/healthz',
    message: { ok: false, error: { code: 'RATE_LIMITED', message: 'Too many requests. Please retry later.' } },
  });
  const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: config.verifyRateLimit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: { code: 'VERIFY_RATE_LIMITED', message: 'Too many verification checks. Please retry later.' } },
  });
  const creationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: config.keyCreationRateLimit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: { code: 'KEY_CREATION_RATE_LIMITED', message: 'Too many keys were requested from this IP.' } },
  });
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: 'Too many login attempts. Try again later.',
  });

  app.use('/api', generalLimiter);
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api/')) return next();
    const started = Date.now();
    res.on('finish', () => {
      const endpoint = req.path.replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, ':id').slice(0, 160);
      store.recordLog({
        key_id: req.apiKey?.id || null,
        endpoint,
        method: req.method,
        status: res.statusCode,
        latency_ms: Date.now() - started,
        ip_hash: hashIp(req.ip, config.sessionSecret),
      }).catch((error) => console.error('Request log write failed:', error.message));
    });
    next();
  });

  app.get('/healthz', (req, res) => {
    res.json({ ok: true, service: 'botastra-fampay-api', storage: store.kind, time: new Date().toISOString() });
  });

  app.get('/', (req, res) => {
    res.render('index', { title: 'BotAstra FamPay Verify API', publicKeyCreation: config.publicKeyCreation });
  });

  app.get('/setup', (req, res) => {
    res.render('setup', {
      title: 'Create API Key',
      enabled: config.publicKeyCreation,
      maxTtlDays: config.publicKeyMaxTtlDays,
      defaultTtlDays: Math.min(config.defaultKeyTtlDays, config.publicKeyMaxTtlDays),
      defaultAllowedSenders: config.defaultAllowedSenders.join(', '),
      accessCodeRequired: Boolean(config.setupAccessCode),
    });
  });

  app.get('/docs', (req, res) => {
    res.render('docs', { title: 'API Documentation', baseUrl: baseUrlFor(req, config) });
  });

  app.get('/openapi.json', (req, res) => res.json(openApiDocument(baseUrlFor(req, config))));

  app.get('/admin/login', (req, res) => {
    if (adminAuth.resolve(req)) return res.redirect('/admin');
    res.render('admin-login', { title: 'Admin Login', error: '' });
  });

  app.post('/admin/login', loginLimiter, (req, res) => {
    if (!config.adminPassword || !safeEqual(req.body.password || '', config.adminPassword)) {
      return res.status(401).render('admin-login', { title: 'Admin Login', error: 'Invalid admin password.' });
    }
    const { token } = createAdminSession(config.sessionSecret, config.sessionHours);
    res.cookie('botastra_admin', token, {
      httpOnly: true,
      secure: config.production,
      sameSite: 'strict',
      maxAge: config.sessionHours * 60 * 60 * 1000,
      path: '/',
    });
    return res.redirect('/admin');
  });

  app.post('/admin/logout', (req, res) => {
    res.clearCookie('botastra_admin', { path: '/' });
    res.redirect('/admin/login');
  });

  app.get('/admin', adminAuth.page, (req, res) => {
    res.render('admin', {
      title: 'Admin Dashboard',
      csrfToken: req.adminAuth.csrf || '',
      bearerMode: req.adminAuth.mode === 'bearer',
      storageKind: store.kind,
      defaultAllowedSenders: config.defaultAllowedSenders.join(', '),
    });
  });

  app.post('/api/v1/keys', creationLimiter, async (req, res) => {
    if (!config.publicKeyCreation) {
      return res.status(403).json({ ok: false, error: { code: 'PUBLIC_ISSUANCE_DISABLED', message: 'Public key creation is disabled. Ask the administrator to issue a key.' } });
    }
    const parsed = publicKeySchema.safeParse(req.body);
    if (!parsed.success) return sendValidation(res, parsed);
    if (config.setupAccessCode && !safeEqual(parsed.data.setup_access_code, config.setupAccessCode)) {
      return res.status(403).json({ ok: false, error: { code: 'INVALID_SETUP_CODE', message: 'The setup access code is invalid.' } });
    }
    const days = Math.min(parsed.data.expires_in_days || config.defaultKeyTtlDays, config.publicKeyMaxTtlDays);
    const issued = await issueKey({
      store,
      config,
      data: parsed.data,
      createdBy: 'self-service',
      ttlHours: days * 24,
      scopes: ['qr', 'verify'],
    });
    return res.status(201).json({
      ok: true,
      api_key: issued.plaintext,
      warning: 'Copy this API key now. It is stored only as a one-way hash and cannot be shown again.',
      key: serializeKey(issued.key),
    });
  });

  app.get('/api/v1/key', apiKeyAuth, (req, res) => {
    res.json({ ok: true, key: serializeKey(req.apiKey) });
  });

  app.post('/api/v1/qr', apiKeyAuth, requireScope('qr'), async (req, res) => {
    const parsed = qrSchema.safeParse(req.body);
    if (!parsed.success) return sendValidation(res, parsed);
    const upiId = parsed.data.upi_id || req.keyConfig?.defaultUpiId;
    const payeeName = parsed.data.payee_name || req.keyConfig?.payeeName;
    if (!upiId || !payeeName) {
      return res.status(422).json({ ok: false, error: { code: 'PAYEE_NOT_CONFIGURED', message: 'Pass upi_id and payee_name, or save defaults on this key.' } });
    }
    const result = await generatePaymentQr({ amount: parsed.data.amount, upiId, payeeName, note: parsed.data.note });
    return res.json({ ok: true, ...result });
  });

  app.post('/api/v1/verify', verifyLimiter, apiKeyAuth, requireScope('verify'), async (req, res) => {
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) return sendValidation(res, parsed);
    const result = await verifyPaymentViaGmail({
      ...parsed.data,
      keyId: req.apiKey.id,
      credentials: req.keyConfig || {},
      store,
      config,
    });
    return res.json({ ok: true, ...result });
  });

  app.get('/api/v1/admin/dashboard', adminAuth.api, async (req, res) => {
    const [stats, logs] = await Promise.all([store.stats(), store.listLogs(20)]);
    res.json({ ok: true, stats, logs });
  });

  app.get('/api/v1/admin/keys', adminAuth.api, async (req, res) => {
    const keys = await store.listKeys(300);
    res.json({ ok: true, keys: keys.map(serializeKey) });
  });

  app.post('/api/v1/admin/keys', adminAuth.api, async (req, res) => {
    const parsed = adminKeySchema.safeParse(req.body);
    if (!parsed.success) return sendValidation(res, parsed);
    const allowedSenders = normalizeAllowedSenders(parsed.data.allowed_senders, config.defaultAllowedSenders);
    if (parsed.data.scopes.includes('verify') && !allowedSenders.length) {
      return res.status(400).json({ ok: false, error: { code: 'SENDER_ALLOWLIST_REQUIRED', message: 'Add at least one trusted sender address or domain.' } });
    }
    const issued = await issueKey({
      store,
      config,
      data: parsed.data,
      createdBy: 'admin',
      ttlHours: parsed.data.expires_in_hours,
      scopes: parsed.data.scopes,
    });
    res.status(201).json({
      ok: true,
      api_key: issued.plaintext,
      warning: 'Copy this API key now. It cannot be retrieved later.',
      key: serializeKey(issued.key),
    });
  });

  app.post('/api/v1/admin/keys/:id/revoke', adminAuth.api, async (req, res) => {
    const key = await store.revokeKey(req.params.id);
    if (!key) return res.status(404).json({ ok: false, error: { code: 'KEY_NOT_FOUND', message: 'API key not found.' } });
    return res.json({ ok: true, key: serializeKey(key) });
  });

  app.post('/api/v1/admin/keys/:id/extend', adminAuth.api, async (req, res) => {
    const parsed = extendSchema.safeParse(req.body);
    if (!parsed.success) return sendValidation(res, parsed);
    const current = await store.getKeyById(req.params.id);
    if (!current) return res.status(404).json({ ok: false, error: { code: 'KEY_NOT_FOUND', message: 'API key not found.' } });
    const base = Math.max(Date.now(), new Date(current.expires_at).getTime());
    const key = await store.updateExpiry(current.id, new Date(base + parsed.data.hours * 60 * 60 * 1000).toISOString());
    return res.json({ ok: true, key: serializeKey(key) });
  });

  app.post('/api/v1/admin/keys/:id/rotate', adminAuth.api, async (req, res) => {
    const parsed = rotateSchema.safeParse(req.body || {});
    if (!parsed.success) return sendValidation(res, parsed);
    const oldKey = await store.getKeyById(req.params.id);
    if (!oldKey) return res.status(404).json({ ok: false, error: { code: 'KEY_NOT_FOUND', message: 'API key not found.' } });
    const plaintext = generateApiKey();
    const ttlMs = parsed.data.expires_in_hours
      ? parsed.data.expires_in_hours * 60 * 60 * 1000
      : Math.max(60 * 60 * 1000, new Date(oldKey.expires_at).getTime() - Date.now());
    const replacement = await store.createKey({
      id: crypto.randomUUID(),
      label: `${oldKey.label} (rotated)`.slice(0, 80),
      contact_email: oldKey.contact_email,
      gmail_hint: oldKey.gmail_hint,
      key_hash: hashApiKey(plaintext),
      key_prefix: keyPrefix(plaintext),
      config_enc: oldKey.config_enc,
      scopes: oldKey.scopes,
      expires_at: new Date(Date.now() + ttlMs).toISOString(),
      created_by: 'admin',
    });
    await store.revokeKey(oldKey.id);
    return res.status(201).json({
      ok: true,
      api_key: plaintext,
      warning: 'Copy this replacement key now. The old key has been revoked.',
      key: serializeKey(replacement),
    });
  });

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'API route not found.' } });
    }
    return res.status(404).render('404', { title: 'Not Found' });
  });

  app.use((error, req, res, next) => {
    console.error('Unhandled request error:', error);
    if (res.headersSent) return next(error);
    if (req.path.startsWith('/api/')) {
      return res.status(500).json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'An unexpected server error occurred.' } });
    }
    return res.status(500).send('An unexpected server error occurred.');
  });

  return app;
}

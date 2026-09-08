import { csrfForSession, decryptJson, hashApiKey, safeEqual, verifyAdminSession } from './crypto.js';
import { keyStatus } from './db.js';

export function extractBearer(req) {
  const authorization = req.get('authorization') || '';
  if (/^Bearer\s+/i.test(authorization)) return authorization.replace(/^Bearer\s+/i, '').trim();
  return '';
}

export function createApiKeyAuth({ store, config }) {
  return async function apiKeyAuth(req, res, next) {
    try {
      const token = (req.get('x-api-key') || extractBearer(req)).trim();
      if (!token || !token.startsWith('bta_live_')) {
        return res.status(401).json({ ok: false, error: { code: 'MISSING_API_KEY', message: 'Pass your key in X-API-Key or Authorization: Bearer.' } });
      }
      const key = await store.getKeyByHash(hashApiKey(token));
      if (!key) {
        return res.status(401).json({ ok: false, error: { code: 'INVALID_API_KEY', message: 'The API key is invalid.' } });
      }
      const status = keyStatus(key);
      if (status === 'revoked') {
        return res.status(403).json({ ok: false, error: { code: 'REVOKED_API_KEY', message: 'The API key was revoked.' } });
      }
      if (status === 'expired') {
        return res.status(403).json({ ok: false, error: { code: 'EXPIRED_API_KEY', message: 'The API key has expired.' } });
      }

      let keyConfig = null;
      if (key.config_enc) {
        try {
          keyConfig = decryptJson(key.config_enc, config.encryptionKey);
        } catch {
          return res.status(500).json({ ok: false, error: { code: 'KEY_CONFIG_ERROR', message: 'This key configuration cannot be decrypted. Contact the administrator.' } });
        }
      }
      req.apiKey = key;
      req.keyConfig = keyConfig;
      await store.touchKey(key.id);
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireScope(scope) {
  return function scopeGuard(req, res, next) {
    if (!req.apiKey?.scopes?.includes(scope)) {
      return res.status(403).json({ ok: false, error: { code: 'SCOPE_REQUIRED', message: `This API key does not include the ${scope} scope.` } });
    }
    next();
  };
}

export function createAdminAuth(config) {
  function resolve(req) {
    const bearer = extractBearer(req);
    if (bearer && config.adminToken && safeEqual(bearer, config.adminToken)) {
      return { mode: 'bearer', session: null, csrf: null };
    }
    const session = verifyAdminSession(req.cookies?.botastra_admin, config.sessionSecret);
    if (!session) return null;
    return { mode: 'cookie', session, csrf: csrfForSession(session.sid, config.sessionSecret) };
  }

  function api(req, res, next) {
    const auth = resolve(req);
    if (!auth) return res.status(401).json({ ok: false, error: { code: 'ADMIN_AUTH_REQUIRED', message: 'Administrator authentication is required.' } });
    req.adminAuth = auth;
    if (auth.mode === 'cookie' && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const supplied = req.get('x-csrf-token') || '';
      if (!safeEqual(supplied, auth.csrf)) {
        return res.status(403).json({ ok: false, error: { code: 'CSRF_FAILED', message: 'Security token is missing or invalid. Refresh the admin page.' } });
      }
    }
    next();
  }

  function page(req, res, next) {
    const auth = resolve(req);
    if (!auth) return res.redirect('/admin/login');
    req.adminAuth = auth;
    next();
  }

  return { resolve, api, page };
}

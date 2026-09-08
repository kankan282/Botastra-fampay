import crypto from 'node:crypto';

const AAD = Buffer.from('botastra:fampay-api:v1');

function deriveKey(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest();
}

export function encryptJson(value, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(secret), iv);
  cipher.setAAD(AAD);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

export function decryptJson(payload, secret) {
  if (!payload) return null;
  const [version, ivPart, tagPart, dataPart] = String(payload).split('.');
  if (version !== 'v1' || !ivPart || !tagPart || !dataPart) throw new Error('Unsupported encrypted payload.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(secret), Buffer.from(ivPart, 'base64url'));
  decipher.setAAD(AAD);
  decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataPart, 'base64url')), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

export function generateApiKey() {
  return `bta_live_${crypto.randomBytes(32).toString('base64url')}`;
}

export function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(String(apiKey)).digest('hex');
}

export function keyPrefix(apiKey) {
  return `${String(apiKey).slice(0, 16)}…`;
}

export function hashTransaction(kind, value) {
  return crypto.createHash('sha256').update(`${kind}:${String(value).trim().toLowerCase()}`).digest('hex');
}

export function hashIp(ip, secret) {
  return crypto.createHmac('sha256', deriveKey(secret)).update(String(ip || 'unknown')).digest('hex').slice(0, 24);
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left ?? ''));
  const b = Buffer.from(String(right ?? ''));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function createAdminSession(secret, hours = 8) {
  const payload = {
    sid: crypto.randomBytes(18).toString('base64url'),
    exp: Date.now() + hours * 60 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', deriveKey(secret)).update(encoded).digest('base64url');
  return { token: `${encoded}.${signature}`, payload };
}

export function verifyAdminSession(token, secret) {
  try {
    const [encoded, signature] = String(token || '').split('.');
    if (!encoded || !signature) return null;
    const expected = crypto.createHmac('sha256', deriveKey(secret)).update(encoded).digest('base64url');
    if (!safeEqual(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.sid || !payload.exp || payload.exp <= Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function csrfForSession(sessionId, secret) {
  return crypto.createHmac('sha256', deriveKey(secret)).update(`csrf:${sessionId}`).digest('base64url');
}

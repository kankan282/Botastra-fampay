import { Pool } from 'pg';

function iso(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function normalizeKey(row) {
  if (!row) return null;
  return {
    ...row,
    scopes: Array.isArray(row.scopes) ? row.scopes : JSON.parse(row.scopes || '[]'),
    created_at: iso(row.created_at),
    expires_at: iso(row.expires_at),
    revoked_at: iso(row.revoked_at),
    last_used_at: iso(row.last_used_at),
    requests_count: Number(row.requests_count || 0),
  };
}

export function keyStatus(key) {
  if (key.revoked_at) return 'revoked';
  if (new Date(key.expires_at).getTime() <= Date.now()) return 'expired';
  return 'active';
}

export class PostgresStore {
  constructor(connectionString, ssl = true) {
    this.pool = new Pool({
      connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      ssl: ssl ? { rejectUnauthorized: false } : false,
    });
    this.kind = 'postgres';
  }

  async init() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id UUID PRIMARY KEY,
        label VARCHAR(80) NOT NULL,
        contact_email VARCHAR(254),
        gmail_hint VARCHAR(254),
        key_hash CHAR(64) UNIQUE NOT NULL,
        key_prefix VARCHAR(24) NOT NULL,
        config_enc TEXT,
        scopes JSONB NOT NULL DEFAULT '["qr","verify"]'::jsonb,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        created_by VARCHAR(20) NOT NULL DEFAULT 'admin',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        requests_count BIGINT NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
      CREATE INDEX IF NOT EXISTS idx_api_keys_expiry ON api_keys(expires_at);

      CREATE TABLE IF NOT EXISTS verification_records (
        id UUID PRIMARY KEY,
        key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
        transaction_hash CHAR(64) UNIQUE NOT NULL,
        reference_preview VARCHAR(32),
        amount NUMERIC(14,2) NOT NULL,
        sender_name VARCHAR(120),
        payment_time TIMESTAMPTZ,
        email_message_id VARCHAR(500),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_verifications_key ON verification_records(key_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS api_request_logs (
        id BIGSERIAL PRIMARY KEY,
        key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
        endpoint VARCHAR(160) NOT NULL,
        method VARCHAR(10) NOT NULL,
        status INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        ip_hash VARCHAR(24),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_request_logs_created ON api_request_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_request_logs_key ON api_request_logs(key_id, created_at DESC);
    `);
  }

  async createKey(key) {
    const result = await this.pool.query(
      `INSERT INTO api_keys
        (id, label, contact_email, gmail_hint, key_hash, key_prefix, config_enc, scopes, expires_at, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)
       RETURNING *`,
      [key.id, key.label, key.contact_email || null, key.gmail_hint || null, key.key_hash, key.key_prefix,
        key.config_enc || null, JSON.stringify(key.scopes), key.expires_at, key.created_by],
    );
    return normalizeKey(result.rows[0]);
  }

  async getKeyByHash(hash) {
    const result = await this.pool.query('SELECT * FROM api_keys WHERE key_hash = $1 LIMIT 1', [hash]);
    return normalizeKey(result.rows[0]);
  }

  async getKeyById(id) {
    const result = await this.pool.query('SELECT * FROM api_keys WHERE id = $1 LIMIT 1', [id]);
    return normalizeKey(result.rows[0]);
  }

  async listKeys(limit = 200) {
    const result = await this.pool.query('SELECT * FROM api_keys ORDER BY created_at DESC LIMIT $1', [limit]);
    return result.rows.map(normalizeKey);
  }

  async touchKey(id) {
    await this.pool.query(
      'UPDATE api_keys SET last_used_at = NOW(), requests_count = requests_count + 1 WHERE id = $1',
      [id],
    );
  }

  async revokeKey(id) {
    const result = await this.pool.query(
      'UPDATE api_keys SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1 RETURNING *',
      [id],
    );
    return normalizeKey(result.rows[0]);
  }

  async updateExpiry(id, expiresAt) {
    const result = await this.pool.query(
      'UPDATE api_keys SET expires_at = $2 WHERE id = $1 RETURNING *',
      [id, expiresAt],
    );
    return normalizeKey(result.rows[0]);
  }

  async recordVerification(record) {
    try {
      await this.pool.query(
        `INSERT INTO verification_records
          (id, key_id, transaction_hash, reference_preview, amount, sender_name, payment_time, email_message_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [record.id, record.key_id, record.transaction_hash, record.reference_preview || null, record.amount,
          record.sender_name || null, record.payment_time || null, record.email_message_id || null],
      );
      return true;
    } catch (error) {
      if (error.code === '23505') return false;
      throw error;
    }
  }

  async recordLog(log) {
    await this.pool.query(
      `INSERT INTO api_request_logs (key_id, endpoint, method, status, latency_ms, ip_hash)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [log.key_id || null, log.endpoint, log.method, log.status, log.latency_ms, log.ip_hash || null],
    );
  }

  async listLogs(limit = 100) {
    const result = await this.pool.query(
      `SELECT l.id, l.endpoint, l.method, l.status, l.latency_ms, l.created_at,
              k.label AS key_label, k.key_prefix
       FROM api_request_logs l
       LEFT JOIN api_keys k ON k.id = l.key_id
       ORDER BY l.created_at DESC LIMIT $1`,
      [limit],
    );
    return result.rows.map((row) => ({ ...row, id: Number(row.id), created_at: iso(row.created_at) }));
  }

  async stats() {
    const result = await this.pool.query(`
      SELECT
        COUNT(*)::int AS total_keys,
        COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at > NOW())::int AS active_keys,
        COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at <= NOW())::int AS expired_keys,
        COUNT(*) FILTER (WHERE revoked_at IS NOT NULL)::int AS revoked_keys,
        COALESCE(SUM(requests_count), 0)::bigint AS total_requests
      FROM api_keys
    `);
    const activity = await this.pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM api_request_logs WHERE created_at >= date_trunc('day', NOW())) AS requests_today,
        (SELECT COUNT(*)::int FROM verification_records WHERE created_at >= date_trunc('day', NOW())) AS verifications_today,
        (SELECT COUNT(*)::int FROM verification_records) AS total_verifications
    `);
    return {
      ...result.rows[0],
      ...activity.rows[0],
      total_requests: Number(result.rows[0].total_requests || 0),
    };
  }

  async close() {
    await this.pool.end();
  }
}

export class MemoryStore {
  constructor() {
    this.kind = 'memory';
    this.keys = new Map();
    this.keyHashes = new Map();
    this.verifications = new Set();
    this.logs = [];
  }

  async init() {}

  async createKey(key) {
    const now = new Date().toISOString();
    const row = normalizeKey({
      ...key,
      contact_email: key.contact_email || null,
      gmail_hint: key.gmail_hint || null,
      config_enc: key.config_enc || null,
      revoked_at: null,
      created_at: now,
      last_used_at: null,
      requests_count: 0,
    });
    this.keys.set(row.id, row);
    this.keyHashes.set(row.key_hash, row.id);
    return { ...row };
  }

  async getKeyByHash(hash) {
    const id = this.keyHashes.get(hash);
    return id ? { ...this.keys.get(id) } : null;
  }

  async getKeyById(id) {
    const row = this.keys.get(id);
    return row ? { ...row } : null;
  }

  async listKeys(limit = 200) {
    return [...this.keys.values()]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, limit)
      .map((row) => ({ ...row }));
  }

  async touchKey(id) {
    const row = this.keys.get(id);
    if (!row) return;
    row.last_used_at = new Date().toISOString();
    row.requests_count += 1;
  }

  async revokeKey(id) {
    const row = this.keys.get(id);
    if (!row) return null;
    row.revoked_at ||= new Date().toISOString();
    return { ...row };
  }

  async updateExpiry(id, expiresAt) {
    const row = this.keys.get(id);
    if (!row) return null;
    row.expires_at = iso(expiresAt);
    return { ...row };
  }

  async recordVerification(record) {
    if (this.verifications.has(record.transaction_hash)) return false;
    this.verifications.add(record.transaction_hash);
    return true;
  }

  async recordLog(log) {
    this.logs.unshift({ id: this.logs.length + 1, created_at: new Date().toISOString(), ...log });
    this.logs = this.logs.slice(0, 2000);
  }

  async listLogs(limit = 100) {
    return this.logs.slice(0, limit).map((log) => {
      const key = log.key_id ? this.keys.get(log.key_id) : null;
      return { ...log, key_label: key?.label || null, key_prefix: key?.key_prefix || null };
    });
  }

  async stats() {
    const keys = [...this.keys.values()];
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    return {
      total_keys: keys.length,
      active_keys: keys.filter((key) => keyStatus(key) === 'active').length,
      expired_keys: keys.filter((key) => keyStatus(key) === 'expired').length,
      revoked_keys: keys.filter((key) => keyStatus(key) === 'revoked').length,
      total_requests: keys.reduce((sum, key) => sum + key.requests_count, 0),
      requests_today: this.logs.filter((log) => new Date(log.created_at) >= start).length,
      verifications_today: 0,
      total_verifications: this.verifications.size,
    };
  }

  async close() {}
}

export function createStore(config) {
  if (config.databaseUrl) return new PostgresStore(config.databaseUrl, config.databaseSsl);
  return new MemoryStore();
}

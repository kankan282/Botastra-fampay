import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { MemoryStore } from '../src/db.js';

async function fixture() {
  const config = loadConfig({
    nodeEnv: 'test',
    encryptionKey: 'e'.repeat(40),
    sessionSecret: 's'.repeat(40),
    adminPassword: 'admin-test-password',
    adminToken: 'admin-test-token',
    publicKeyCreation: true,
    publicKeyMaxTtlDays: 30,
    defaultKeyTtlDays: 7,
    defaultAllowedSenders: ['famapp.in'],
    apiRateLimit: 1000,
    verifyRateLimit: 1000,
    keyCreationRateLimit: 1000,
  });
  const store = new MemoryStore();
  await store.init();
  return { store, config, app: createApp({ store, config }) };
}

const publicPayload = {
  label: 'Test integration key',
  contact_email: 'owner@example.com',
  gmail: 'merchant@gmail.com',
  gmail_app_password: 'abcd efgh ijkl mnop',
  default_upi_id: 'merchant@fam',
  payee_name: 'Test Merchant',
  allowed_senders: 'famapp.in',
  expires_in_days: 3,
  setup_access_code: '',
  consent: true,
};

test('self-service issuance, key inspection, QR and expiry enforcement', async () => {
  const { app, store } = await fixture();
  const issued = await request(app).post('/api/v1/keys').send(publicPayload).expect(201);
  assert.match(issued.body.api_key, /^bta_live_/);
  assert.equal(issued.body.key.status, 'active');
  const key = issued.body.api_key;

  const status = await request(app).get('/api/v1/key').set('x-api-key', key).expect(200);
  assert.equal(status.body.key.label, publicPayload.label);
  assert.equal(status.body.key.verifier_configured, true);
  assert.equal(status.body.key.api_key, undefined);

  const qr = await request(app).post('/api/v1/qr').set('x-api-key', key).send({ amount: 25.01 }).expect(200);
  assert.equal(qr.body.ok, true);
  assert.match(qr.body.upi_uri, /^upi:\/\/pay\?/);
  assert.match(qr.body.qr_image, /^data:image\/png;base64,/);

  await store.updateExpiry(issued.body.key.id, new Date(Date.now() - 1000).toISOString());
  const expired = await request(app).get('/api/v1/key').set('x-api-key', key).expect(403);
  assert.equal(expired.body.error.code, 'EXPIRED_API_KEY');
});

test('admin bearer token issues, extends, rotates and revokes keys', async () => {
  const { app } = await fixture();
  const auth = { Authorization: 'Bearer admin-test-token' };
  const issued = await request(app).post('/api/v1/admin/keys').set(auth).send({
    label: 'Admin QR key', contact_email: '', gmail: '', gmail_app_password: '',
    default_upi_id: 'merchant@fam', payee_name: 'Merchant', allowed_senders: '',
    expires_in_hours: 24, scopes: ['qr'],
  }).expect(201);
  const id = issued.body.key.id;
  assert.match(issued.body.api_key, /^bta_live_/);

  const extended = await request(app).post(`/api/v1/admin/keys/${id}/extend`).set(auth).send({ hours: 24 }).expect(200);
  assert.equal(extended.body.key.status, 'active');

  const rotated = await request(app).post(`/api/v1/admin/keys/${id}/rotate`).set(auth).send({}).expect(201);
  assert.match(rotated.body.api_key, /^bta_live_/);
  assert.notEqual(rotated.body.api_key, issued.body.api_key);

  const old = await request(app).get('/api/v1/key').set('x-api-key', issued.body.api_key).expect(403);
  assert.equal(old.body.error.code, 'REVOKED_API_KEY');
  await request(app).post(`/api/v1/admin/keys/${rotated.body.key.id}/revoke`).set(auth).send({}).expect(200);
});

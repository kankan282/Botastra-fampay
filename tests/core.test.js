import test from 'node:test';
import assert from 'node:assert/strict';
import { decryptJson, encryptJson, generateApiKey, hashApiKey } from '../src/crypto.js';
import { amountMatches, extractPaymentReferences, normalizeAllowedSenders, senderAllowed } from '../src/payment.js';

test('encrypted configuration round-trips and rejects a wrong key', () => {
  const value = { gmail: 'owner@gmail.com', gmailAppPassword: 'secret-app-pass' };
  const encrypted = encryptJson(value, 'a'.repeat(32));
  assert.notEqual(encrypted, JSON.stringify(value));
  assert.deepEqual(decryptJson(encrypted, 'a'.repeat(32)), value);
  assert.throws(() => decryptJson(encrypted, 'b'.repeat(32)));
});

test('API keys have the BotAstra prefix and stable one-way hash', () => {
  const key = generateApiKey();
  assert.match(key, /^bta_live_[A-Za-z0-9_-]{40,}$/);
  assert.equal(hashApiKey(key), hashApiKey(key));
  assert.notEqual(hashApiKey(key), key);
});

test('sender allowlist supports exact addresses and domain subdomains', () => {
  const rules = normalizeAllowedSenders('alerts@famapp.in, fampay.in');
  assert.equal(senderAllowed(['alerts@famapp.in'], rules), true);
  assert.equal(senderAllowed(['notify@mail.fampay.in'], rules), true);
  assert.equal(senderAllowed(['fake-fampay.in@evil.test'], rules), false);
  assert.equal(senderAllowed(['attacker@notfampay.in'], rules), false);
});

test('amount matching respects numeric boundaries and credit context', () => {
  assert.equal(amountMatches('You received ₹25.01 from A', 25.01), true);
  assert.equal(amountMatches('INR 1,250.00 credited', 1250), true);
  assert.equal(amountMatches('You received 25.01 from A', 25.01), true);
  assert.equal(amountMatches('You received ₹125.01 from A', 25.01), false);
  assert.equal(amountMatches('Your balance is 25.01', 25.01), false);
});

test('UTR and transaction IDs are extracted', () => {
  const refs = extractPaymentReferences('UPI Ref No: 123456789012\nTransaction ID: FAMABC98765');
  assert.equal(refs.utr, '123456789012');
  assert.equal(refs.txnid, 'FAMABC98765');
});

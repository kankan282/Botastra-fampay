import crypto from 'node:crypto';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import QRCode from 'qrcode';
import { hashTransaction } from './crypto.js';

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function normalizeAllowedSenders(value, defaults = []) {
  const input = Array.isArray(value) ? value : String(value || '').split(',');
  const normalized = input
    .map((rule) => String(rule).trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
  const rules = normalized.length ? normalized : defaults.map((item) => String(item).trim().toLowerCase()).filter(Boolean);
  return [...new Set(rules)].slice(0, 10);
}

export function senderAllowed(addresses, rules) {
  if (!Array.isArray(rules) || rules.length === 0) return false;
  return addresses.some((rawAddress) => {
    const address = String(rawAddress || '').trim().toLowerCase();
    const domain = address.split('@')[1] || '';
    return rules.some((rawRule) => {
      const rule = String(rawRule).trim().toLowerCase().replace(/^@/, '');
      if (!rule) return false;
      if (rule.includes('@')) return address === rule;
      return domain === rule || domain.endsWith(`.${rule}`);
    });
  });
}

export function hasAuthenticatedSender(headers) {
  const value = headers?.get?.('authentication-results');
  const text = Array.isArray(value) ? value.join(' ') : String(value || '');
  return /\b(?:spf|dkim|dmarc)=pass\b/i.test(text);
}

export function amountMatches(text, amount, creditKeywords = ['received', 'credited', 'added']) {
  const numeric = Number(amount);
  if (!Number.isFinite(numeric) || numeric <= 0) return false;
  const fixed = numeric.toFixed(2);
  const [whole, fraction] = fixed.split('.');
  const grouped = Number(whole).toLocaleString('en-IN');
  const variants = new Set([fixed, `${whole}.${fraction}`, `${grouped}.${fraction}`]);
  if (fraction === '00') {
    variants.add(whole);
    variants.add(grouped);
  }
  const numberPattern = [...variants].map(escapeRegex).sort((a, b) => b.length - a.length).join('|');
  const boundaryPattern = `(?<![\\d.])(?:${numberPattern})(?![\\d.])`;
  const currencyPattern = new RegExp(`(?:₹|rs\\.?|inr)\\s*${boundaryPattern}|${boundaryPattern}\\s*(?:₹|rs\\.?|inr)`, 'i');
  if (currencyPattern.test(text)) return true;

  const plainPattern = new RegExp(boundaryPattern, 'gi');
  let match;
  while ((match = plainPattern.exec(text)) !== null) {
    const context = text.slice(Math.max(0, match.index - 90), Math.min(text.length, match.index + match[0].length + 90)).toLowerCase();
    if (creditKeywords.some((keyword) => context.includes(keyword.toLowerCase()))) return true;
  }
  return false;
}

export function extractPaymentReferences(text, supplied = {}) {
  const utrMatch = String(text).match(/(?:utr|upi\s*ref(?:erence)?(?:\s*no)?|ref(?:erence)?\s*no)\s*[:#-]?\s*(\d{12})/i);
  const txnMatch = String(text).match(/(?:transaction|txn)\s*(?:id|no)?\s*[:#-]?\s*([a-zA-Z0-9._-]{6,100})/i);
  return {
    utr: supplied.utr || utrMatch?.[1] || null,
    txnid: supplied.txnid || txnMatch?.[1] || null,
  };
}

function extractSenderName(text) {
  const patterns = [
    /(?:received\s+(?:₹|rs\.?|inr)?[\d,.]+\s+from|received\s+from|sender)\s+([a-zA-Z][a-zA-Z .'-]{1,60})/i,
    /(?:from)\s+([a-zA-Z][a-zA-Z .'-]{1,60})\s+(?:via|on|at|utr|upi)/i,
  ];
  for (const pattern of patterns) {
    const match = String(text).match(pattern);
    if (match?.[1]) return match[1].trim().replace(/\s+/g, ' ').slice(0, 100);
  }
  return 'UPI User';
}

function errorResult(error) {
  const message = String(error?.message || error || 'Unknown IMAP error');
  const auth = /authenticationfailed|invalid credentials|auth(?:entication)? failed|application-specific password required/i.test(message);
  const timeout = /timeout|timed out|etimedout/i.test(message);
  return {
    verified: false,
    code: auth ? 'INVALID_GMAIL_CREDENTIALS' : timeout ? 'IMAP_TIMEOUT' : 'IMAP_ERROR',
    message: auth ? 'Gmail authentication failed. Check the Gmail address and App Password.'
      : timeout ? 'Gmail took too long to respond. Please retry.'
        : 'Payment inbox could not be checked.',
    details: message.slice(0, 300),
  };
}

export async function generatePaymentQr({ amount, upiId, payeeName, note = '' }) {
  const params = new URLSearchParams({
    pa: upiId,
    pn: payeeName,
    am: Number(amount).toFixed(2),
    cu: 'INR',
  });
  if (note) params.set('tn', note);
  const upiUri = `upi://pay?${params.toString()}`;
  const qrImage = await QRCode.toDataURL(upiUri, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 420,
    color: { dark: '#111827', light: '#ffffff' },
  });
  const now = new Date();
  return {
    qr_image: qrImage,
    upi_uri: upiUri,
    upi_id: upiId,
    amount: Number(amount).toFixed(2),
    name: payeeName,
    created_at: now.toISOString(),
    created_at_ist: now.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
  };
}

export async function verifyPaymentViaGmail({ amount, utr, txnid, keyId, credentials, store, config }) {
  const gmail = String(credentials.gmail || '').trim().toLowerCase();
  const appPassword = String(credentials.gmailAppPassword || '').replace(/\s/g, '');
  const allowedSenders = normalizeAllowedSenders(credentials.allowedSenders, config.defaultAllowedSenders);

  if (!gmail || !appPassword) {
    return { verified: false, code: 'VERIFIER_NOT_CONFIGURED', message: 'This API key has no Gmail verifier configuration.' };
  }
  if (!allowedSenders.length) {
    return { verified: false, code: 'SENDER_ALLOWLIST_REQUIRED', message: 'No trusted payment-email sender is configured.' };
  }

  const client = new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: { user: gmail, pass: appPassword },
    logger: false,
    connectionTimeout: 12_000,
    greetingTimeout: 12_000,
    socketTimeout: 25_000,
    tls: { rejectUnauthorized: true, servername: 'imap.gmail.com' },
  });

  const explicitReference = utr || txnid;
  const windowMs = explicitReference
    ? config.utrLookbackDays * 24 * 60 * 60 * 1000
    : config.dynamicWindowMinutes * 60 * 1000;
  const since = new Date(Date.now() - windowMs);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX', { readOnly: true });

    let uids;
    if (explicitReference) {
      uids = await client.search({
        since,
        or: [{ body: String(explicitReference) }, { subject: String(explicitReference) }],
      }, { uid: true });
    } else {
      uids = await client.search({ since }, { uid: true });
    }

    const recentUids = [...uids].sort((a, b) => b - a).slice(0, config.maxEmailsToScan);
    for (const uid of recentUids) {
      const message = await client.fetchOne(uid, { source: true, internalDate: true, envelope: true }, { uid: true });
      if (!message?.source) continue;
      const parsed = await simpleParser(message.source);
      const addresses = parsed.from?.value?.map((entry) => entry.address).filter(Boolean) || [];
      if (!senderAllowed(addresses, allowedSenders)) continue;
      if (config.requireAuthenticatedEmail && !hasAuthenticatedSender(parsed.headers)) continue;

      const body = parsed.text || parsed.html || '';
      const fullText = `${parsed.subject || ''}\n${typeof body === 'string' ? body : ''}`;
      const lowered = fullText.toLowerCase();
      if (!config.creditKeywords.some((keyword) => lowered.includes(keyword.toLowerCase()))) continue;

      const paymentDate = parsed.date || message.internalDate || new Date();
      const paymentMs = new Date(paymentDate).getTime();
      if (!explicitReference && (paymentMs < Date.now() - windowMs || paymentMs > Date.now() + 5 * 60 * 1000)) continue;
      if (!amountMatches(fullText, amount, config.creditKeywords)) continue;

      if (utr && !new RegExp(`(?<!\\d)${escapeRegex(utr)}(?!\\d)`).test(fullText)) continue;
      if (txnid && !new RegExp(`(?<![a-zA-Z0-9])${escapeRegex(txnid)}(?![a-zA-Z0-9])`, 'i').test(fullText)) continue;

      const refs = extractPaymentReferences(fullText, { utr, txnid });
      const messageIdentity = parsed.messageId || `${gmail}:${uid}:${new Date(paymentDate).toISOString()}:${Number(amount).toFixed(2)}`;
      const referenceKind = refs.utr ? 'utr' : refs.txnid ? 'txnid' : 'email';
      const referenceValue = refs.utr || refs.txnid || messageIdentity;
      const transactionHash = hashTransaction(referenceKind, referenceValue);
      const senderName = extractSenderName(fullText);
      const recorded = await store.recordVerification({
        id: crypto.randomUUID(),
        key_id: keyId,
        transaction_hash: transactionHash,
        reference_preview: refs.utr ? `UTR …${refs.utr.slice(-4)}` : refs.txnid ? `TXN …${refs.txnid.slice(-4)}` : 'email fingerprint',
        amount: Number(amount),
        sender_name: senderName,
        payment_time: new Date(paymentDate).toISOString(),
        email_message_id: parsed.messageId || null,
      });

      if (!recorded) {
        return {
          verified: false,
          code: 'TRANSACTION_ALREADY_VERIFIED',
          message: 'This transaction was already verified.',
        };
      }

      return {
        verified: true,
        transaction_id: refs.txnid || refs.utr || undefined,
        amount: Number(amount),
        utr: refs.utr,
        sender_name: senderName,
        payment_time: new Date(paymentDate).toISOString(),
        payment_time_ist: new Date(paymentDate).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
      };
    }

    return {
      verified: false,
      code: 'TRANSACTION_NOT_FOUND',
      message: 'No matching trusted payment email was found.',
      details: explicitReference
        ? `Checked trusted payment emails from the last ${config.utrLookbackDays} day(s).`
        : `Checked trusted payment emails from the last ${config.dynamicWindowMinutes} minute(s).`,
    };
  } catch (error) {
    return errorResult(error);
  } finally {
    try {
      if (client.usable) await client.logout();
    } catch {
      client.close();
    }
  }
}

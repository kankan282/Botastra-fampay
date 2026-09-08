# BotAstra FamPay Verify API

A complete, Render-ready Node.js API for generating UPI QR codes and verifying trusted FamPay/FamApp payment-alert emails through Gmail IMAP.

**Owner / maintainer credit:** `@botastra`

> This is an independent project and is not affiliated with, endorsed by, or an official API of FamPay/FamApp. Email alerts can be delayed or changed. Do not treat email matching as the only control for high-value fulfilment.

## Included

- Expiring, revocable, rotatable API keys (`bta_live_…`)
- API keys stored only as SHA-256 hashes
- Gmail App Passwords and payment profiles encrypted with AES-256-GCM
- Public setup page with optional access code
- Admin dashboard and separate `ADMIN_TOKEN` API authentication
- Key scopes: `qr` and `verify`
- Dynamic exact-amount matching (default 15-minute window)
- Manual 12-digit UTR and Txn ID lookup
- Sender-domain/address allowlist and optional SPF/DKIM/DMARC pass requirement
- Database-level replay prevention using unique transaction fingerprints
- UPI URI + base64 QR generation
- PostgreSQL persistence and automatic schema initialization
- Render Blueprint, health check, Dockerfile, OpenAPI document, tests, and responsive UI

## Quick local start

Requirements: Node.js 20+.

```bash
cp .env.example .env
npm install
npm test
npm start
```

Open `http://localhost:3000`. Without `DATABASE_URL`, local development uses non-persistent memory storage. Production intentionally requires PostgreSQL.

## Render deployment

1. Extract this package into a **private** GitHub/GitLab repository.
2. Keep `render.yaml` in the repository root.
3. In Render, choose **New → Blueprint** and connect the repository.
4. Render prompts for `ADMIN_PASSWORD`; use a long unique password.
5. Apply the Blueprint. It creates the Node web service and PostgreSQL database.
6. Open the deployed `/admin` page and issue a short-lived test key.
7. Check a genuine payment email with Gmail's **Show original** view. Update `DEFAULT_ALLOWED_SENDERS` to the exact real sender/domain if required.
8. Send and verify a small unique-decimal payment such as ₹1.01 before production use.

Render currently documents that free PostgreSQL databases expire after 30 days. Upgrade or migrate before expiry for durable production use: <https://render.com/docs/free>

## Important environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string; wired by `render.yaml` |
| `ENCRYPTION_KEY` | Encrypts Gmail credentials/profile data; do not change casually |
| `SESSION_SECRET` | Signs admin cookies and hashes request IP metadata |
| `ADMIN_PASSWORD` | Password for `/admin` |
| `ADMIN_TOKEN` | Bearer token for admin REST endpoints |
| `PUBLIC_KEY_CREATION` | Enables/disables `/setup` issuance |
| `SETUP_ACCESS_CODE` | Optional shared code required by public setup |
| `DEFAULT_ALLOWED_SENDERS` | Exact addresses/domains, comma-separated |
| `REQUIRE_AUTHENTICATED_EMAIL` | Requires SPF, DKIM, or DMARC `pass` in Gmail headers |
| `DYNAMIC_PAYMENT_WINDOW_MINUTES` | Recent window for amount-only matching (default 15) |
| `UTR_LOOKBACK_DAYS` | Search window for explicit UTR/Txn ID (default 30) |

Never commit `.env`. Back up `ENCRYPTION_KEY` securely: replacing it makes existing verifier profiles undecryptable.

## Gmail setup

Use a Google **App Password**, never the normal account password:

1. Enable 2-Step Verification on the Google account that receives payment alerts.
2. Open <https://myaccount.google.com/apppasswords>.
3. Create an App Password and use the 16-character value on `/setup` or in the admin dashboard.
4. Confirm that IMAP access is available for the account.

The server can read matching inbox messages through IMAP. Only connect an inbox you own or are authorized to use.

## API examples

Set:

```bash
export BASE_URL="https://your-service.onrender.com"
export BOTASTRA_API_KEY="bta_live_..."
```

### Generate QR

```bash
curl -X POST "$BASE_URL/api/v1/qr" \
  -H "X-API-Key: $BOTASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":25.01,"note":"Order 1042"}'
```

If a key has no saved payee defaults, also pass `upi_id` and `payee_name`.

### Verify recent unique amount

```bash
curl -X POST "$BASE_URL/api/v1/verify" \
  -H "X-API-Key: $BOTASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":25.01}'
```

### Verify with UTR

```bash
curl -X POST "$BASE_URL/api/v1/verify" \
  -H "X-API-Key: $BOTASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":25.01,"utr":"123456789012"}'
```

### Inspect key

```bash
curl "$BASE_URL/api/v1/key" -H "X-API-Key: $BOTASTRA_API_KEY"
```

### Admin key list

```bash
curl "$BASE_URL/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The complete machine-readable description is at `/openapi.json`; human documentation is at `/docs`.

## Security behavior

- Public setup is rate limited. For a private service, set `PUBLIC_KEY_CREATION=false` or configure `SETUP_ACCESS_CODE`.
- The app never logs request bodies, API keys, Gmail addresses in clear, or Gmail App Passwords.
- The trusted sender allowlist is mandatory for verification. An exact sender email is safer than a whole domain.
- `REQUIRE_AUTHENTICATED_EMAIL=true` rejects messages where Gmail exposes no SPF/DKIM/DMARC pass. Forwarded alerts may need testing.
- A successful match inserts a unique hash for its UTR, Txn ID, or message identity. Concurrent reuse is rejected at database level.
- Dynamic amount matching should use unique decimals and a short window. Manual UTR is safer when available.
- Rotate `ADMIN_TOKEN`, API keys, and App Passwords after suspected exposure.

## Project structure

```text
src/              API, auth, crypto, database, IMAP verification
views/            EJS pages and admin dashboard
public/           Local CSS and browser JavaScript
tests/            Node test runner + API integration tests
render.yaml       One-click Render Blueprint
openapi.json      Served dynamically at /openapi.json
```

## Attribution and license

This application is MIT licensed. The email-verification concept and portions of the matching approach were adapted from the MIT-licensed [`Sagexdd/fampay-verify`](https://github.com/Sagexdd/fampay-verify) project. Its copyright notice is preserved in `LICENSE` and `THIRD_PARTY_NOTICES.md`.

The API platform, key system, encryption layer, PostgreSQL store, dashboard, hardening, and Render package are maintained under owner credit **@botastra**.

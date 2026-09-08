# Render par deploy — Hindi / Hinglish guide

## 1. ZIP ko GitHub par dalo

1. ZIP extract karo.
2. GitHub par **private repository** banao.
3. Extracted folder ke andar ke saare files push karo.
4. Check karo ki `render.yaml` repository ke root mein ho.

## 2. Render Blueprint banao

1. Render Dashboard → **New** → **Blueprint**.
2. Apna GitHub repository connect karo.
3. Render `render.yaml` detect karega.
4. `ADMIN_PASSWORD` maangega—strong aur unique password set karo.
5. **Apply** par click karo.

Blueprint automatically:

- Node.js web service banayega;
- PostgreSQL database connect karega;
- `ENCRYPTION_KEY`, `SESSION_SECRET`, aur `ADMIN_TOKEN` generate karega;
- `/healthz` health check set karega.

> Render ka free PostgreSQL database filhaal 30 din ke baad expire hota hai. Production ke liye expiry se pehle upgrade/migrate karna hoga.

## 3. Deploy ke baad

- Home: `https://YOUR-SERVICE.onrender.com/`
- Key setup: `/setup`
- API docs: `/docs`
- Admin dashboard: `/admin`
- OpenAPI: `/openapi.json`

Admin login mein wahi `ADMIN_PASSWORD` use karo jo Render par set kiya tha.

## 4. Gmail App Password

Normal Gmail password **kabhi mat dalo**.

1. Google Account mein 2-Step Verification on karo.
2. <https://myaccount.google.com/apppasswords> kholo.
3. 16-character App Password banao.
4. `/setup` ya admin dashboard mein Gmail aur App Password set karo.

Sirf apna ya authorized Gmail inbox connect karo.

## 5. Real sender confirm karo

Gmail mein asli payment alert kholo → three-dot menu → **Show original**. Sender email/domain check karo. Agar sender `fampay.in` ya `famapp.in` nahi hai to Render Environment mein:

```env
DEFAULT_ALLOWED_SENDERS=exact-alert@example.com,example.com
```

Exact email address poore domain se zyada safe hai. Change ke baad redeploy karo.

## 6. API key ka use

Key header:

```http
X-API-Key: bta_live_...
```

QR:

```bash
curl -X POST "https://YOUR-SERVICE.onrender.com/api/v1/qr" \
  -H "X-API-Key: bta_live_..." \
  -H "Content-Type: application/json" \
  -d '{"amount":1.01}'
```

Payment verify:

```bash
curl -X POST "https://YOUR-SERVICE.onrender.com/api/v1/verify" \
  -H "X-API-Key: bta_live_..." \
  -H "Content-Type: application/json" \
  -d '{"amount":1.01}'
```

UTR ke saath:

```bash
curl -X POST "https://YOUR-SERVICE.onrender.com/api/v1/verify" \
  -H "X-API-Key: bta_live_..." \
  -H "Content-Type: application/json" \
  -d '{"amount":1.01,"utr":"123456789012"}'
```

## 7. Zaroori security settings

- Public setup nahi chahiye: `PUBLIC_KEY_CREATION=false`
- Setup ko code se lock karna hai: `SETUP_ACCESS_CODE=strong-secret-code`
- `ENCRYPTION_KEY` badalne se purane encrypted Gmail configs open nahi honge.
- Pehle ₹1.01 jaise unique decimal amount se end-to-end test karo.
- Email verification official FamPay/FamApp webhook nahi hai; high-value order ke liye ise akela proof mat rakho.

**Owner credit: `@botastra`**

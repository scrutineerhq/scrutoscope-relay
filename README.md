# Scrutinizer Relay

A **zero-knowledge relay** for sharing [Scrutinizer](https://scrutineer.dev/scrutinizer) performance reports. It runs as a single Cloudflare Worker and does exactly one thing: store an already-encrypted report and hand it back to whoever has the link — without ever being able to read it.

> **Looking for the product?** The profiler, what it measures, and how to use it all live at **[scrutineer.dev/scrutinizer](https://scrutineer.dev/scrutinizer)**. This repo is just the sharing relay.

## Why this is open source

Transparency, not forking. When you click **"Send to Support"** in Scrutinizer, your report leaves your server — so you should be able to read exactly what the receiving end does with it. That's the entire reason this code is public: so anyone can verify that the relay genuinely cannot see report contents. You're welcome to run your own, but it's published to be *audited*, not cloned.

## Zero-knowledge in one paragraph

Your browser compresses and encrypts the report with **AES-256-GCM** before anything is uploaded. The relay receives only **ciphertext + a little metadata** and stores it in R2. The decryption key never reaches the server: it lives in the URL **fragment** (`https://…/r/<id>#<key>`), and browsers never send the fragment in HTTP requests. The recipient's browser reads the key from the fragment and decrypts locally. The operator of this relay — including us — cannot decrypt a stored report.

### What the relay stores vs. never sees

| Stored (R2) | Never sent to the server |
|---|---|
| Ciphertext (AES-256-GCM) | The decryption key (URL fragment only) |
| The AES initialization vector | The plaintext report |
| Flags: `has_passphrase`, `expire_after_reading`, `compressed` | Your passphrase (if used) |
| TTL / expiry, created-at timestamps | The wrapped data key (also fragment-only for passphrase shares) |
| A random revocation token, KDF salt/iterations (non-secret) | |

## Lifecycle & safety features

- **Encryption** — AES-256-GCM, client-side. Payloads are gzip-compressed before encryption and decompressed in the viewer after decryption.
- **Optional passphrase** — wraps the data key with a key derived via **PBKDF2 (600k iterations, SHA-256, per-report random salt)**. The KDF parameters travel as non-secret metadata; older shares decrypt via a documented legacy fallback. Brute force is offline-only and gated by key strength, so the relay does no rate-limiting theatre around it.
- **Storage** — ciphertext in a Cloudflare R2 bucket, keyed by a 128-bit random capability ID. Metadata rides along as R2 `customMetadata`.
- **TTL / expiry** — share links expire after **1–30 days** (chosen at share time, default 7). A TTL of 0 creates a permanent link (used for demo/marketing reports). Expired objects are deleted on access and reaped by lifecycle rules.
- **Expire-after-reading** — optional burn-after-read. The viewer only confirms the read (`POST /r/{id}/confirm-read`) **after a successful decrypt**, so a transient network error can't destroy the only copy, and a bare `GET` can't silently burn someone else's report.
- **Revocation** — `DELETE /r/{id}` with the report's revocation token (256-bit, compared in constant time) removes it immediately. Because every response that carries report content is `Cache-Control: no-store`, there's no shared cache to purge.
- **Rate limiting** — a Durable Object sliding window throttles abusive create/read volume. Client IPs are **HMAC-SHA256 hashed** before they touch storage (no raw IPs persisted); if no hashing secret is configured the limiter **fails open** rather than storing a weakly-pseudonymized IP. Rate limiting is an availability measure, not a security boundary.

## Viewer safety

The viewer renders attacker-controllable JSON (anyone can craft a report and send a link), so it's hardened accordingly:

- **CSP with a per-response nonce** — no `script-src 'unsafe-inline'`; non-viewer responses fall back to `script-src 'none'`.
- **Output escaping** — every report field is HTML-/attribute-escaped before it reaches the DOM. No report content is ever executed.
- **Decompression cap** — gzip output is bounded to guard against decompression bombs.
- **Prototype-pollution-safe** — report-keyed maps use null-prototype objects, so crafted keys (`__proto__`, `constructor`) can't pollute or break rendering.
- **Security headers** — HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.

## HTTP API

| Method & path | Purpose |
|---|---|
| `POST /r/` | Store an encrypted report; returns the capability ID + revocation token. |
| `GET /r/{id}` | Serve the viewer SPA (HTML). |
| `GET /r/{id}/data` | Return the ciphertext + metadata for client-side decryption. |
| `POST /r/{id}/confirm-read` | Confirm a successful decrypt; deletes burn-after-read reports. |
| `DELETE /r/{id}` | Revoke (requires `X-Revoke-Token`). |
| `GET /view` | File-upload viewer — drop a local JSON export, no server round-trip. |

## Configuration

Bindings (see `wrangler.toml`):

- **R2 bucket** `REPORTS` — ciphertext storage.
- **Durable Object** `RATE_LIMITER` (`RateLimiterDO`) — rate limiting.

Secret:

- **`IP_HASH_SECRET`** — HMAC key used to pseudonymize client IPs for rate limiting. Set it in production (`wrangler secret put IP_HASH_SECRET`); without it, rate limiting fails open and no IP hash is stored.

## Development

```sh
npm install
npm run check     # node --check worker.js
npm run build     # wrangler deploy --dry-run (bundle + binding validation)
npm test          # vitest unit tests
npx wrangler dev  # local
```

CI runs the lint, build, and unit tests on every pull request.

## License

GPL-2.0-or-later. Part of [The Scrutineer Project](https://scrutineer.dev).

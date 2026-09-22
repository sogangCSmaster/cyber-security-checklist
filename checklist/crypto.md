# CRYPTO · Hashing, tokens, randomness, transport

Cryptography fails in a small number of boringly repeatable ways: a fast hash on passwords, a
predictable "random" token, a comparison that leaks timing, plaintext on the wire, or a home-grown
scheme. You do not need to invent anything here — you need to use the vetted primitive correctly.

← [Back to the checklist](../checklist.md) · Related: [`DATA`](./data.md), [`AUTH`](./authentication.md), [`LEAK`](./leakage.md), [`WEB`](./web.md)

---

### CRYPTO-01
**P0 · code** — Passwords hashed with argon2id, bcrypt, or scrypt, salted per password. This is [`DATA-06`](./data.md#data-06).

- **Why:** Yahoo used MD5; Zynga used SHA-1 for some accounts and legacy MD5 for others. A fast or unsalted hash means a stolen table is cracked, not merely stolen.
- **Detect:** find the password hashing call; MD5, SHA-1, SHA-256, or unsalted anything fails.
- **Fix:** argon2id (preferred) with sound parameters, or bcrypt/scrypt; a unique salt per password (the library handles it).
- **Verify:** stored hashes carry a modern algorithm identifier and a per-password salt.

### CRYPTO-02
**P1 · code** — Tokens, session IDs, reset codes, and secrets come from a cryptographically secure RNG.

- **Why:** a session ID or password-reset token from `Math.random()`, a timestamp, or a sequential counter is predictable, and a predictable token is a guessable credential.
- **Detect:** grep for `Math.random`, `rand()`, `mt_rand`, `uuid1` (time-based), or counters used for tokens, IDs, or codes.
- **Fix:** use a CSPRNG (`crypto.randomBytes`, `secrets` module, `SecureRandom`); enough entropy (≥128 bits) for anything security-bearing.
- **Verify:** confirm every security token is CSPRNG-derived; sampled tokens show no structure or predictability.

### CRYPTO-03
**P1 · code** — Comparisons of secrets are constant-time. This backstops [`LEAK-02`](./leakage.md#leak-02).

- **Why:** `==` on a token, HMAC, or API key returns as soon as a byte differs, leaking the correct value one byte at a time under measurement.
- **Detect:** grep for `==`/`!=`/`.equals` on tokens, signatures, HMACs, or API keys.
- **Fix:** `hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual` — constant-time comparison for all secret material.
- **Verify:** secret comparisons use a constant-time function.

### CRYPTO-04
**P1 · config** — TLS everywhere, modern configuration. No credential or sensitive data over plaintext, no disabled certificate validation.

- **Why:** plaintext transport lets a network attacker read or alter data; disabled validation (a client that skips certificate checks "to make it work") removes the protection entirely.
- **Detect:** grep for `http://` endpoints handling data, `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`, `TrustAllCerts`; check TLS config for old protocols/ciphers.
- **Fix:** TLS 1.2+ everywhere with a modern cipher suite; never disable validation; enforce HTTPS ([`WEB-02`](./web.md#web-02)).
- **Verify:** no code disables TLS validation; a plaintext request to a data endpoint is refused/redirected.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example) — check HSTS and HTTP→HTTPS redirect.

### CRYPTO-05
**P1 · code** — No home-grown cryptography. Use vetted libraries and authenticated encryption; manage and rotate keys.

- **Why:** custom ciphers, ECB mode, static IVs, and unauthenticated encryption fail in ways their authors cannot see. Keys hard-coded or never rotated ([`CRED`](./secrets.md)) are the other half.
- **Detect:** grep for custom encryption, `ECB`, static/zero IVs, encryption without a MAC; check where keys live and whether they rotate.
- **Fix:** use a high-level vetted library and an AEAD mode (AES-GCM, ChaCha20-Poly1305); store keys in a KMS/secret manager; rotate them.
- **Verify:** encryption uses an AEAD construction from a standard library and keys come from managed storage.

### CRYPTO-06
**P2 · config** — Sensitive data encrypted at rest. This is [`DATA-07`](./data.md#data-07).

- **Why:** Marriott, 2018 — 5.25M unencrypted passport numbers.
- **Detect:** which sensitive fields/objects are encrypted at rest?
- **Fix:** encrypt sensitive data at rest with managed keys.
- **Verify:** sensitive stores are encrypted and keys are managed.

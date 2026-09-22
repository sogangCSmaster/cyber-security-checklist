# CRYPTO · Hashing, tokens, randomness, transport

Cryptography fails in a small number of boringly repeatable ways: a fast hash on passwords, a
predictable "random" token, a comparison that leaks timing, plaintext on the wire, or a home-grown
scheme. You do not need to invent anything here — you need to use the vetted primitive correctly.

← [Back to the checklist](../checklist.md) · Related: [`DATA`](./data.md), [`AUTH`](./authentication.md), [`LEAK`](./leakage.md), [`WEB`](./web.md)

---

### CRYPTO-01
**P0 · code** — Passwords are hashed one-way with argon2id, scrypt, or bcrypt — never encrypted, never a fast hash. Full treatment: [`DATA-06`](./data.md#data-06).

- **Why:** LinkedIn (unsalted SHA-1, 117M), Yahoo (MD5), Zynga (SHA-1). A fast or unsalted hash means a stolen table is cracked, not merely stolen; reversible encryption means one stolen key reveals every password.
- **Detect:** find the password storage call; MD5, SHA-1, SHA-256, unsalted anything, or `encrypt()` fails.
- **Fix:** see [`DATA-06`](./data.md#data-06) — algorithm, OWASP parameters, and upgrading legacy hashes at next sign-in.
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
**P2 · config** — Disk, volume, and backup encryption is on everywhere. This is the floor under [`DATA-07`](./data.md#data-07), not a substitute for it.

- **Why:** stolen or lost media — eir, 2018 (an unencrypted laptop), Washington State University, 2017 (a backup drive) — are the cases disk encryption stops. It does not stop anyone who reads the data through the database or the application.
- **Detect:** check that databases, volumes, object storage, laptops, and backups have encryption at rest enabled.
- **Fix:** enable provider-managed encryption at rest everywhere, and full-disk encryption on every laptop ([`CICD-07`](./cicd.md#cicd-07)); add field-level encryption for high-harm data ([`DATA-07`](./data.md#data-07)).
- **Verify:** every store and device reports encryption at rest enabled.

### CRYPTO-07
**P1 · code** — Encrypted fields that must be searchable use a keyed blind index (an HMAC with a secret key), never a plaintext copy and never an unkeyed hash.

- **Why:** the usual workaround for "we encrypted the phone number but still need to look users up by it" is a plaintext copy or `sha256(phone)` beside the ciphertext. Phone numbers, birth dates, and national identifiers come from small, structured spaces, so an unkeyed hash of one can be reversed by hashing every possible value — the protection the encryption bought is gone.
- **Detect:** for each encrypted field, look for a sibling column used for lookups: plaintext, a truncated value, or `sha256()`/`md5()` of the value without a secret key.
- **Fix:** store `HMAC-SHA256(index_key, normalized_value)` as the lookup column, with `index_key` held in the KMS like the encryption key and distinct from it. Normalize before hashing (strip spaces, fix case and format) so lookups match.
- **Verify:** no plaintext or unkeyed-hash copy of an encrypted field exists, and the lookup column cannot be recomputed without the key.

### CRYPTO-08
**P1 · config** — Encryption keys are kept apart from the data they protect — in a KMS or HSM, not in the database, the repository, or the same secret store entry as the database password — and every decryption is permissioned and logged.

- **Why:** encryption whose key is reachable along the same path as the data protects nothing from whoever walks that path. LastPass, 2022 — one DevOps engineer's vault held the access and decryption keys for the production backups, so one compromised engineer reached both the customer vault backups and what was needed to decrypt the backup storage.
- **Detect:** where does the application get its data-encryption key? A constant in code, a database column, a file on the same host, or an environment variable set alongside the database password all fail. Can one human or one credential reach both the ciphertext and the key?
- **Fix:** envelope encryption — a KMS-held key wraps the data keys; the application asks the KMS to unwrap; IAM grants decrypt only to the service that needs it; no human holds both the data and the key; KMS calls are logged; keys rotate on a schedule and on suspicion.
- **Verify:** the database credentials alone cannot decrypt anything; the KMS audit log shows which principal decrypted what; a key rotation has actually been performed.


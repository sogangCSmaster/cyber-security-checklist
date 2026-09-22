# DATA · Data layer, tenant isolation, storage

Where the data actually lives, and what stands between one user (or one internet stranger) and all
of it. The controls here are the difference between "an account was compromised" and "everyone's
data was compromised".

← [Back to the checklist](../checklist.md) · Related: [`API`](./api.md), [`AUTH`](./authentication.md), [`CRED`](./secrets.md), [`FILE`](./files.md), [`CRYPTO`](./crypto.md)

---

### DATA-01
**P0 · config** — Row-level authorization enabled and default-deny on every client-reachable table.

- **Why:** Lovable, 2025 (CVE-2025-48757) — generated Supabase apps without RLS, 170+ production applications exposed. Moltbook, 2026 — the same failure, 1.5M tokens. The code worked perfectly; that was the problem.
- **Detect:** `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN (SELECT tablename FROM pg_policies);` returns nothing. Then read each policy — `USING (true)` is not a policy.
- **Fix:** enable RLS in the same migration that creates the table; write default-deny then grant, scoped to `auth.uid()`.
- **Verify:** the query above is empty and each policy scopes by user.
- **Probe:** if the anon key is client-side, [playbook §2/§3](./probe-playbook.md#2--the-unauthenticated-sweep--what-answers-with-no-credentials) will surface tables readable without a per-user policy.

### DATA-02
**P0 · code** — A negative test proves user A cannot read, update, or delete user B's data.

- **Why:** the test that would have caught First American, Panera, McHire, and every other IDOR ([`API-01`](./api.md#api-01)) before shipping.
- **Detect:** is there such a test in CI, or was it checked once by hand?
- **Fix:** write it: authenticate as A, attempt B's rows across read/update/delete, assert failure.
- **Verify:** the test is in CI and fails if the policy/check is removed.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record).

### DATA-03
**P0 · config** — Object storage private by default; legacy buckets audited.

- **Why:** Tea, 2025 — a legacy Firebase bucket left publicly readable: 13,000 government IDs and selfies, 1.1M private messages. A hotel check-in system, 2026 — 1M passports and licences. The upload worked example ([`FILE-04`](./files.md#file-04)) is the same failure reached through an open upload.
- **Detect:** enumerate every bucket, including ones from earlier versions, and read its public-access setting.
- **Fix:** block public access at the account and bucket level; serve via signed URLs ([`CLOUD-04`](./cloud.md#cloud-04)).
- **Verify:** each bucket denies anonymous reads.
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example).

### DATA-04
**P0 · infra** — Databases and search indexes not reachable from the public internet.

- **Why:** Exactis, 2018 — an ElasticSearch instance on a public IP: 340M records. Ecuador, 2019 — an unsecured Elasticsearch server: effectively the entire population.
- **Detect:** check bind addresses and security groups; look for `0.0.0.0` binds and open management ports.
- **Fix:** bind to a private network; require a bastion or VPN; never expose a datastore port to the internet.
- **Verify:** the datastore port is unreachable from outside the private network.
- **Probe:** from outside, confirm datastore/management ports do not answer.

### DATA-05
**P0 · code** — Admin or service-role database keys never reach a client or an agent context.

- **Why:** 2025 research — a Cursor agent connected with a Supabase `service_role` key dumped the integration-tokens table into a support ticket after reading instructions embedded in it.
- **Detect:** grep client and edge code for `service_role`, admin keys, root DB creds; check agent/tool configs.
- **Fix:** keep privileged keys in server environments only; agents get task-scoped credentials ([`AGENT-02`](./agents.md#agent-02)).
- **Verify:** no privileged key appears in any client bundle, edge function output, or agent context.

### DATA-06
**P1 · code** — Passwords are stored only as a slow, salted, one-way hash — argon2id, scrypt, or bcrypt. Never encrypted, never plaintext, never a fast hash.

- **Why:** LinkedIn's 2012 breach, resold at full scale in 2016 — 117M unsalted SHA-1 hashes; the large majority of an initial sample was cracked within days, and the recovered passwords fed credential stuffing elsewhere. Yahoo used MD5; Zynga used SHA-1. Suprema BioStar 2, 2019 — plaintext usernames and passwords in an open index.
- **Detect:**
  - Find where passwords are written. MD5, SHA-1, SHA-256/512 (even salted), unsalted anything, a homegrown scheme, or reversible encryption (`AES`, `encrypt(password)`) all fail.
  - Find where the password travels besides the hasher — logs, analytics events, error reports, a "support" column. Those are [`OBSV-04`](./observability.md#obsv-04) failures.
  - A "forgot password" flow that can send the user their existing password proves it is stored reversibly.
- **Fix:**
  - **Hash, don't encrypt.** A password is verified, never recovered. With reversible encryption, one stolen key reveals every password.
  - Use argon2id where available. OWASP's current minimums: argon2id with 19 MiB memory, 2 iterations, parallelism 1; scrypt with N=2^17, r=8, p=1; bcrypt with cost 10 or more; PBKDF2-HMAC-SHA256 with 600,000 iterations only where FIPS requires it. Let the library generate and store the salt.
  - **Upgrade legacy hashes at next sign-in:** after a successful login, if the stored hash uses an old algorithm or cost, rehash with the current parameters. Fast legacy hashes you cannot wait for can be wrapped now (argon2id over the old hash) and unwrapped at next login.
  - A pepper — a secret mixed in before hashing, held in a KMS or secret manager rather than the database — is an optional extra layer.
- **Verify:** every stored hash carries a modern algorithm identifier (`$argon2id$`, `$2b$`, `$scrypt$`) with a per-user salt; no column, log, or backup holds a password in any reversible form; password reset issues a new password, never the old one.

### DATA-07
**P1 · code** — High-harm personal data is encrypted by the application, field by field, with keys the database cannot reach — and identity documents are deleted once they have served their purpose.

- **Why:** Marriott, 2018 — 5.25M unencrypted passport numbers, plus payment card numbers, in the stolen data. SK Telecom, 2025 — subscriber authentication keys stored without encryption, so reaching the Home Subscriber Server was the same as reading every SIM's key; 26.96M records. Lotte Card, 2025 — resident registration numbers stored unencrypted, including in the payment server's own log files; 2.97M people. Vastaamo, 2020 — verbatim psychotherapy notes on an unencrypted database, then extortion of individual patients. Tea, 2025 — verification selfies and IDs kept long after verification.
- **Detect:**
  - List the columns and objects holding high-harm data: national identifiers (resident registration, social security, passport, and driver's-licence numbers), bank account and card numbers, health data, biometrics, precise location, uploaded identity documents, and authentication secrets such as SIM keys or API tokens stored for users.
  - For each, is it encrypted **by the application** before it reaches the database, or only by the disk underneath? Managed-database and volume "encryption at rest" protects a stolen disk. It does nothing against SQL injection, a leaked database credential, an over-privileged app role, or a backup the app can read — which is how the incidents above actually happened.
  - Where are the keys? A key in the same database, in the same `.env` as the database password, or in the repository is not separation ([`CRYPTO-08`](./crypto.md#crypto-08)).
- **Fix:**
  - Encrypt high-harm fields in the application with an authenticated mode (AES-GCM through a vetted library or a KMS envelope-encryption SDK — [`CRYPTO-05`](./crypto.md#crypto-05)); hold the keys in a KMS or HSM with decrypt rights granted only to the service that needs them ([`CRYPTO-08`](./crypto.md#crypto-08)).
  - Do not store what you do not need: verify an identity document, keep the result, and delete the image ([`DATA-09`](#data-09)).
  - Card numbers: do not store them at all ([`DATA-14`](#data-14)). Fields you must search by: [`CRYPTO-07`](./crypto.md#crypto-07).
  - Keep disk and volume encryption on as well; it is the floor, not the control.
  - Where regulation names specific fields, treat it as the floor. In Korea, the Personal Information Protection Act requires resident registration numbers to be stored encrypted and passwords to be hashed one-way; GDPR Article 32 names encryption and pseudonymisation as appropriate measures.
- **Verify:** a raw `SELECT` of a high-harm column using the application's own database credentials returns ciphertext; those credentials cannot read the key; a restored backup is ciphertext too.

### DATA-08
**P1 · infra** — Backups exist, are restore-tested, and are not writable by production credentials.

- **Why:** NotPetya, 2017 — Maersk rebuilt Active Directory from one surviving domain controller in Ghana, found by accident. Backups a production credential can encrypt are not backups against ransomware.
- **Detect:** confirm backups exist, are periodically restore-tested, and use separate write credentials.
- **Fix:** immutable or separately-credentialed backups; a tested restore procedure.
- **Verify:** a restore drill succeeds and production credentials cannot alter the backups.

### DATA-09
**P2 · process** — Data minimization and enforced retention limits.

- **Why:** First American's exposure reached back to 2003. You cannot lose what you deleted.
- **Detect:** for each data class, is there a retention limit and a job that enforces it?
- **Fix:** collect less; delete on a schedule.
- **Verify:** old data past its retention window is actually gone.

### DATA-10
**P1 · code** — Features that fan out one account's data to others are rate-limited and opt-in.

- **Why:** 23andMe, 2023 — the "DNA Relatives" feature turned 14,000 compromised logins into 6.9M exposed profiles. Facebook, 2021 — contact import, 533M phone numbers.
- **Detect:** find features that expose one user's data to others (relatives, contacts, "people you may know"); check rate limits and opt-in.
- **Fix:** opt-in by default, rate-limited, and capped.
- **Verify:** the fan-out is off by default and throttled when on.

### DATA-11
**P1 · code** — Bulk export is a privileged, logged, alerting action.

- **Why:** Salesloft Drift, 2025 — stolen OAuth tokens used for bulk CRM export across 700+ organizations. Every mass-scraping incident in the corpus ran through an endpoint working exactly as designed.
- **Detect:** identify endpoints that return many records; check they are privileged, logged, and alert on volume.
- **Fix:** gate bulk export behind explicit permission, log each run, alert on abnormal volume ([`OBSV-02`](./observability.md#obsv-02)).
- **Verify:** a large export produces a log entry and an alert.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### DATA-12
**P1 · infra** — What a single compromise can reach is capped, in value and in volume.

- **Why:** Youbit, 2017 and Coinrail, 2018 — hot wallets held the full balance, so one compromise took everything; Youbit filed for bankruptcy the same day. The general form: cap what any internet-connected system holds at once and sweep the rest out of reach.
- **Detect:** for any store of value or bulk data, is there a documented ceiling on what one compromise reaches?
- **Fix:** hold the minimum online; move the rest to cold or segmented storage.
- **Verify:** the online ceiling is documented and enforced.

### DATA-13
**P1 · code** — Sensitive values are masked wherever they are displayed or leave the service — UI, API responses, logs, exports, analytics, support tools — and revealing a full value is a permissioned, logged action.

- **Why:** exposure usually comes from data that was served, exported, or logged in full when a fragment would have done. Lotte Card, 2025 — resident registration numbers in plaintext in server log files. Klaviyo, 2026 — trackers on its own sign-up form forwarded what users typed, passwords included, to six advertising and analytics companies.
- **Detect:** grep serializers, templates, and CSV exports for full national identifier, card, account, and phone fields; check logs, error-tracker events, and analytics payloads for the same.
- **Fix:** return masked forms by default (last four digits of a card, a partial identifier); a separate, role-restricted action reveals the full value and records who asked and why; strip sensitive fields from logs and analytics at the source ([`OBSV-04`](./observability.md#obsv-04)).
- **Verify:** a representative API response, a log sample, and an export each contain only masked values.

### DATA-14
**P0 · code** — Payment card numbers never touch your storage: the payment processor tokenizes them, and the card security code is never stored at all. *(Applies if you take payments.)*

- **Why:** Marriott, 2018 — payment card numbers among the stolen guest data. Forever 21, 2017 — point-of-sale encryption "was not always on," so malware read card data in the clear for months.
- **Detect:** any column, log, or file holding a full card number or a security code; any card field posted to your own server instead of the processor's hosted field or checkout.
- **Fix:** collect cards in the processor's hosted fields or checkout so the full number never reaches your servers; keep only the processor's token and the last four digits; never store the security code — PCI DSS forbids retaining it after authorization.
- **Verify:** a scan of tables, logs, and backups for 13–19-digit sequences that pass the Luhn check finds none.


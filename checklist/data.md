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
**P1 · code** — Passwords hashed with argon2id, bcrypt, or scrypt. See [`CRYPTO-01`](./crypto.md#crypto-01).

- **Why:** Yahoo used MD5; Zynga used SHA-1 for some accounts and legacy MD5 for others. A fast hash means a stolen table is cracked, not merely stolen.
- **Detect:** find the hashing call; MD5/SHA-1/SHA-256/unsalted anything fails.
- **Fix:** argon2id (preferred), bcrypt, or scrypt with sound parameters.
- **Verify:** stored hashes carry a modern algorithm identifier and per-password salt.

### DATA-07
**P1 · config** — Sensitive fields encrypted at rest; identity documents deleted after they have served their purpose.

- **Why:** Marriott, 2018 — 5.25M unencrypted passport numbers. Tea, 2025 — verification selfies and IDs retained long after verification.
- **Detect:** identify sensitive fields and check encryption at rest and retention policy.
- **Fix:** encrypt sensitive columns/objects; delete identity documents once verification is complete.
- **Verify:** sensitive data is encrypted and the deletion job runs.

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

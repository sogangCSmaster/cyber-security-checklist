# CRED · Secrets and credentials

The single largest category in the corpus. Roughly a third of recorded incidents begin with a
credential somewhere it should not have been — a repository, a client bundle, a support ticket, a
prompt. Most of these are invisible from the outside, so the checks here are source- and
config-level.

← [Back to the checklist](../checklist.md) · Related: [`AUTH`](./authentication.md), [`CLOUD`](./cloud.md), [`CICD`](./cicd.md), [`AGENT`](./agents.md)

---

### CRED-01
**P0 · code** — No secret in source, configuration, client bundle, or git history.

- **Why:** Uber, 2016 — an AWS key in a *private* repository, 57M records, $148M settlement, a criminal conviction for the CSO. Toyota, 2022 — a key in a *public* repository for five years, 296k records. Internet Archive, 2024 — a GitLab config with a token reachable since 2022, 31M records.
- **Detect:** `gitleaks detect --no-git` on the tree and `gitleaks detect` over full history. Without it: `git log --all -p -S'BEGIN PRIVATE KEY'` and grep for `AKIA`, `sk-`, `ghp_`, `xox`, `eyJ`.
- **Fix:** remove the secret, **rotate it** ([`CRED-03`](#cred-03)), and move it to a secret manager or the runtime environment ([`CRED-04`](#cred-04)). Deleting the commit is not enough — history keeps it.
- **Verify:** a secret scanner over full history returns clean, and the old value now fails to authenticate.

### CRED-02
**P0 · code** — Anything the client can read is public. Secrets are server-side only.

- **Why:** Moltbook, 2026 — a Supabase anon key in the client bundle with RLS off: 1.5M API tokens, 4,060 private messages. Every `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*` value ships to the browser.
- **Detect:** build the bundle, then scan it: [`scan.py --bundle auto`](../skills/security-audit/scripts/scan.py). Without Python, list the files that hold a key: `grep -rlE "sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|[rs]k_live_|sb_secret_|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY" .next/static/ dist/ build/ out/`. A Supabase `service_role` key is a JWT like the public anon key, so the words "service_role" never appear in it — only decoding the token tells the two apart, which the scanner does. Reading the source is a different, weaker check.
- **Fix:** move any real secret to a server route or function; keep only publishable identifiers client-side.
- **Verify:** the built bundle contains no credential beyond public identifiers; confirm by grepping the artifact, not the source.
- **Probe:** pull the deployed JS bundle and grep it — [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all).

### CRED-03
**P0 · process** — Rotate on exposure, including anything an AI tool, a vendor, or a support ticket has seen.

- **Why:** Okta, 2023 — service-account credentials saved into a personal Google profile, then session tokens inside support HAR files. s1ngularity, 2025 — AI CLIs were driven to collect local secrets; Wiz counted over a thousand valid GitHub tokens plus cloud and npm credentials.
- **Detect:** treat any secret that has touched a repo, a log, a prompt, a screenshot, or a ticket as exposed.
- **Fix:** rotate it and confirm the old one fails. Removing the commit is not rotation.
- **Verify:** the old credential now returns an auth error.

### CRED-04
**P1 · config** — Secrets injected at runtime from a manager or the environment, never baked into images or repositories.

- **Detect:** `docker history --no-trunc <image> | grep -iE "key|secret|token"` returns nothing; check for secrets in build args and layer files.
- **Fix:** load secrets from a manager or environment at start; keep them out of image layers and repos.
- **Verify:** the image history and filesystem carry no secret.

### CRED-05
**P1 · code** — Secret file patterns ignored before the first commit.

- **Why:** the window between "created `.env`" and "added it to `.gitignore`" is where it gets committed. A `.env` added to `.gitignore` after it was tracked stays in history.
- **Detect:** `git ls-files | grep -E '(^|/)\.env($|\.)|\.(pem|key|p12|pfx)$|service-account.*\.json$' | grep -vE '\.env\.(example|sample|template)$'` is empty — nested `apps/web/.env` included, templates excluded — and `git check-ignore -q .env` succeeds.
- **Fix:** add the patterns before the first commit and ship a `.env.example` with placeholders.
- **Verify:** the grep above is empty and history is clean.

### CRED-06
**P1 · config** — Credentials scoped to one job, one resource, one permission.

- **Why:** Microsoft AI research, 2023 — one Azure SAS token scoped to an entire storage account, write-enabled, expiring in 2051: 38 TB including workstation backups. Capital One, 2019 — an IAM role that could list every bucket.
- **Detect:** no IAM policy on an application role contains `"Resource": "*"` or `"Action": "*"`; SAS/OAuth scopes are the minimum needed.
- **Fix:** scope each credential to the specific resource and action; split broad roles.
- **Verify:** the credential can do its job and fails at anything wider.

### CRED-07
**P1 · config** — Credentials expire. No indefinite lifetimes.

- **Why:** Klue, 2026 — a credential issued in 2022 for a pilot, never used and never revoked, reached ~200 customer companies four years later.
- **Detect:** list every long-lived token/key in the account and its expiry.
- **Fix:** give each an expiry or a named owner and a review date; prefer short-lived, auto-refreshed credentials.
- **Verify:** no non-expiring credential remains without an owner.

### CRED-08
**P1 · config** — Per-environment secrets; development cannot reach production.

- **Evidence:** none in this corpus turns specifically on a shared secret; several show a non-production *environment* with a path into production ([`CLOUD-06`](./cloud.md#cloud-06)). Kept as a preventive control.
- **Detect:** confirm dev/staging/prod use distinct credentials and that a dev credential cannot authenticate to prod.
- **Fix:** separate secrets per environment; no shared keys.
- **Verify:** a dev credential is rejected by production.

### CRED-09
**P2 · process** — A rotation and revocation runbook with a named owner and a stated maximum time-to-revoke.

- **Detect:** someone can answer "how long to kill every credential?" with a number.
- **Fix:** write the runbook, name the owner, rehearse it.
- **Verify:** a rehearsal meets the stated time.

### CRED-10
**P1 · code** — No default or shared credential in anything you ship or deploy. A unique one is forced at first use.

- **Why:** Mirai, 2016 — default factory credentials on IoT cameras and DVRs assembled a botnet that took a DNS provider offline across much of the US. VPNFilter, 2018 — the same class on consumer routers. McHire, 2025 — a `123456` admin login alongside the IDOR.
- **Detect:** grep firmware, images, and seed data for embedded credentials; check first-boot behaviour.
- **Fix:** no shipped credential; force a unique one at first use and refuse to proceed until set.
- **Verify:** a fresh install cannot be reached with any known default.
- **Probe:** try well-known default credentials on any admin login ([playbook §4](./probe-playbook.md#4--auth-responses--timing-and-message-differences-worked-example)) — staging/authorized only.

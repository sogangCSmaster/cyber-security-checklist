---
name: ship-gate
description: A blocking go/no-go gate to run immediately before deploying, launching, or making an application public. Checks the small set of failures that account for most real breaches and returns a clear SHIP or DO NOT SHIP verdict, with evidence for every gate. Use when about to deploy to production, publish or launch an app, make a repository public, open a service to real users, or when asked whether something is ready to go live.
argument-hint: "[what is being deployed]"
allowed-tools: Read, Grep, Glob, Bash(python3 ${CLAUDE_SKILL_DIR}/../security-audit/scripts/scan.py *), Bash(git log *), Bash(git ls-files *), Bash(git status *), Bash(git rev-parse *), Bash(git check-ignore *)
---

# Ship gate

The last checkpoint before real users and real attackers. This is deliberately **not** the full
checklist — it is the subset that accounts for most of what actually goes wrong in the incident
corpus, ordered by how often each failure appears there.

Run it. Give a verdict. Do not soften it.

Target: `$ARGUMENTS` — if empty, the current repository and its deployment configuration.

---

## How to run this

**1. Scan.** The scanner ships with the `security-audit` skill beside this one:

```bash
python3 ${CLAUDE_SKILL_DIR}/../security-audit/scripts/scan.py --gate
```

It prints its findings, the checks it could not run, and a table mapping its evidence to each
gate below. If it is not there (this skill was copied without `security-audit`), do the checks by
hand with Grep and say so in the verdict.

**2. Scan what the browser will download.** G1 is about the built bundle, not the source. Build
the app — ask first, because a build runs the project's own scripts — then:

```bash
python3 ${CLAUDE_SKILL_DIR}/../security-audit/scripts/scan.py --only bundle-secret --bundle auto
```

`--bundle auto` finds `.next/static`, `dist`, `build`, `out`, `.output/public` and
`.svelte-kit/output/client`; pass `--bundle <dir>` for anything else. If you cannot build, G1
is UNVERIFIED for the bundle, whatever the source looks like.

**3. Ask once for what a repository cannot show.** Put these to the user in a single message,
not one at a time:

- G5 — is MFA on for every account that can reach production? Name them: cloud console,
  hosting, database, domain registrar, CI/CD, package registry, source control — and any
  contractor's or unused account.
- G8 — where do authentication failures and bulk reads get recorded, and who is alerted?
- G11 — do backups exist, and when was a restore last tested?
- G15 — who owns an incident, and how does an outsider report a vulnerability?
- G3 — what is live: domains, buckets, databases, admin panels, staging environments?

Their answer makes a gate ATTESTED, not PASS. A question they cannot answer leaves the gate
UNVERIFIED.

**4. Trace G4 by hand.** Pick three endpoints that return user data — at least one write — and
follow each from the request to the query.

## Statuses

| Status | Meaning |
| --- | --- |
| **PASS** | Verified here, and the evidence is named: a scanner check that ran clean, a file read, a command's output |
| **ATTESTED** | The user confirmed it; nothing here could verify it. Counts as passing, and the verdict says how many gates rest on the user's word |
| **N/A** | The surface does not exist, with the reason in one line: no database, no agent, no uploads |
| **UNVERIFIED** | Could not be checked and nobody vouched for it. On a blocking gate, this means do not ship |
| **FAIL** | The failure is present |

**Do not mark a gate PASS because it is likely to be fine.** A PASS with no evidence is an
UNVERIFIED wearing a disguise.

---

## The blocking gates

Any single FAIL or UNVERIFIED here means **DO NOT SHIP**.

### G1 · No secret is reachable by a user — `CRED-01`, `CRED-02`
No credential in the repository, in git history, or in the built client bundle. Every
`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*` value is one you would publish on purpose.
*Evidence:* `secret-shape`, `client-env-secret`, `tracked-secret-file` and `history-secret` ran
clean, and `bundle-secret` ran clean against the build.

### G2 · Every client-reachable table denies by default — `DATA-01`, `DATA-02`
RLS or equivalent enabled on every table, with a policy that actually scopes by user. A test
exists proving user A cannot read user B's rows. `USING (true)` fails this gate.
*Evidence:* `rls` and `firebase-rules` ran clean, and you found the negative test. N/A if no
client ever queries the database directly.

### G3 · Nothing is public that was not meant to be — `DATA-03`, `DATA-04`, `CLOUD-01`
Storage buckets, databases, search indexes, admin panels, debug endpoints, and staging
environments. Enumerate what is internet-reachable and confirm each one on purpose. Legacy
buckets from an earlier version of the project count — that is exactly how the Tea app lost
13,000 government IDs.
An unauthenticated write endpoint (an upload or create that answers a request with no session)
counts here too — especially one whose file then lands at a public bucket URL. That is two
failures at once. — `FILE-01`, `FILE-04`
*Evidence:* `public-storage`, `datastore-exposure` and `open-security-group` ran clean, every
`upload-handler` line requires a session, and the user confirmed the list of what is live.

### G4 · Authorization is server-side and per-object — `AUTH-02`, `AUTH-03`
Every endpoint returning user data checks both who is asking and whether they may have this
specific record. If any of the three you traced takes an identifier from the request and returns
the record without an ownership check, this gate fails.

### G5 · MFA on every path into production — `AUTH-01`, `CLOUD-06`
Cloud console, hosting provider, database, domain registrar, CI/CD, package registry, source
control. Including contractors. Including the account nobody uses any more. A missing MFA on one
remote-access path is the single most expensive line item in the entire corpus. This gate is
almost always ATTESTED: name each account the user vouched for.

### G6 · Admin database credentials are server-side only — `DATA-05`, `AGENT-02`
`service_role` keys, admin API keys, and root database credentials exist only in server
environments — never in client code, never in an edge function that returns their output to the
caller, never in an agent's context or tool configuration.
*Evidence:* `service-role` and `client-env-secret` ran clean, and you read every medium
`service-role` line and confirmed it runs only on a server.

### G7 · Dependencies are pinned and install scripts are off — `DEPS-01`, `DEPS-02`
A lockfile is committed and the deploy installs from it. Post-install scripts do not run in CI
unless a specific package requires them and that package has been reviewed. Workflows that
deploy pin their actions to a commit and do not run fork code with secrets — `CICD-01`, `CICD-04`.
*Evidence:* `lockfile`, `install-scripts` and `workflow` ran clean.

### G8 · Someone would notice — `OBSV-01`, `OBSV-02`
Authentication failures, authorization failures, and bulk reads are recorded somewhere
persistent that a named person can query, and at least one alert reaches a human. If the app
holds high-harm data — identity documents, health, financial, precise location (`DATA-07`) — an
alert on abnormal read or export volume per account is part of this gate; for anything else it
is should-fix. Median dwell time in the corpus is measured in weeks; without this gate, you find
out from a journalist.

---

## The should-fix gates

These do not block a launch on their own. Two or more FAILs together do.
One exception: G10 blocks on its own if passwords are stored in plaintext, with a fast hash, or
with reversible encryption, or if card security codes are stored at all — `DATA-06`, `DATA-14`.

| | Gate | Control | Scanner evidence |
| --- | --- | --- | --- |
| G9 | Rate limiting on login, password reset, and any endpoint enumerable by id, email, or phone | `AUTH-06` | `rate-limit` |
| G10 | Passwords stored only as argon2id, scrypt, or bcrypt hashes; national-ID, card, health, and biometric fields encrypted by the application with keys the database credential cannot read; no passwords or identifiers in logs | `DATA-06`, `DATA-07`, `CRYPTO-08`, `OBSV-04` | `weak-password-hash`, `card-data`, `high-harm-field`, `sensitive-logging` |
| G11 | Backups exist, have been restore-tested, and are not writable by production credentials | `DATA-08` | — ask |
| G12 | Identity documents and other high-harm data are deleted after they have served their purpose | `DATA-07` | — read the retention code or ask |
| G13 | Cloud roles carry no wildcard actions or resources | `CLOUD-03` | `iam-wildcard` |
| G14 | Third-party scripts on pages handling credentials or payment are pinned or self-hosted | `DEPS-06`, `VENDOR-05` | `external-script` |
| G15 | A named person owns the response, and there is a published way to report a vulnerability | `OBSV-05`, `OBSV-06` | `disclosure`, then ask |
| G16 | Agents with data access cannot both read untrusted content and send outbound unsupervised | `AGENT-03` | `agent-config`, `invisible-unicode`, then read the wiring |
| G17 | A real Content-Security-Policy (no `*`/`unsafe-inline`/`unsafe-eval` on script-src) plus HSTS, nosniff, framing control, and Secure/HttpOnly/SameSite cookies | `WEB-01`, `WEB-05` | `csp`, `cookie-flags`, then the live headers |
| G18 | Login, signup, and reset reveal nothing by message, status, timing, or lockout — the login path hashes even when the account is absent — and no account named `admin`, `root`, or `test` exists in production | `AUTH-13`, `AUTH-14`, `LEAK-01` | `enumeration-message`, `default-credential` |

---

## The verdict

```markdown
## Ship gate — <target>

# DO NOT SHIP

**2 blocking gates failed, 1 unverified. 1 gate rests on the user's word.**

| Gate | Status | Evidence |
| --- | --- | --- |
| G1 Secrets | **FAIL** | `SUPABASE_SERVICE_ROLE_KEY` in `.env.production`, which is tracked in git (`tracked-secret-file`) |
| G2 Row-level security | **FAIL** | `messages` and `profiles` have no policy — `supabase/migrations/0002_init.sql:3`, `:19` (`rls`) |
| G3 Public surface | PASS | `public-storage` and `datastore-exposure` clean; both buckets private per `gsutil iam get` |
| G4 Authorization | UNVERIFIED | `/api/orders/[id]` ownership check not located — needs a human |
| G5 MFA | ATTESTED | User confirmed MFA on AWS, Vercel, Supabase, Cloudflare, GitHub and npm |
| G6 Admin keys | PASS | `service-role` clean; `lib/server/admin.ts` imported only by API routes |
| ... | | |

### To clear the gate

1. Rotate `SUPABASE_SERVICE_ROLE_KEY`. It is in git history, so removing the file is not enough.
   Then untrack the file and load the key from the deploy environment. — `CRED-03`
2. Enable RLS on `messages` and `profiles` with default-deny policies scoped to `auth.uid()`,
   and add the negative test. — `DATA-01`
3. Trace `/api/orders/[id]` and confirm the ownership check, or add one. — `AUTH-02`
```

Rules:

- **The verdict goes first, in a heading.** Nobody reads to the bottom of a gate report.
- **Evidence, not assertion.** Every PASS names what was checked. ATTESTED names who vouched and
  for what. N/A says why the surface does not exist.
- **Never reproduce a secret.** Name the variable and where it is; never its value.
- **Never soften a FAIL** because the deadline is today or the user seems committed. State it
  plainly once, give the fix, and if the user decides to ship anyway, that is their call to make
  — say so without moralizing and help them ship.
- **Do not invent gates.** If something outside this list worries you, say it separately as an
  observation rather than inflating the gate count.
- If everything passes, say **SHIP** and stop. Do not manufacture concerns to seem thorough.

---

## After a failed gate

Offer to fix the blocking findings directly. For each fix, re-run the check that failed —
`python3 ${CLAUDE_SKILL_DIR}/../security-audit/scripts/scan.py --only <check>` — and show its
output. A gate cleared without re-verification is not cleared.

Full control text and verification steps: `checklist.md` in this plugin
(`${CLAUDE_SKILL_DIR}/../../checklist.md`). The incident behind each gate:
`${CLAUDE_SKILL_DIR}/../security-audit/references/precedents.md`.

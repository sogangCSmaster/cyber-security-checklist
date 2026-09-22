---
name: ship-gate
description: A blocking go/no-go gate to run immediately before deploying, launching, or making an application public. Checks the small set of failures that account for most real breaches and returns a clear SHIP or DO NOT SHIP verdict. Use when about to deploy to production, publish or launch an app, make a repository public, open a service to real users, or when asked whether something is ready to go live.
argument-hint: "[what is being deployed]"
allowed-tools: Read, Grep, Glob, Bash
disable-model-invocation: false
---

# Ship gate

The last checkpoint before real users and real attackers. This is deliberately **not** the full
checklist — it is the subset that, according to [`incidents/STATS.md`](../../incidents/STATS.md),
accounts for most of what actually goes wrong.

Run it. Give a verdict. Do not soften it.

Target: `$ARGUMENTS` — if empty, the current repository and its deployment configuration.

---

## How to run this

Order the gates by the corpus, not by the list below:

```bash
head -40 incidents/STATS.md 2>/dev/null
```

If `STATS.md` exists, its `entry/` frequency table tells you which gates matter most for the
current state of the corpus. If it does not, use the order given here.

Check each gate with a command or a file read. **Do not mark a gate PASS because it is likely to
be fine.** A gate you could not verify is `UNVERIFIED`, and `UNVERIFIED` on a blocking gate means
do not ship until someone looks.

---

## The blocking gates

Any single failure here means **DO NOT SHIP**.

### G1 · No secret is reachable by a user — `CRED-01`, `CRED-02`
No credential in the repository, in git history, or in the client bundle. Every `NEXT_PUBLIC_*`,
`VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*` value is one you would publish on purpose.
*Build the bundle and grep it.* Reading the source is not the same check.

### G2 · Every client-reachable table denies by default — `DATA-01`, `DATA-02`
RLS or equivalent enabled on every table, with a policy that actually scopes by user. A test
exists proving user A cannot read user B's rows. `USING (true)` fails this gate.

### G3 · Nothing is public that was not meant to be — `DATA-03`, `DATA-04`, `CLOUD-01`
Storage buckets, databases, search indexes, admin panels, debug endpoints, and staging
environments. Enumerate what is internet-reachable and confirm each one on purpose. Legacy
buckets from an earlier version of the project count — that is exactly how the Tea app lost
13,000 government IDs.

### G4 · Authorization is server-side and per-object — `AUTH-02`, `AUTH-03`
Every endpoint returning user data checks both who is asking and whether they may have this
specific record. Pick three endpoints at random and trace them. If any takes an identifier from
the request and returns the record without an ownership check, this gate fails.

### G5 · MFA on every path into production — `AUTH-01`, `CLOUD-06`
Cloud console, hosting provider, database, domain registrar, CI/CD, package registry, source
control. Including contractors. Including the account nobody uses any more. A missing MFA on one
remote-access path is the single most expensive line item in the entire corpus.

### G6 · Admin database credentials are server-side only — `DATA-05`, `AGENT-02`
`service_role` keys, admin API keys, and root database credentials exist only in server
environments — never in client code, never in an edge function that returns their output to the
caller, never in an agent's context or tool configuration.

### G7 · Dependencies are pinned and install scripts are off — `DEPS-01`, `DEPS-02`
A lockfile is committed and the deploy installs from it. Post-install scripts do not run in CI
unless a specific package requires them and that package has been reviewed.

### G8 · Someone would notice — `OBSV-01`, `OBSV-02`
Authentication failures, authorization failures, and bulk data reads are logged somewhere a human
or an alert can reach. At minimum, an alert on abnormal export volume per account. Median dwell
time in the corpus is measured in weeks; without this gate, you find out from a journalist.

---

## The should-fix gates

These do not block a launch on their own. Two or more together do.

| | Gate | Control |
| --- | --- | --- |
| G9 | Rate limiting on login, password reset, and any endpoint enumerable by id, email, or phone | `AUTH-06` |
| G10 | Passwords hashed with argon2id, bcrypt, or scrypt | `DATA-06` |
| G11 | Backups exist, have been restore-tested, and are not writable by production credentials | `DATA-08` |
| G12 | Identity documents and other high-harm data are deleted after they have served their purpose | `DATA-07` |
| G13 | Cloud roles carry no wildcard actions or resources | `CLOUD-03` |
| G14 | Third-party scripts on pages handling credentials or payment are pinned or self-hosted | `DEPS-06`, `VENDOR-05` |
| G15 | A named person owns the response, and there is a published way to report a vulnerability | `OBSV-05`, `OBSV-06` |
| G16 | Agents with data access cannot both read untrusted content and send outbound unsupervised | `AGENT-03` |

---

## The verdict

```markdown
## Ship gate — <target>

# DO NOT SHIP

**2 blocking gates failed, 1 unverified.**

| Gate | Status | Evidence |
| --- | --- | --- |
| G1 Secrets | **FAIL** | `SUPABASE_SERVICE_ROLE_KEY` present in `.env.production`, which is tracked in git |
| G2 Row-level security | **FAIL** | `messages` and `profiles` have no policy (`supabase/migrations/`) |
| G3 Public surface | PASS | Two buckets, both private; verified with `gsutil iam get` |
| G4 Authorization | UNVERIFIED | `/api/orders/[id]` ownership check not located — needs a human |
| G5 MFA | PASS | Confirmed by the user on all six accounts |
| ... | | |

### To clear the gate

1. Rotate `SUPABASE_SERVICE_ROLE_KEY`. It is in git history, so removing the file is not enough.
   Then remove it from the tracked file and load it from the deploy environment. — `CRED-03`
2. Enable RLS on `messages` and `profiles` with default-deny policies scoped to `auth.uid()`,
   and add the negative test. — `DATA-01`
3. Trace `/api/orders/[id]` and confirm the ownership check, or add one. — `AUTH-02`
```

Rules:

- **The verdict goes first, in a heading.** Nobody reads to the bottom of a gate report.
- **Evidence, not assertion.** Every PASS names what was checked. A PASS with no evidence is an
  UNVERIFIED wearing a disguise.
- **Never soften a FAIL** because the deadline is today or the user seems committed. State it
  plainly once, give the fix, and if the user decides to ship anyway, that is their call to make
  — say so without moralizing and help them ship.
- **Do not invent gates.** If something outside this list worries you, say it separately as an
  observation rather than inflating the gate count.
- If everything passes, say **SHIP** and stop. Do not manufacture concerns to seem thorough.

---

## After a failed gate

Offer to fix the blocking findings directly. For each fix, re-run the specific check that failed
and show its output — a gate cleared without re-verification is not cleared.

Full control text and verification steps: [`checklist.md`](../../checklist.md).
Why each gate exists: [`incidents/`](../../incidents/).

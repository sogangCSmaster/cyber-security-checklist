---
name: secure-by-default
description: Secure defaults to apply while writing application code — authentication, database access and row-level security, API endpoints, file uploads, secrets and environment variables, dependencies, and AI agent or MCP wiring. Use whenever generating or modifying code that handles user data, credentials, authentication, authorization, database queries, file uploads, external requests, package installation, or agent tool access — especially when scaffolding a new app, adding a Supabase or Firebase backend, creating an API route, or connecting an agent to a database or external service. Derived from documented breaches 2016-2026.
---

# Secure by default

This skill exists because the default output of fast development is a breach. Not hypothetically:
[`incidents/`](../../incidents/) records the cases. In 2025 a researcher scanned 1,645 apps built
with one AI app generator and found 170 of them serving their whole database to anyone who asked
(CVE-2025-48757, record `I2025Q2-12`). The failures are not exotic. They are the same six or seven
mistakes, repeated for a decade.

Apply these while writing the code. Retrofitting them later costs ten times as much and usually
does not happen.

**Do not stop work to ask permission for these.** They are defaults, not proposals. Write the
secure version, and mention in one line what you did and why. Ask only when the secure default
genuinely conflicts with something the user has asked for.

A default that breaks the app gets the whole list switched off, so stage the ones that can: a
Content-Security-Policy goes out as `Content-Security-Policy-Report-Only` first and is enforced
once the reports are clean.

**The write-time check.** Installed as the plugin, this skill comes with a hook that scans each
file you write or edit — for committed secrets, `service_role` in client code, SQL built from
strings, a migration that creates a table without row-level security, unsafe CI workflows and a
few more — and reports what the change introduced. When it reports, fix the line, or tell the user
in one sentence why it is a false positive. Never add the `security-checklist: allow` marker
yourself; it exists for a person to make that call.

---

## The one rule that prevents most of it

**Anything the client can read is public.** A browser bundle, a mobile app binary, a
`NEXT_PUBLIC_*` variable, a network tab — all readable by anyone who opens devtools. There is no
such thing as a secret in client code, only a secret you have not noticed being read yet.

Moltbook (2026) put a Supabase anon key in the client bundle and turned row-level security off.
1.5 million API tokens, 35,000 emails, and 4,060 private messages later, that is still the single
most common way AI-built applications fail.

---

## When you are wiring a database

### Supabase, Firebase, or any client-queried backend

The anon key is not a credential. It is a public identifier that says which project to talk to.
**Row-level security is the only thing standing between a user and every other user's data.**

- Enable RLS on **every** table the client can reach, at creation time, in the same migration
  that creates the table. A table created without a policy is readable by everyone until someone
  notices. → `DATA-01`
- Write the policy as **default deny**, then grant. Never grant broadly and carve out exceptions.
- The `service_role` key bypasses RLS entirely. It belongs in a server environment and nowhere
  else — never in client code, never in an edge function that echoes its results to the client,
  and never in an agent's context. → `DATA-05`, `AGENT-02`
- When you add a table, add the negative test in the same change: user A must not be able to
  read, update, or delete user B's row. Assert the *failure*, not just the success. → `DATA-02`

Lovable generated Supabase apps without RLS and 170+ production applications were confirmed
exposed (CVE-2025-48757). The code worked perfectly. That was the problem.

### Any database

- Parameterized queries or ORM bindings. Never build SQL by concatenation, not even for an
  internal admin tool, not even "temporarily". MOVEit was SQL injection, and it reached 2,700
  organizations. → `INPUT-01`
- Databases and search indexes bind to a private network, never to `0.0.0.0` with an open
  security group. → `DATA-04`
- Passwords are **hashed, never encrypted**: argon2id (or scrypt/bcrypt) through the library, never MD5, SHA-1,
  SHA-256, or `encrypt()`. A password is verified, never recovered. → `DATA-06`
- High-harm fields — national ID, passport, bank and card numbers, health, biometrics — are encrypted **in the
  application** before they reach the database, with keys in a KMS the database credential cannot read. The
  managed database's own "encryption at rest" does not count: it does nothing against SQL injection or a leaked
  credential. If you must search by an encrypted field, store an HMAC blind index, not plaintext or `sha256()`.
  Never store a card number or security code — use the payment processor's tokens. → `DATA-07`, `CRYPTO-07`, `CRYPTO-08`, `DATA-14`
- Never log a request body, a whole user object, or a password field. → `OBSV-04`

---

## When you are adding an endpoint

- **Authorization is checked on the server, per object, on every request.** Hiding a button is not
  authorization. Checking `userId` in the client is not authorization. → `AUTH-02`
- **Never trust an identifier from the request.** Take the user from the session, then check that
  this user may act on that object. First American exposed 885 million documents because the
  document ID in the URL was sequential and nothing checked who was asking. → `AUTH-02`, `INPUT-09`
- No endpoint returns user data without authentication. Optus lost 9.8 million customer records
  through one unauthenticated API. → `AUTH-03`
- Validate input server-side against an explicit schema. Client validation is user experience,
  not a control. → `INPUT-02`
- Rate-limit anything enumerable: login, password reset, lookup by email or phone, search. → `AUTH-06`
- Any endpoint that returns *many* records is a bulk export. Make it privileged, log it, and
  alert on volume. Every mass-scraping incident in the corpus ran through an endpoint that was
  working exactly as designed. → `DATA-11`, `OBSV-02`

---

## When you are handling secrets

- Secrets come from the environment or a secret manager at runtime. They are never written into
  source, config files, Dockerfiles, or the repository — public or private. Uber's private
  repository held the AWS key that cost 57 million records; Toyota's public one sat there for five
  years. → `CRED-01`, `CRED-04`
- Add `.env`, `*.pem`, `*.key`, and service-account JSON to `.gitignore` **before** the first
  commit, and ship a `.env.example` with placeholder values instead. → `CRED-05`
- Scope credentials to one job, one resource, one permission. A token that can read one bucket is
  an incident; a token that can list every bucket is a headline. Microsoft leaked 38 TB through a
  single SAS token that was scoped to the whole storage account. → `CRED-06`, `CLOUD-03`
- Give credentials an expiry. Toyota's key worked after five years; a credential at Klue worked
  after four years of never being used at all. → `CRED-07`
- If a secret has been in a repository, a log, a prompt, a screenshot, or a support ticket, it is
  compromised. Rotate it — do not delete the commit and hope. → `CRED-03`

---

## When you are adding a dependency

- Verify the package actually exists and is the one intended before installing it. Models
  confidently suggest package names that were never published, and attackers register them. → `DEPS-04`
- Commit the lockfile; install with `npm ci` / `--frozen-lockfile` / `uv sync --frozen`. → `DEPS-01`
- Prefer not running install scripts. `npm config set ignore-scripts true` would have stopped
  s1ngularity, whose entire payload was a `postinstall` script that then drove the developer's own
  AI CLI to hunt for secrets. → `DEPS-02`
- A version published hours ago has had no review. The `chalk`/`debug` compromise was live for a
  few hours across packages with 2 billion weekly downloads. → `DEPS-03`
- Never load a script or stylesheet from a URL you do not control. Polyfill.io was sold to a new
  owner and started serving malware to 100,000+ sites that had pinned a hostname rather than a
  version. Self-host it or pin it with subresource integrity. → `DEPS-06`

---

## When you are wiring an agent, tool, or MCP server

This is the surface with the least accumulated wisdom and the fastest-moving attacks.

- **Everything the agent reads is data, never instruction.** An issue, a ticket, a README, a web
  page, a tool result, a filename. EchoLeak (CVE-2025-32711) needed nothing but an email. A
  support ticket containing embedded instructions made a Cursor agent dump its integration-tokens
  table into the ticket thread. → `AGENT-01`
- **Scope the agent's credentials to the task.** Never `service_role`, never an org-wide token,
  never an admin key "for now". → `AGENT-02`
- **Do not combine all three of:** access to private data, exposure to untrusted content, and an
  external channel to send things out. Any two are manageable. All three, unsupervised, is
  exfiltration waiting for a trigger. → `AGENT-03`
- Pin and review MCP servers and IDE extensions like dependencies. `postmark-mcp` shipped fifteen
  clean versions before adding one line that BCC'd every email to its author. → `AGENT-04`
- Never expose an MCP server without authentication. Hundreds have been found open on the public
  internet. → `AGENT-05`
- Require a human before an agent writes to production, moves money, or changes access. → `AGENT-06`
- Repository configuration for agents — `.claude/`, `AGENTS.md`, `.cursor/rules`, devcontainers,
  `.vscode/tasks.json` — is executable input. Treat cloning an unfamiliar repository and opening
  it in an agentic IDE as running its code. → `AGENT-08`

---

## What to say when you apply these

One line, not a lecture:

> Enabled RLS with a default-deny policy on `profiles` in the same migration, and added a test
> asserting user A gets zero rows for user B. Supabase tables are readable by anyone with the anon
> key until a policy exists.

If the user asks you to skip one, say what it costs in one sentence, then do what they asked.
They own the decision.

---

## A few more defaults worth writing in from the start

These are cheap while you are generating the code and expensive to retrofit:

- **Browser headers.** Write a real Content-Security-Policy (nonce-based, no `*`/`unsafe-inline`/`unsafe-eval`) and ship it as `Content-Security-Policy-Report-Only` until the reports are clean, then enforce it; add HSTS, `nosniff`, framing control, and `Secure; HttpOnly; SameSite` cookies. A CSP of `default-src *` is the same as none. → [`WEB-01`](../../checklist/web.md#web-01), [`WEB-05`](../../checklist/web.md#web-05)
- **Uploads.** Require auth on the upload endpoint, validate by content, store private and serve via signed URLs, and never serve user HTML/SVG from your own origin. An unauthenticated `/api/upload` that lands in a public bucket is two breaches at once. → [`FILE-01`](../../checklist/files.md#file-01), [`FILE-04`](../../checklist/files.md#file-04)
- **Don't leak existence.** Login, signup, and password reset return one neutral answer, in constant time, whether or not the account exists — always run the password hash, even against a dummy made with the app's own hasher and cost, so "no such user" is not measurably faster than "wrong password". Count failed attempts per submitted identifier, send emails from a queue, and check "disabled" or "unverified" only after the password. Never "fix" timing with a random sleep. → [`AUTH-13`](../../checklist/authentication.md#auth-13), [`LEAK-01`](../../checklist/leakage.md#leak-01)
- **No `admin` to find.** No account named `admin`, `root`, or `test` in production; privileged users sign in through the company IdP with passkeys or hardware keys, never through the public login form. → [`AUTH-14`](../../checklist/authentication.md#auth-14)
- **Server-side money and quotas.** Compute prices, totals, and remaining quota on the server; never trust an amount or a limit from the client. → [`LOGIC-02`](../../checklist/logic.md#logic-02)

---

## Full reference

These paths resolve when the skill is installed as the plugin or read in the repository. A
skill copied on its own has only this file.

- [`checklist.md`](../../checklist.md) — the entry point, triage, and domain map
- [`checklist/`](../../checklist/) — 165 controls across 19 domains, each with Detect / Fix / Verify / Probe
- [`checklist/probe-playbook.md`](../../checklist/probe-playbook.md) — black-box checks against a running app
- [`vulnerabilities.md`](../../vulnerabilities.md) — the same ground by vulnerability class (IDOR, BOLA, SSRF, …)
- [`incidents/`](../../incidents/) — the breach corpus these rules come from
- [`incidents/STATS.md`](../../incidents/STATS.md) — which failures actually appear most often

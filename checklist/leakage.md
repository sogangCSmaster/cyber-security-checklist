# LEAK · Information disclosure — what you give away for free

A system leaks not only when it hands over records, but when it *answers questions it was never
asked*: whether an account exists, how long a comparison took, what framework it runs, what the
next record's id is. None of these is a breach on its own. Every one of them is the reconnaissance
step that makes the breach cheap.

← [Back to the checklist](../checklist.md) · Related: [`AUTH`](./authentication.md), [`API`](./api.md), [`CRYPTO`](./crypto.md), [`OBSV`](./observability.md)

---

### LEAK-01
**P1 · code** — No endpoint reveals whether an account or resource exists. Login, signup, password reset, and "check availability" give one identical response regardless.

- **Why:** account enumeration is the first step of every credential-stuffing and phishing campaign — 23andMe (2023) and Nintendo (2020) both began by knowing which accounts were real. A signup that says *"email already in use"* and a reset that says *"no account with that email"* hand the attacker a membership oracle for free.
- **Detect:** exercise each account-touching endpoint with a known-real and a known-fake identifier and diff the responses — message text, status code, and whether the side effect (an email sent) differs.
- **Fix:** one neutral answer per flow, and nothing on the response path that only happens for real accounts:
  - **Password reset** — always *"If an account exists for that address, we've sent a link."* Send the email from a background queue: a synchronous send only for real accounts makes the response measurably slower, which is the same oracle as [`AUTH-13`](./authentication.md#auth-13).
  - **Sign-up** — accept the submission either way and reply *"Check your email to continue."* A new address gets a verification link; an existing one gets *"You already have an account — sign in or reset your password."* The page never says "email already in use".
  - **Login** — [`AUTH-13`](./authentication.md#auth-13).
  - **Magic-link and one-time-code login** — the same pattern as reset: one answer, queued send.
  - **"Is this username available?"** — if usernames are public by design (profile URLs, @handles), availability is not a secret, but rate-limit the check ([`API-05`](./api.md#api-05)). If they are not public, do not offer the check before sign-up completes.
- **Verify:** for each flow, a test asserts the response for a nonexistent account is byte-identical to the one for a real account (status, body, headers, cookies), and that the median response time over many attempts does not differ by the cost of an email send or a hash.
- **Probe:** [playbook §4](./probe-playbook.md#4--auth-responses--timing-and-message-differences-worked-example).

### LEAK-02
**P1 · code** — Security decisions run in time independent of the secret. No comparison, lookup, or hash short-circuits in a way an outsider can measure.

- **Why:** the **timing oracle** worked example — a nonexistent login returned far faster than a real account with a wrong password, because only the real path ran the password hash (~0.06 s vs ~1.0 s), confirming which usernames existed. The same class covers token and API-key comparison that stops at the first differing byte, and coupon/2FA-code checks that return early.
- **Detect:** find every place a user-supplied value is compared against a secret or used to gate work — auth, token/HMAC verification, password-reset tokens, API keys, one-time codes. Does any of them branch or return before doing constant work? Then look *after* the comparison: work that runs on only one branch (a counter write, an email, a webhook) reintroduces the difference.
- **Fix:** use constant-time comparison for secrets (`hmac.compare_digest`, `crypto.timingSafeEqual`) ([`CRYPTO-03`](./crypto.md#crypto-03)); on the login path, hash even when the account is absent ([`AUTH-13`](./authentication.md#auth-13)); move one-branch side effects to a background queue; avoid early returns keyed on secret existence. **Random delays are not a fix** — averaging over many requests removes the noise and leaves the difference.
- **Verify:** measure each branch many times and compare medians; the difference must be within noise, not the cost of the skipped work.
- **Probe:** [playbook §4](./probe-playbook.md#4--auth-responses--timing-and-message-differences-worked-example).

### LEAK-03
**P1 · config** — Errors returned to clients are generic. No stack traces, database errors, framework debug pages, or internal hostnames leave the server.

- **Why:** a stack trace names your framework, versions, file paths, and often the failing query; a raw database error is the difference between blind and error-based SQL injection. Debug mode left on in production is a recurring finding across the corpus's misconfiguration cases.
- **Detect:** force errors — a string where a number is expected, malformed JSON, a missing field — and read the body. Grep config for `DEBUG=True`, `app.debug`, `NODE_ENV` not set to `production`, detailed-error flags.
- **Fix:** a global error handler that logs the detail server-side and returns a generic message with a correlation id; debug mode off in production, enforced by config, not habit.
- **Verify:** trigger a handled and an unhandled error in a production-like build and confirm neither body contains a trace, a query, or a path.
- **Probe:** [playbook §7](./probe-playbook.md#7--error-and-metadata-leakage--what-the-app-tells-you-when-it-fails).

### LEAK-04
**P1 · code** — Identifiers exposed to clients are unguessable, and unguessability is never the *only* control. Nothing leaks the size, order, or existence of the data set.

- **Why:** First American (2019) — sequential document IDs made 885M documents walkable by editing a number; the missing authorization check ([`API-01`](./api.md#api-01)) was the flaw, but the sequence was the convenience that made it a five-minute job. Sequential IDs also leak volume and growth rate ("how many customers do they have").
- **Detect:** look at the IDs in URLs and responses — are they sequential integers? Do responses include total counts, or `next`/`previous` cursors that reveal ordering, on data the caller should not be able to size?
- **Fix:** use opaque, random identifiers (UUIDv4, ULID) for anything client-facing; keep the authorization check regardless; do not return global counts on per-user endpoints.
- **Verify:** confirm client-facing IDs are non-sequential *and* that [`API-01`](./api.md#api-01)'s ownership test passes — random IDs with no check still fail.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record).

### LEAK-05
**P2 · config** — Version and stack banners are removed from responses.

- **Why:** `Server: nginx/1.18.0`, `X-Powered-By: Express`, `X-AspNet-Version` tell an attacker exactly which known vulnerabilities to try first. It is free reconnaissance that the framework emits by default.
- **Detect:** read the response headers ([playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example)) for `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.
- **Fix:** strip or generacize these at the app or proxy layer.
- **Verify:** a header check confirms none of the version-bearing headers is present.
- **Probe:** [playbook §7](./probe-playbook.md#7--error-and-metadata-leakage--what-the-app-tells-you-when-it-fails).

### LEAK-06
**P2 · code** — Files and exports are stripped of hidden metadata before they leave; responses and URLs carry no secrets or full identifiers.

- **Why:** uploaded photos carry EXIF GPS coordinates; exported PDFs and spreadsheets carry author names, tracked changes, and hidden columns; a token placed in a URL ends up in logs, referers, and browser history. Each is data the user did not know they were sending.
- **Detect:** inspect an uploaded image's EXIF and a generated export's metadata; grep for tokens or session ids passed as query parameters rather than headers.
- **Fix:** strip metadata server-side on upload and on export; carry secrets in headers or bodies, never in URLs; do not echo full identifiers you do not need to.
- **Verify:** upload an image with GPS EXIF and confirm the stored/served copy has none; confirm no endpoint places a token in a query string.

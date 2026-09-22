# AUTH · Identity, authentication, authorization

Who the caller is, how they prove it, and how that proof is managed over its life. Authorization
of a *specific object* on a *specific request* lives in [`api.md`](./api.md); this file is about
establishing identity in the first place and not giving it away.

← [Back to the checklist](../checklist.md) · Related: [`API`](./api.md), [`LEAK`](./leakage.md), [`WEB`](./web.md), [`HUMAN`](./people.md)

---

### AUTH-01
**P0 · process** — Phishing-resistant MFA on every human account with production reach, including contractors, legacy accounts, and test tenants.

- **Why:** Change Healthcare, 2024 — a Citrix portal with no MFA, nine days of undetected lateral movement, ~190M people, $3B+ cost. Colonial Pipeline, 2021 — one legacy VPN account, no MFA, password present in a credential dump.
- **Detect:** enumerate every identity provider, VPN, cloud console, database, registry, and SaaS admin, and list the accounts on each that can reach production. The gap is always the account nobody remembered.
- **Fix:** require MFA — WebAuthn/passkeys or a hardware key where possible — on every one, with no exempt "service" humans. Disable accounts that cannot carry it rather than exempting them.
- **Verify:** for each account with production access, confirm MFA is enrolled and enforced, not merely available. A policy that permits a fallback to password is not enforcement.
- **Probe:** from the outside you cannot see MFA on internal consoles, but you can confirm the *public* login enforces it — complete a password login and check that a second factor is demanded before any authenticated action.

### AUTH-02
**P0 · code** — Authorization is checked server-side, per object, on every request — the caller may act on *this* record, not merely on records of this type.

- **Why:** First American Financial, 2019 — sequential document IDs in the URL with no authorization check: 885M documents back to 2003, readable by editing a number. This is the corpus's most-cited authorization failure and the canonical IDOR. Its API-layer treatment, with probes, is [`API-01`](./api.md#api-01); make the identifier unguessable too ([`INPUT-09`](./input.md#input-09)), but the missing check is the finding, not the id shape.
- **Detect:** read each handler that takes an id. Does it verify the object belongs to the session user, or just look it up and return it?
- **Fix:** derive the user from the session and scope every query by ownership (`WHERE id = ? AND owner_id = ?`); never trust an id from the request to decide access.
- **Verify:** authenticate as user A, request user B's record by id, assert `403`/`404`; automate it as [`DATA-02`](./data.md#data-02).
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record).

### AUTH-03
**P0 · code** — No unauthenticated endpoint returns or accepts user data. Read *and* write.

- **Why:** Optus, 2022 — one unauthenticated API, 9.8M customers, 2.1M identity documents. The write side is the same failure: an unauthenticated upload or create endpoint (see [`FILE-01`](./files.md#file-01)).
- **Detect:** for every endpoint, ask what it returns or mutates with no session. Grep for handlers that read `request.body` before any auth call.
- **Fix:** require authentication on data endpoints; if something is genuinely public (a health check, a marketing page), it returns nothing user-specific.
- **Verify:** the negative test above, extended to POST/PUT endpoints.
- **Probe:** [playbook §2](./probe-playbook.md#2--the-unauthenticated-sweep--what-answers-with-no-credentials).

### AUTH-04
**P1 · code** — Sessions are short-lived, revocable, rotated on privilege change, and carried in a cookie with `Secure`, `HttpOnly`, `SameSite`.

- **Why:** CircleCI, 2022 — malware stole a valid, 2FA-backed SSO session cookie. A session is a bearer token; the MFA already happened, so the cookie is the credential.
- **Detect:** read the session config — lifetime, whether logout and password-change invalidate server-side, and the cookie flags. Grep `Set-Cookie`.
- **Fix:** server-side revocable sessions with a sane idle and absolute lifetime; rotate the session id on login and on privilege elevation; set all three cookie flags. (Flags themselves: [`WEB-05`](./web.md#web-05).)
- **Verify:** log in, copy the cookie, log out, and confirm the copied cookie is now rejected.
- **Probe:** inspect `Set-Cookie` in the response headers ([playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example)); a session cookie missing `HttpOnly` is reachable from any XSS.

### AUTH-05
**P1 · process** — Account recovery and help-desk paths are as strong as the login path.

- **Why:** MGM Resorts, 2023 — ten minutes of LinkedIn research, one help-desk call, an Okta password and MFA reset, ~$100M. Instructure, 2026 — voice phishing posing as IT, 30M+ students and staff. Meta, 2026 — their own AI chatbot used to reset passwords.
- **Detect:** map every way an account's credentials or MFA can be reset, including the human ones. Recovery is a login path; treat it as one.
- **Fix:** identity proofing on reset that does not rely on facts an attacker can gather (see [`HUMAN-01`](./people.md#human-01)); MFA re-enrolment that requires the old factor or a strong out-of-band check.
- **Verify:** call your own help desk and try to reset an account you do not own. Do not warn them first.
- **Probe:** exercise the self-service reset flow and confirm it does not, by itself, hand over a session (and does not enumerate accounts — [`LEAK-01`](./leakage.md#leak-01)).

### AUTH-06
**P1 · code** — Rate limiting, lockout, and breached-password checks on all authentication surfaces.

- **Why:** 23andMe, 2023 — credential stuffing against ~14k accounts with reused passwords, which then fanned out to 6.9M via a sharing feature. Nintendo, 2020 — credential stuffing against a legacy login.
- **Detect:** find login, reset, token, and lookup endpoints; check for any throttle, lockout, or CAPTCHA, and whether new passwords are checked against a breach corpus.
- **Fix:** per-account and per-IP rate limits with backoff, temporary lockout on repeated failure, and a `Have I Been Pwned`-style check at set-password time.
- **Verify:** an automated test confirms the Nth rapid attempt is throttled or locked.
- **Probe:** against staging only, send repeated attempts and confirm the Nth is refused — [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### AUTH-07
**P1 · code** — Admin and impersonation tooling sits behind separate authentication and full audit.

- **Why:** Twitter, 2020 — vishing employees reached an internal account-management tool with no per-action approval: 130 high-profile accounts.
- **Detect:** find the admin surface. Does it share the ordinary session, or require a step-up? Is every privileged action logged with the operator identity?
- **Fix:** step-up authentication for admin, per-action logging that names the human, and approval on the highest-impact actions ([`HUMAN-02`](./people.md#human-02)).
- **Verify:** confirm an ordinary session cannot reach an admin action without the step-up, and that the action appears in the audit log.

### AUTH-08
**P1 · process** — Access is inventoried, owned, and expires when unused.

- **Why:** Klue, 2026 — a credential issued in 2022 for a pilot, never revoked, reached ~200 customer companies four years later.
- **Detect:** can you produce a list of who has access to what, and when each was last used?
- **Fix:** periodic access review, an owner per grant, and automatic expiry of unused access.
- **Verify:** pull the access list and find the oldest unused grant; it should already be gone.

### AUTH-09
**P1 · config** — MFA cannot be satisfied by a tap. Number matching or hardware keys.

- **Why:** Uber, 2022 — MFA push-bombing a contractor until they approved one prompt out of fatigue.
- **Detect:** check the MFA method configured in the IdP — simple push approval is the weak one.
- **Fix:** number matching, or phishing-resistant WebAuthn/hardware keys.
- **Verify:** trigger an MFA challenge and confirm it requires matching a number or a key, not a bare "approve".

### AUTH-10
**P1 · config** — Legacy and alternative login paths are disabled, not merely deprecated.

- **Why:** Nintendo, 2020 — credential stuffing against the legacy NNID login. Microsoft, 2024 — password spraying a legacy, non-production test tenant with no MFA, which held an OAuth app with corporate reach.
- **Detect:** enumerate every way in — old SSO endpoints, basic-auth API paths, legacy mobile endpoints, a deprecated tenant. "Deprecated" and "reachable" are different words.
- **Fix:** turn the old path off at the server, not just remove the link to it.
- **Verify:** request the legacy login endpoint and confirm it is gone, not merely unlinked.
- **Probe:** try known legacy paths and older API versions — [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### AUTH-11
**P1 · code** — Every state-changing interface authenticates its caller, including the ones that are not HTTP.

- **Why:** St. Jude implantable cardiac devices, 2016 — a radio command interface accepted state-changing commands from an unauthenticated party nearby. The same gap appears in message queues, serial and Bluetooth interfaces, gRPC, and internal services assumed to be "behind the firewall".
- **Detect:** enumerate every interface that can change state, not just the web routes — queues, sockets, RPC, hardware buses, internal service-to-service calls.
- **Fix:** authenticate the caller on each; "internal" is not authentication.
- **Verify:** for each non-HTTP interface, confirm an unauthenticated message is rejected.

### AUTH-12
**P1 · code** — Federated logins (OAuth/OIDC/SAML) are validated in full: signature, issuer, audience, expiry, and nonce. A well-formed token is not a valid one.

- **Why:** the recurring pattern behind token-forgery and "sign in with" bypasses — code that decodes a token and trusts its claims without verifying the signature against the provider's keys, or without checking the token was issued *for this application*.
- **Detect:** read the token-validation code. Is the signature verified against the provider's current JWKS? Are `iss`, `aud`, `exp`, and `nonce` all checked? Is the algorithm pinned (no `alg: none`, no HS/RS confusion)?
- **Fix:** use the provider's vetted library with signature verification on, pin the expected algorithm, and check issuer and audience explicitly.
- **Verify:** feed the validator a token with a good body but a bad signature, and one with the wrong `aud`, and confirm both are rejected.

### AUTH-13
**P1 · code** — Login returns the same answer, in the same time, with the same side effects, whether or not the account exists.

- **Why:** the login **timing oracle** — a self-test of a real platform found that logging in as a nonexistent user returned in ~0.06 s while `admin` with a wrong password took ~1.0 s, because only the existing-account path ran the slow password hash. That gap confirmed `admin` existed. A difference in message (`"no such user"` vs `"wrong password"`), status (`404` vs `401`), response size, or cookies leaks the same fact more loudly.
- **Detect:**
  - **Hand-written handlers** — the shape AI generates most often: the user lookup misses and the handler returns *before* any hash runs (`if (!user) return 401` above `bcrypt.compare`).
  - **Framework auth** — some already do constant work: Django's `ModelBackend` runs the default hasher when the user is missing, and Spring Security's `DaoAuthenticationProvider` compares against a precomputed dummy. Confirm the built-in path is the one actually used, and that custom code wrapped around it has not reintroduced an early return.
  - **Work after the hash that only real accounts get** — a failed-attempt counter write, a lockout lookup, a synchronous "someone tried to sign in" email or webhook, audit rows joined to the user record.
  - **Order of checks** — "account disabled", "email not verified", or "MFA not enrolled" checked *before* the password, which tells someone who does not know the password that the account exists.
- **Fix:**
  1. **Equal work.** When the account does not exist, verify the submitted password against a dummy hash produced by **the app's own hashing function with its current parameters** — same algorithm, same cost. A dummy made with library defaults (`gensalt()`) differs from real hashes made at another cost or with argon2, and the gap survives.
  2. **One answer.** Identical status, body, headers, and cookies on every failure: `401 Invalid username or password`.
  3. **Password first, account state second.** Say "disabled", "unverified", or "enrol MFA" only after the password has verified.
  4. **Equal side effects.** Count failed attempts and apply throttling per *submitted identifier*, whether or not an account exists, so lockout looks the same for both. Send emails and webhooks, and write heavy audit records, from a background queue so they never sit on the response path.
  5. **Not a fix: random delays.** A `sleep(random())` adds noise that averaging over many attempts removes; the difference in means remains. Equal work is the fix; a fixed minimum response time is at most a supplement.
  6. Residual micro-differences (a cache hit versus a database miss) cannot be engineered away entirely. Remove the large, reliable signal — the hash — and make what remains impractical to measure with rate limits per IP and per identifier ([`AUTH-06`](#auth-06)).
  ```python
  # constant-work login; hash_password / verify_password are the app's own helpers
  DUMMY_HASH = hash_password(secrets.token_urlsafe(16))   # same algorithm and cost as real hashes

  def login(username, password):
      user = find_user(username)
      ok = verify_password(password, user.password_hash if user else DUMMY_HASH)
      if user is None or not ok:
          queue_failed_attempt(username)                   # keyed by submitted id, off the response path
          return error(401, "Invalid username or password")
      if user.disabled or not user.email_verified:         # account state only after the password
          return error(403, "Account needs attention")
      return start_session(user)
  ```
- **Verify:**
  - A test issues dozens of failed logins on each path — a nonexistent identifier, and a real one with a wrong password — and compares the **medians**. The difference must be far below the cost of one hash (single-digit milliseconds, not hundreds); one attempt each proves nothing.
  - The two failure responses are byte-identical: status, body, headers, `Set-Cookie`, and length.
  - After N failures, a nonexistent identifier receives the same throttle or lockout response as a real one.
- **Probe:** the timing comparison in [playbook §4](./probe-playbook.md#4--auth-responses--timing-and-message-differences-worked-example). Related: [`LEAK-01`](./leakage.md#leak-01), [`LEAK-02`](./leakage.md#leak-02), and [`AUTH-14`](#auth-14) — why confirming that `admin` exists should be worth nothing.

### AUTH-14
**P1 · config** — Privileged accounts are worth nothing to someone who learns they exist: no predictable identifiers, no path through the public login, phishing-resistant MFA always.

- **Why:** enumeration is half of an attack; the other half is what the confirmed account can do. McHire, 2025 — the staff login accepted a leftover test account whose username and password were both `123456`, which carried a restaurant-owner administrative view; with an IDOR behind it, 64M applicant records were reachable. The timing oracle in [`AUTH-13`](#auth-13) mattered precisely because it confirmed an account named `admin`.
- **Detect:**
  - Accounts named `admin`, `administrator`, `root`, `test`, `demo`, `support`, `superuser`, or the company name — in the production user table, seed data, fixtures, and migrations.
  - Whether privileged roles can sign in through the same public form and endpoint as customers.
  - Test, demo, and seed accounts present in production at all.
  - Privileged accounts without phishing-resistant MFA, or with MFA that can be skipped.
- **Fix:**
  - Give every privileged human a personal, non-guessable identity tied to SSO — never a shared `admin`.
  - Serve privileged sign-in from a separate surface (the company IdP, an allowlisted network, or a separate admin host), and have the public login refuse privileged roles outright ([`AUTH-07`](#auth-07), [`CLOUD-08`](./cloud.md#cloud-08)).
  - Require phishing-resistant MFA — passkeys or hardware keys — on every privileged account ([`AUTH-01`](#auth-01), [`AUTH-09`](#auth-09)).
  - Remove test, demo, and seed accounts from production, and make the deploy refuse to load seed data there ([`CRED-10`](./secrets.md#cred-10)).
  - Alert on any sign-in attempt against a reserved or privileged identifier through the public login; with no such account there, every attempt is reconnaissance ([`OBSV-02`](./observability.md#obsv-02)).
- **Verify:** the public login rejects a privileged account even with the correct password; no reserved identifier exists in the production user table; every privileged account shows phishing-resistant MFA enrolled and enforced.
- **Probe:** a sign-in attempt for `admin` through the public login behaves exactly like any other failure ([playbook §4](./probe-playbook.md#4--auth-responses--timing-and-message-differences-worked-example)) — and there is no such account there to confirm.

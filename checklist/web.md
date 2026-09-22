# WEB · Browser trust — headers, CSP, cookies, CSRF

The browser will do whatever your responses tell it to: run any script the page references, frame
your page inside another, send your cookies along with a cross-site request. These controls are
the instructions that tell it not to. Most are a header — a config change, not a code change — and
most AI-generated apps ship with them absent or, worse, present but neutered.

← [Back to the checklist](../checklist.md) · Related: [`INPUT`](./input.md), [`FILE`](./files.md), [`DEPS`](./dependencies.md), [`AUTH`](./authentication.md)

---

### WEB-01
**P0 · config** — A Content-Security-Policy that actually constrains script. No `default-src *`, no `'unsafe-inline'`, no `'unsafe-eval'` on `script-src`.

- **Why:** a self-test of a real platform found this header:
  `default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'`.
  It looks like a CSP and passes a "has a CSP" checkbox, but `*` allows script from anywhere,
  `'unsafe-inline'` allows injected `<script>`, and `'unsafe-eval'` allows `eval` — it closes none
  of the paths a CSP exists to close. It is equivalent to no CSP. A real CSP is the defense-in-depth
  that would have limited the British Airways (2018) formjacking script, which ran because nothing
  constrained where script could come from.
- **Detect:** read the `Content-Security-Policy` response header. Any `*` in `script-src`/`default-src`, or either unsafe keyword, fails. No header at all also fails.
- **Fix:** a nonce- or hash-based policy: `script-src 'self' 'nonce-<per-response-random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'` and tighten from there. Move inline scripts to files or attach the per-response nonce. Deploy `Content-Security-Policy-Report-Only` first to find breakage, then enforce.
- **Verify:** confirm the enforced header has no `*` in `script-src`, no unsafe keywords, and that an injected inline `<script>` without the nonce does not execute.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

### WEB-02
**P1 · config** — HTTPS is enforced everywhere and `Strict-Transport-Security` is set with a long max-age. No mixed content.

- **Why:** without HSTS, the first request is plaintext and strippable; mixed content lets an active network attacker replace a script. HTTPS-only is the floor for every other browser control.
- **Detect:** check for the `Strict-Transport-Security` header and for any `http://` resource references or redirects that land on HTTP first.
- **Fix:** `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`; redirect all HTTP to HTTPS; serve every subresource over HTTPS.
- **Verify:** confirm the header is present and that an `http://` request redirects to `https://` before any content.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

### WEB-03
**P1 · config** — `X-Content-Type-Options: nosniff` is set so the browser does not second-guess declared content types.

- **Why:** without it, a browser may sniff a response as HTML or script even when it was meant as data — turning an uploaded or reflected file into executable content. It is one header and it closes a whole class of content-type confusion.
- **Detect:** check the header on app responses and especially on any route that serves user content.
- **Fix:** set `X-Content-Type-Options: nosniff` globally.
- **Verify:** header present on responses.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

### WEB-04
**P1 · config** — Framing is controlled: `frame-ancestors` in CSP (and/or `X-Frame-Options`) prevents your pages being embedded by other sites.

- **Why:** clickjacking — your page loaded invisibly inside an attacker's, so a user's clicks land on your controls (transfer, approve, delete) without their knowledge.
- **Detect:** check for `frame-ancestors` in the CSP or `X-Frame-Options: DENY|SAMEORIGIN`.
- **Fix:** `frame-ancestors 'none'` (or an explicit allowlist for pages meant to be embedded).
- **Verify:** attempt to load a sensitive page in an `<iframe>` from another origin and confirm the browser blocks it.

### WEB-05
**P1 · config** — Cookies carrying identity are `Secure`, `HttpOnly`, and `SameSite`, and scoped to the narrowest domain/path.

- **Why:** `HttpOnly` keeps a session cookie out of reach of any XSS; `Secure` keeps it off plaintext; `SameSite` blocks it from riding cross-site requests (a CSRF defense, [`WEB-07`](#web-07)). CircleCI (2022) showed a stolen session cookie is a full credential.
- **Detect:** read every `Set-Cookie`. Missing any of the three flags on a session/auth cookie fails.
- **Fix:** set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on identity cookies; scope `Domain`/`Path` tightly.
- **Verify:** inspect `Set-Cookie` on login and confirm all three flags on the session cookie.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

### WEB-06
**P1 · code** — User-supplied content is output-encoded for its context and never rendered as trusted HTML in the app origin.

- **Why:** cross-site scripting — stored or reflected user input executed as script in another user's session. The most common web flaw for two decades, and AI-generated front ends reach for `dangerouslySetInnerHTML`/`v-html`/`innerHTML` freely. Uploaded HTML/SVG is the same failure through storage ([`FILE-02`](./files.md#file-02)).
- **Detect:** grep for `dangerouslySetInnerHTML`, `innerHTML =`, `v-html`, `document.write`, template `| safe`/`{{{ }}}`, and any place server-rendered HTML interpolates user data without escaping.
- **Fix:** let the framework auto-escape; where raw HTML is unavoidable, sanitize with a vetted allowlist library (DOMPurify) on the server; serve user files off-origin ([`FILE-02`](./files.md#file-02)); rely on [`WEB-01`](#web-01) as the second layer.
- **Verify:** submit `<script>`/`<img onerror>` payloads through each user-content path and confirm they render inert.
- **Probe:** reflect test markup through search, profile, and comment fields against staging and confirm it does not execute.

### WEB-07
**P1 · code** — State-changing requests are protected against cross-site request forgery.

- **Why:** without it, another site can cause a logged-in user's browser to submit a request — change email, transfer, delete — using their ambient cookie.
- **Detect:** check whether state-changing endpoints require an anti-CSRF token or rely on `SameSite` cookies plus a non-simple content type; look for cookie-authenticated `GET`s that change state.
- **Fix:** anti-CSRF tokens for cookie-based sessions, `SameSite=Lax/Strict` as reinforcement, and never mutate state on `GET`. Token-in-header auth (not cookies) is not CSRF-able.
- **Verify:** replay a state-changing request without the CSRF token / from a cross-site context and confirm rejection.

### WEB-08
**P2 · config** — CORS is not wildcarded with credentials; `Referrer-Policy` and `Permissions-Policy` are set.

- **Why:** `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true` (or reflecting an arbitrary `Origin`) lets any site read authenticated responses. A permissive referrer policy leaks URLs (with any tokens in them) to third parties.
- **Detect:** read the CORS config and the `Access-Control-*` headers; check `Referrer-Policy` and `Permissions-Policy`.
- **Fix:** allowlist specific origins for credentialed CORS; `Referrer-Policy: strict-origin-when-cross-origin`; a restrictive `Permissions-Policy`.
- **Verify:** send a cross-origin credentialed request from a non-allowlisted origin and confirm it is not permitted to read the response.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

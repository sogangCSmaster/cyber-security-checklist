# The black-box probe playbook

Everything else in this repository reviews **source you can read**. This file is the other half:
the checks you run against a **running deployment**, from the outside, with no source access —
the way a real attacker meets your system, and the way an AI told to "test my app" actually
behaves. It fires ordinary requests at ordinary URLs and reads what comes back.

Every **Probe** field in the domain files is collected and ordered here.

---

## Rules of engagement — read first

These are tests against a live system. Run them **only** against systems you own or have explicit,
current authorization to test.

- **Scope in writing.** Know exactly which hostnames and paths are in scope. A staging or
  pre-production copy is the right target; production is a last resort and only with sign-off.
- **Do not damage or exfiltrate.** The goal is to learn whether a door is open, not to walk
  through it and take things. Confirm an upload endpoint accepts an unauthenticated file with one
  harmless marker file, then stop — do not enumerate or download other people's data. If a probe
  starts returning real personal data, you have your finding: stop, record it, and report it.
- **Throttle yourself.** Enumeration and timing loops look exactly like an attack to any
  monitoring you have. Tell whoever runs detection that you are testing, keep request rates low,
  and never run a lockout or resource-exhaustion probe against production.
- **Log what you did.** A probe run should be reproducible and reversible. Note the time, the
  target, and every request that got an interesting response.
- **A finding is a finding regardless of who found it.** If your own AI tester reports that
  `/api/upload` took an unauthenticated file, that is real — treat it with the same seriousness
  as an external report.

The three worked examples below (a login timing oracle, an unauthenticated upload reaching a
public bucket, a Content-Security-Policy that is disabled in all but name) are drawn from a real
self-test of a real platform. The bucket names, hostnames, and account names are generic here on
purpose; substitute your own.

---

## How to run a pass

Set a base URL and a couple of helpers once, then work the sections in order.

```bash
BASE="https://staging.example.com"          # a target you are authorized to test
UA="security-selftest/1.0 (authorized)"     # identify yourself to your own logs
c() { curl -sS -A "$UA" -o /dev/null -w "%{http_code} %{size_download}B %{time_total}s  $1\n" "$BASE$1"; }
```

`c /path` prints the status, response size, and wall-clock time for one GET. That is enough for
most of the surface-mapping and exposure checks; the auth and upload sections below add a few more
lines.

Work the sections **in this order** — it moves from "what exists" to "what is open" to "what
leaks", which is the order that minimizes noise and maximizes what each step tells the next.

---

## 1 · Map the surface — what endpoints exist at all

You cannot test an endpoint you do not know about. Before probing behaviour, enumerate the
attack surface the way an outsider would.

- **Read the client for its own API.** The single richest source of endpoints is the app's own
  JavaScript bundle — it contains every path the front end calls. Load the site, open the network
  tab, and also pull the bundle directly and grep it:
  ```bash
  # collect the script URLs the page loads, then grep each for API paths
  curl -sS -A "$UA" "$BASE/" | grep -oE '<script[^>]+src="[^"]+"' | grep -oE 'https?://[^"]+|/[^"]+'
  # in a downloaded bundle: paths, fetch calls, and route tables
  grep -oE '"/(api|v[0-9]+|internal|admin|graphql)/[a-zA-Z0-9/_-]+"' bundle.js | sort -u
  ```
- **Check the conventional locations.** `robots.txt`, `sitemap.xml`, `/.well-known/`,
  `/openapi.json`, `/swagger.json`, `/graphql`, `/.git/config`, `/.env`, `/actuator`, `/metrics`,
  `/debug`. A single GET each:
  ```bash
  for p in /robots.txt /sitemap.xml /openapi.json /swagger.json /graphql /.git/config /.env /actuator/health /metrics /server-status; do c "$p"; done
  ```
- **Note the common API shapes.** Most frameworks and most AI-generated backends converge on the
  same paths: `/api/users`, `/api/user/{id}`, `/api/me`, `/api/admin`, `/api/upload`,
  `/api/files`, `/api/export`, `/api/login`, `/api/register`, `/api/reset`, `/api/orders/{id}`.
  You are not guessing blindly — you are checking the paths every similar app has.

**What you are building:** a list of real endpoints, each tagged as read or write, authenticated
or not. Everything below runs against that list.

→ Controls: [`API-07` shadow/zombie APIs](./api.md#api-07), [`CLOUD-09` asset inventory](./cloud.md#cloud-09).

---

## 2 · The unauthenticated sweep — what answers with no credentials

For every endpoint from step 1, send the request **with no session, no token, no cookie** and see
what happens. This is the cheapest and highest-yield probe in the whole playbook.

```bash
# GETs that return data unauthenticated
for p in /api/users /api/me /api/orders /api/export /api/admin/stats; do c "$p"; done
# a write endpoint that accepts input unauthenticated is worse — note any 2xx
curl -sS -A "$UA" -X POST -H 'content-type: application/json' -d '{}' -w '\n%{http_code}\n' "$BASE/api/upload"
```

- **A `200` with a body on a data endpoint** means missing authentication → [`AUTH-03`](./authentication.md#auth-03). Optus lost 9.8M customer records through exactly one such endpoint.
- **A `200` or `201` on a *write* endpoint** — upload, create, invite, reset — means an
  unauthenticated mutation. This is the first of the three worked examples and it gets its own
  section below.
- **A `401`/`403`** is the right answer. A `302` to a login page is usually fine for a browser
  route but suspicious for an API (it may mean the check is a redirect, not a refusal — see step 8).

→ Controls: [`AUTH-03`](./authentication.md#auth-03), [`FILE-01`](./files.md#file-01), [`API-01`](./api.md#api-01).

---

## 3 · Object-reference walking — can you read someone else's record

Authenticate as one ordinary user. Now request objects that belong to **other** users by changing
the identifier. This is IDOR / BOLA, and it is the most common serious flaw in AI-generated code
because the happy path works perfectly.

```bash
# as user A (TOKEN_A), fetch your own record, then walk the id
AUTH="-H \"authorization: Bearer $TOKEN_A\""
curl -sS -A "$UA" -H "authorization: Bearer $TOKEN_A" "$BASE/api/orders/1001"   # yours
curl -sS -A "$UA" -H "authorization: Bearer $TOKEN_A" "$BASE/api/orders/1002"   # the next one — should be 403
```

- **Sequential integer IDs** (`1001`, `1002`, …) make this trivial and are a smell in themselves,
  but random IDs only slow it down — the finding is the **missing ownership check**, not the ID
  shape. First American exposed 885 million documents this way; the IDs were sequential, but the
  fix was the check, not the randomness → [`API-01`](./api.md#api-01), [`LEAK-04`](./leakage.md#leak-04).
- **Try every verb, not just GET.** An endpoint may check ownership on read but not on
  `PUT`/`PATCH`/`DELETE`. Confirm you cannot modify or delete B's object either → [`API-02`](./api.md#api-02).
- **Try the id in every position** — URL path, query string, JSON body, and headers like
  `X-User-Id`. Some code trusts a body or header field over the session → [`API-03` mass assignment](./api.md#api-03).

→ Controls: [`API-01`](./api.md#api-01), [`API-02`](./api.md#api-02), [`API-03`](./api.md#api-03).

---

## 4 · Auth responses — timing and message differences (worked example)

**The setup.** Log in with an account you *know* does not exist. Then log in with an account you
know *does* exist (or suspect — `admin`, `administrator`, `root`, a known support address) and a
deliberately wrong password. Compare three things about the two responses: the **message**, the
**status code**, and the **time**.

**Why timing leaks.** A correct login flow, on a *wrong* password, still runs the slow password
hash (bcrypt/argon2/scrypt) to decide it is wrong. But a naive flow **skips the hash when the
account does not exist** — there is nothing to compare against — and returns early. So:

- nonexistent account → fast (no hash) — e.g. ~0.06 s
- real account, wrong password → slow (one hash) — e.g. ~1.0 s

That gap *is* a user-enumeration oracle: it confirms which usernames are real, and in the worked
example it confirmed that `admin` existed while random names did not. Message and status
differences (`"user not found"` vs `"wrong password"`, or `404` vs `401`) leak the same fact more
loudly.

```bash
# time a login attempt; run each a few times and compare the medians
login() { curl -sS -A "$UA" -o /dev/null -w "%{time_total}s  http=%{http_code}  $1\n" \
  -X POST -H 'content-type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"wrong-password-000\"}" "$BASE/api/login"; }

for i in 1 2 3 4 5; do login "definitely-not-a-real-user-$RANDOM"; done   # expect: fast
for i in 1 2 3 4 5; do login "admin"; done                               # slow ⇒ admin exists
```

- **The finding is a *difference*.** If the nonexistent-user attempts are consistently faster than
  the real-user-wrong-password attempts by roughly the cost of one hash, you have a timing oracle
  → [`AUTH-13`](./authentication.md#auth-13), [`LEAK-02`](./leakage.md#leak-02).
- **Repeat on every account-touching endpoint**, not just login: registration ("email already in
  use"), password reset ("no account with that email"), and any "check availability" call. Each is
  its own enumeration surface → [`LEAK-01`](./leakage.md#leak-01).
- **The fix is uniformity** — same message, same status, same work regardless of whether the
  account exists — covered in the controls; the probe only has to show the difference.

→ Controls: [`LEAK-01`](./leakage.md#leak-01), [`AUTH-13`](./authentication.md#auth-13), [`LEAK-02`](./leakage.md#leak-02), [`AUTH-06`](./authentication.md#auth-06).

---

## 5 · Upload probing — unauthenticated writes and where the file lands (worked example)

**The setup.** From step 2 you have any write endpoint that answered without credentials —
classically `/api/upload`. Confirm it accepts a file, then follow the file to where it is served.

```bash
# a harmless marker file — never upload anything that could be mistaken for an attack payload
echo "authorized-selftest-$(date +%s)" > /tmp/marker.txt
curl -sS -A "$UA" -X POST -F "file=@/tmp/marker.txt" -w '\n%{http_code}\n' "$BASE/api/upload"
```

Two independent failures compound here, and the worked example had both:

1. **The endpoint took the file with no authentication** (`200`/`201`) → [`FILE-01`](./files.md#file-01). Anyone on the internet can write to your storage.
2. **The response handed back a public URL** — often a bucket address like
   `https://<bucket-name>.s3.<region>.amazonaws.com/<path>` — and fetching that URL with no
   credentials returned the file. That means the storage bucket is world-readable → [`DATA-03`](./data.md#data-03), [`FILE-04`](./files.md#file-04).
   ```bash
   # whatever URL the upload returned:
   curl -sS -A "$UA" -o /dev/null -w '%{http_code}\n' "https://<bucket-name>.s3.<region>.amazonaws.com/<returned-path>"
   # 200 ⇒ the bucket is public
   ```

- **Then check what types it accepts.** An endpoint that accepts `.html` or `.svg` and serves it
  from your own origin turns "upload" into "stored XSS", because an `.svg` is script the browser
  will run. Confirm the content-type and origin it is served under — this is a `FILE`+`WEB`
  finding, not just a storage one → [`FILE-02`](./files.md#file-02), [`FILE-04`](./files.md#file-04), [`WEB-06`](./web.md#web-06).
- **Stop at confirmation.** One marker file proves the door is open. Do not upload more, and
  delete the marker if you can.

→ Controls: [`FILE-01`](./files.md#file-01), [`FILE-02`](./files.md#file-02), [`FILE-04`](./files.md#file-04), [`DATA-03`](./data.md#data-03), [`AUTH-03`](./authentication.md#auth-03).

---

## 6 · Header and CSP inspection (worked example)

**The setup.** One request, read the response headers. Most browser-trust controls are visible
here without touching the app logic at all.

```bash
curl -sS -A "$UA" -D - -o /dev/null "$BASE/"
```

Read the returned headers against the checklist. The worked example's finding was a
Content-Security-Policy that looked present but was disabled in all but name:

```
content-security-policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'
```

- `default-src *` allows loading from **any** origin.
- `script-src * 'unsafe-inline' 'unsafe-eval'` allows script from any origin **and** inline
  `<script>` **and** `eval`. That is every script-injection path a CSP is supposed to close. A
  policy like this stops nothing; it is equivalent to having no CSP, while looking like diligence
  in a scan → [`WEB-01`](./web.md#web-01).
- **Also check for the header being absent, and check the rest of the set**:
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options` /
  `frame-ancestors`, `Referrer-Policy`, and cookie flags (`Secure`, `HttpOnly`, `SameSite`) on any
  `Set-Cookie`. Each maps to a `WEB` control.

→ Controls: [`WEB-01`](./web.md#web-01), [`WEB-02`](./web.md#web-02), [`WEB-03`](./web.md#web-03), [`WEB-04`](./web.md#web-04), [`WEB-05`](./web.md#web-05).

---

## 7 · Error and metadata leakage — what the app tells you when it fails

Make things go wrong on purpose and read what comes back.

- **Force an error.** Send a string where a number is expected, malformed JSON, a huge value, a
  missing required field. A stack trace, a SQL error, a framework debug page, or an internal
  hostname in the response is a leak → [`LEAK-03`](./leakage.md#leak-03).
  ```bash
  curl -sS -A "$UA" -X POST -H 'content-type: application/json' -d '{"id":"not-a-number' "$BASE/api/orders"
  ```
- **Read the headers for version tells.** `Server:`, `X-Powered-By:`, `X-AspNet-Version:` name
  the stack and version an attacker should match exploits to → [`LEAK-05`](./leakage.md#leak-05).
- **Check for verbose auth errors** already covered in step 4, and for IDs, tokens, or emails
  echoed in error bodies.

→ Controls: [`LEAK-03`](./leakage.md#leak-03), [`LEAK-05`](./leakage.md#leak-05).

---

## 8 · Rate limits, method tampering, and the checks that only exist on the happy path

- **Absence of rate limiting.** Send the same login or lookup request many times quickly (against
  staging only). If the Nth attempt behaves like the first, there is no lockout or throttle →
  [`AUTH-06`](./authentication.md#auth-06), [`API-05`](./api.md#api-05). 23andMe was credential
  stuffing against accounts with no such limit.
- **Method and verb tampering.** An endpoint that refuses `GET` may answer `POST`, `PUT`, or the
  override header `X-HTTP-Method-Override`. A `403` on the browser path may become `200` on
  `HEAD` or an unusual verb → [`API-06`](./api.md#api-06).
- **Old API versions.** If `/api/v2/users` enforces authorization, try `/api/v1/users` — the old
  version is often still routed and often weaker → [`API-07`](./api.md#api-07).
- **Redirect and SSRF parameters.** Any parameter that takes a URL (`?next=`, `?url=`,
  `?redirect=`, `?image=`, `?webhook=`) — point it at a domain you control and see if the app
  follows it (open redirect) or fetches it server-side (SSRF). For SSRF, the classic target is the
  cloud metadata address; confirm the app refuses it → [`INPUT-04`](./input.md#input-04),
  [`INPUT-08`](./input.md#input-08).

→ Controls: [`AUTH-06`](./authentication.md#auth-06), [`API-05`](./api.md#api-05), [`API-06`](./api.md#api-06), [`API-07`](./api.md#api-07), [`INPUT-04`](./input.md#input-04), [`INPUT-08`](./input.md#input-08).

---

## Probe → control map

| Probe | Finding | Controls |
| --- | --- | --- |
| Endpoint enumeration from JS bundle & common paths | Undocumented / forgotten endpoints | `API-07`, `CLOUD-09` |
| Unauthenticated GET returns data | Missing authentication | `AUTH-03`, `API-01` |
| Unauthenticated POST/upload accepted | Unauthenticated write | `FILE-01`, `AUTH-03` |
| Change id → read/modify another user's object | IDOR / BOLA / BFLA | `API-01`, `API-02` |
| id or role in body/header overrides session | Mass assignment / privilege via input | `API-03` |
| Login timing differs by account existence | Timing oracle / user enumeration | `AUTH-13`, `LEAK-02`, `LEAK-01` |
| Login/reset message or status differs | User enumeration | `LEAK-01`, `AUTH-06` |
| Uploaded file reachable at public URL | World-readable storage | `DATA-03`, `FILE-04` |
| Upload accepts HTML/SVG served same-origin | Stored XSS via upload | `FILE-02`, `WEB-06` |
| `default-src *` / `unsafe-inline` / `unsafe-eval` | CSP disabled in all but name | `WEB-01` |
| Missing HSTS / nosniff / frame protection | Weak browser-trust headers | `WEB-02`, `WEB-03`, `WEB-04` |
| Cookies without Secure/HttpOnly/SameSite | Session exposure | `WEB-05`, `AUTH-04` |
| Stack trace / SQL error / debug page | Verbose error leakage | `LEAK-03` |
| `Server` / `X-Powered-By` version banners | Stack fingerprinting | `LEAK-05` |
| No lockout after many attempts | Missing rate limiting | `AUTH-06`, `API-05` |
| Alternate verb / old version bypasses check | Method / version bypass | `API-06`, `API-07` |
| URL parameter is followed or fetched | Open redirect / SSRF | `INPUT-08`, `INPUT-04` |

---

*Every finding here points back to a control with a Fix and a Verify. The probe tells you the door
is open; the control tells you how to close it and how to prove it stayed closed.*

# INPUT · Input handling and injection

Untrusted input that reaches an interpreter — SQL, a shell, a template, a parser, a log sink, an
outbound HTTP client — and is treated as code rather than data. Cross-site scripting (input that
reaches the *browser* as code) lives in [`web.md`](./web.md); this file is server-side injection.

The IDs here (`INPUT-01`…`INPUT-09`) are cited throughout [`incidents/`](../incidents/) and keep
their meaning.

← [Back to the checklist](../checklist.md) · Related: [`WEB`](./web.md), [`API`](./api.md), [`FILE`](./files.md), [`CLOUD`](./cloud.md)

---

### INPUT-01
**P0 · code** — Parameterized queries everywhere. No concatenated SQL, including in internal tooling.

- **Why:** MOVEit, 2023 — SQL injection in a file-transfer app: 2,700+ organizations, 90M+ people, most of them customers of customers. Kaseya VSA, 2021 — SQLi plus auth bypass, ~1,500 downstream businesses.
- **Detect:** grep for query calls that concatenate or interpolate input: `execute("... " + x)`, `f"SELECT ... {x}"`, template literals with `${}` inside SQL, `.raw(`.
- **Fix:** parameterized queries / prepared statements / ORM bindings; never build SQL from strings, not even for an admin tool, not even "temporarily".
- **Verify:** search finds no string-built SQL; a test sends `' OR '1'='1` and quote/semicolon payloads and confirms they are treated as data.
- **Probe:** submit SQL metacharacters in inputs against staging and watch for errors or behaviour change ([playbook §7](./probe-playbook.md#7--error-and-metadata-leakage--what-the-app-tells-you-when-it-fails)).

### INPUT-02
**P0 · code** — Server-side schema validation on every input. Client validation is user experience, not a control.

- **Why:** the precondition for most of this file — an endpoint that accepts arbitrary shapes is an endpoint you cannot reason about. Client-side checks are trivially bypassed by calling the API directly.
- **Detect:** for each endpoint, is there an explicit server-side schema (types, ranges, lengths, allowed values)? Grep for handlers reading `request.body` fields without validation.
- **Fix:** validate against an explicit schema at the boundary (zod, pydantic, JSON Schema); reject unknown fields (also closes mass assignment, [`API-03`](./api.md#api-03)).
- **Verify:** send malformed, oversized, and extra-field inputs and confirm rejection with a generic error.
- **Probe:** [playbook §7](./probe-playbook.md#7--error-and-metadata-leakage--what-the-app-tells-you-when-it-fails).

### INPUT-03
**P1 · code** — Output encoding and a content security policy. No raw HTML from user data.

- **Why:** cross-site scripting; see [`WEB-06`](./web.md#web-06) for the full treatment and [`WEB-01`](./web.md#web-01) for the CSP that backstops it. British Airways, 2018 — injected script on the payment page, £20M fine.
- **Detect:** grep for `dangerouslySetInnerHTML`, `innerHTML =`, `v-html`, `document.write`, unescaped template output.
- **Fix:** context-aware output encoding; sanitize any unavoidable raw HTML; deploy a real CSP.
- **Verify:** XSS payloads through user-content paths render inert.
- **Probe:** [playbook §6](./probe-playbook.md#6--header-and-csp-inspection-worked-example).

### INPUT-04
**P1 · code** — Outbound requests to user-supplied URLs are allowlisted; link-local metadata addresses blocked; IMDSv2 enforced.

- **Why:** server-side request forgery. Capital One, 2019 — SSRF through a misconfigured WAF reached the EC2 metadata service, yielding IAM role credentials, then S3: 106M applicants.
- **Detect:** grep for outbound clients built from request input — `fetch(req...)`, `requests.get(user_url)`, image/webhook/import features that take a URL.
- **Fix:** allowlist destinations; resolve and block private, loopback, and link-local ranges (including `169.254.169.254`); enforce IMDSv2 ([`CLOUD-02`](./cloud.md#cloud-02)); do not follow redirects into blocked ranges.
- **Verify:** request `http://169.254.169.254/` and internal addresses through the feature and confirm refusal.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path) — point a URL parameter at a host you control.

### INPUT-05
**P1 · code** — Uploads type-checked, size-limited, stored off-host, served from a separate origin, never executed.

- **Why:** the full treatment is now [`FILE`](./files.md) — see [`FILE-01`](./files.md#file-01) (auth), [`FILE-02`](./files.md#file-02) (content type / SVG), [`FILE-04`](./files.md#file-04) (storage). Kept here because the corpus cites `INPUT-05`.
- **Detect:** see [`files.md`](./files.md).
- **Fix:** see [`files.md`](./files.md).
- **Verify:** see [`files.md`](./files.md).
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example).

### INPUT-06
**P1 · code** — No deserialization, template rendering, or evaluation of untrusted data.

- **Why:** Equifax, 2017 — Apache Struts CVE-2017-5638, patch available two months, 147M people. Hugging Face, 2024 — model files carrying pickle payloads that execute on load ([`INPUT`](./input.md) meets [`DEPS`](./dependencies.md)).
- **Detect:** grep for `pickle.loads`, `yaml.load` (unsafe), `eval`, `exec`, `new Function`, server-side template rendering of user strings, native deserialization of request data.
- **Fix:** safe deserializers (`yaml.safe_load`, JSON), never `eval`/`exec` on input, never render user data as a template; sandbox or refuse untrusted model artifacts.
- **Verify:** confirm no code path deserializes or evaluates untrusted input; test with a known-safe marker that a template payload is not executed.

### INPUT-07
**P1 · code** — Logging cannot be made to fetch or execute. Structured logging only.

- **Why:** Log4Shell, 2021 — a JNDI lookup triggered by a string that reached a log message, in a transitive dependency most organizations could not enumerate. CVSS 10.0.
- **Detect:** identify the logging framework and whether any lookup/interpolation feature is enabled; check that user input is logged as data, not format.
- **Fix:** structured logging with user input as fields; disable message lookups/expansions; patch the logger.
- **Verify:** a log line containing a lookup-style payload is recorded literally, with no fetch or expansion.

### INPUT-08
**P2 · code** — Redirects and webhook destinations allowlisted.

- **Why:** open redirect (phishing that borrows your domain's trust) and webhook SSRF. Related: [`INPUT-04`](#input-04).
- **Detect:** grep for redirects built from `?next=`/`?url=`/`?redirect=` and webhook targets taken from input.
- **Fix:** allowlist redirect targets and webhook destinations; use relative paths or a mapping table, not raw URLs.
- **Verify:** a redirect to an external domain via the parameter is refused.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### INPUT-09
**P1 · code** — Identifiers unguessable, and unguessability never the only control.

- **Why:** sequential IDs made First American trivial, but random IDs would only have slowed it down. The missing authorization check ([`AUTH-02`](./authentication.md#auth-02) / [`API-01`](./api.md#api-01)) is the finding; the sequence was the convenience. See also [`LEAK-04`](./leakage.md#leak-04).
- **Detect:** are client-facing IDs sequential integers? Is there an ownership check regardless?
- **Fix:** opaque random IDs (UUID/ULID) *and* the authorization check; never rely on unguessability alone.
- **Verify:** IDs are non-sequential and [`DATA-02`](./data.md#data-02)'s ownership test passes.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record).

# Vulnerability Classes

[`checklist.md`](./checklist.md) is organised by **what to do**. This file is organised by **what
goes wrong** — the named classes developers, scanners, bug bounty reports and security reviews
actually use. It exists because a control called "authorization checked server-side, per object,
on every request" is correct and unsearchable: nobody greps for that. They grep for `IDOR`.

Each class gives you a plain definition, what it looks like in code, **how it tends to appear in
AI-generated code specifically**, the controls that prevent it, the incidents in
[`incidents/`](./incidents/) that prove it matters, and how to test for it.

> Corpus counts below are live as of the last index build. Check any of them yourself:
> `grep -rl 'entry/idor' incidents/20*/ | wc -l`

---

## The map

| Class | Also called | Controls | In the corpus |
| --- | --- | --- | --- |
| [IDOR](#idor--broken-object-level-authorization) | BOLA, API1:2023 | `AUTH-02` `INPUT-09` `DATA-02` | 9 |
| [Broken function-level authorization](#broken-function-level-authorization) | BFLA, API5:2023 | `AUTH-02` `AUTH-07` | — |
| [Mass assignment](#mass-assignment) | BOPLA, API3:2023, over-posting | `INPUT-02` `AUTH-02` | — |
| [Missing authentication](#missing-authentication) | API2:2023, unauthenticated endpoint | `AUTH-03` `DATA-04` | 12 |
| [Missing row-level authorization](#missing-row-level-authorization) | RLS off, tenant bleed | `DATA-01` `DATA-02` `DATA-05` | 3 |
| [SQL injection](#sql-injection) | SQLi | `INPUT-01` | 13 |
| [NoSQL / command / LDAP injection](#nosql-command-and-ldap-injection) | — | `INPUT-01` `INPUT-02` | — |
| [Template injection](#template-injection) | SSTI | `INPUT-06` | — |
| [XML external entity](#xml-external-entity) | XXE | `INPUT-06` | — |
| [Unsafe deserialization](#unsafe-deserialization) | object injection, pickle | `INPUT-06` | 1 |
| [Log injection](#log-injection) | lookup injection, Log4Shell class | `INPUT-07` | 1 |
| [SSRF](#server-side-request-forgery) | — | `INPUT-04` `CLOUD-02` | 4 |
| [CSRF](#cross-site-request-forgery) | XSRF | `INPUT-08` `AUTH-04` | — |
| [Open redirect](#open-redirect) | — | `INPUT-08` | — |
| [XSS](#cross-site-scripting) | stored / reflected / DOM | `INPUT-03` | 1 |
| [Prototype pollution](#prototype-pollution) | — | `INPUT-02` `DEPS-07` | — |
| [Clickjacking](#clickjacking) | UI redress | `INPUT-03` | — |
| [Path traversal](#path-traversal) | directory traversal, zip slip | `INPUT-05` | 1 |
| [Unrestricted upload](#unrestricted-file-upload) | — | `INPUT-05` | — |
| [Unrestricted resource consumption](#unrestricted-resource-consumption) | API4:2023 | `AUTH-06` `DATA-11` | 2 |
| [Race conditions](#race-conditions) | TOCTOU | `INPUT-02` `HUMAN-08` | — |
| [Business-logic abuse](#business-logic-abuse) | — | `INPUT-02` `DATA-11` | 10 |
| [Enumeration and scraping](#enumeration-and-scraping) | API6:2023 | `AUTH-06` `DATA-10` `DATA-11` | 2 |
| [Secrets in the client](#secrets-in-the-client) | — | `CRED-02` `DATA-05` | 5 |
| [Secrets in the repository](#secrets-in-the-repository) | — | `CRED-01` `CRED-03` | many |
| [Session theft](#session-theft) | token replay, cookie theft | `AUTH-04` | 6 |
| [OAuth consent phishing](#oauth-consent-phishing) | illicit consent grant | `VENDOR-02` `VENDOR-03` | 3 |
| [Default credentials](#default-credentials) | — | `CRED-10` | 6 |
| [Subdomain takeover](#subdomain-takeover) | dangling DNS | `CLOUD-09` `CLOUD-01` | — |
| [Zombie APIs](#zombie-and-shadow-apis) | API9:2023, improper inventory | `CLOUD-09` `AUTH-08` | — |
| [Dependency confusion](#dependency-confusion) | namespace shadowing | `DEPS-05` | — |
| [Typosquatting and slopsquatting](#typosquatting-and-slopsquatting) | — | `DEPS-04` | 1 |
| [Malicious install scripts](#malicious-install-scripts) | postinstall abuse | `DEPS-02` | several |
| [Compromised update channel](#compromised-update-channel) | — | `CICD-03` `DEPS-06` | many |
| [Invisible code](#invisible-and-homoglyph-code) | Unicode smuggling | `AGENT-09` | 1 |
| [Direct prompt injection](#direct-prompt-injection) | LLM01, jailbreak | `AGENT-01` `AGENT-06` | 1 |
| [Indirect prompt injection](#indirect-prompt-injection) | LLM01 | `AGENT-01` `AGENT-03` | 7 |
| [Excessive agency](#excessive-agency) | LLM06 | `AGENT-02` `AGENT-06` | 10 |
| [Insecure output handling](#insecure-output-handling) | LLM02 | `AGENT-01` `INPUT-03` | — |
| [Model artifact execution](#model-artifact-execution) | LLM03/LLM05, pickle | `INPUT-06` `DEPS-09` | 2 |
| [Agent config as code](#agent-configuration-as-executable-code) | — | `AGENT-08` | several |
| [Inadvertent disclosure](#inadvertent-disclosure) | misdirected data | `HUMAN-10` `DATA-09` | 12 |
| [Offboarding failure](#offboarding-failure) | stale access | `HUMAN-03` `AUTH-08` `CRED-07` | 5 |
| [Insider misuse](#insider-misuse) | — | `HUMAN-09` `DATA-11` | 15 |
| [Help-desk social engineering](#help-desk-social-engineering) | vishing, account recovery abuse | `HUMAN-01` `AUTH-05` | many |

A dash in the last column means the corpus has no incident tagged for that class. That is a gap
in the evidence, not proof the class is rare — several of these are among the most-reported bug
bounty findings in the world, and simply do not produce the kind of public breach notification
this corpus is built from.

---

# A. Broken authorization

The largest single family, and the one AI-generated code gets wrong most reliably, because the
happy path works perfectly.

## IDOR — Broken Object Level Authorization

**Also called:** BOLA, OWASP API1:2023, horizontal privilege escalation, insecure direct object
reference.

**In one sentence.** The application takes an object identifier from the request and returns the
object without checking whether *this caller* is allowed to have *that object*.

**What it looks like.**

```
GET /api/orders/1042   →  200, order 1042
GET /api/orders/1043   →  200, someone else's order
```

The endpoint authenticated you. It never authorized you for this particular row.

**How it shows up in AI-generated code.** This is the single most common serious flaw in generated
applications, because a model writing a CRUD handler writes the query that satisfies the prompt:

```js
// generated, and wrong
const order = await db.order.findUnique({ where: { id: params.id } })
return Response.json(order)
```

It fetches the object by id. Nothing about the prompt "let users view their orders" forces the
`AND user_id = session.user.id` that makes it correct. The route works in testing because you test
it as the owner. It is a data breach in production because attackers do not test as the owner.

**Controls:** `AUTH-02` (authorization server-side, per object, every request), `INPUT-09`
(unguessable ids, never as the only control), `DATA-02` (a test proving A cannot read B).

**In the corpus:** 9 incidents. `grep -rl 'entry/idor' incidents/20*/`

- **First American Financial, 2019** — sequential document ids in the URL, no authorization check.
  885 million title and escrow documents going back to 2003, including social security numbers and
  bank statements, readable by editing a number. The largest IDOR on record.
- **Panera Bread, 2018** — a customer-lookup endpoint returned records by incrementing an id; a
  researcher reported it and was ignored for eight months.
- **Fiserv and GovPayNet, 2018** — two financial platforms, same flaw, found by a researcher
  weeks apart. GovPayNet exposed 14 million receipts including partial card data.
- **T-Mobile US, 2018** — an API returned customer data for any phone number supplied.

**How to test.** Authenticate as user A, request user B's object by id, assert 403. Make it a test
in CI, not a thing you once did by hand. Then do it for every endpoint that takes an identifier —
the one you skip is the one that ships.

---

## Broken function-level authorization

**Also called:** BFLA, OWASP API5:2023, vertical privilege escalation, forced browsing.

**In one sentence.** A regular user can call an endpoint meant for administrators, because the
only thing stopping them was that the UI did not show the button.

**What it looks like.** `POST /api/admin/users/42/promote` returns 200 for an ordinary session.
Or the same endpoint accepts `?role=admin`. Or `GET` is authorized and `DELETE` on the same path
is not.

**How it shows up in AI-generated code.** Generated admin panels commonly gate on the client —
`{user.isAdmin && <DeleteButton/>}` — and the model considers the requirement met, because the
prompt said "only admins can delete". Hiding a control is presentation, not authorization. Also
common: a middleware that checks the role on `/admin/*` pages but not on the `/api/*` routes those
pages call.

**Controls:** `AUTH-02`, `AUTH-07` (admin tooling behind separate auth and full audit).

**In the corpus:** no incident is tagged specifically for this. Related: **Twitter, 2020**, where
an internal account-management tool required no per-action approval once reached.

**How to test.** Take the full route list. For each route, call it with a low-privilege session and
with no session. Anything that is not a 401 or 403 is a finding. Include every HTTP method.

---

## Mass assignment

**Also called:** BOPLA (Broken Object Property Level Authorization), OWASP API3:2023,
over-posting, autobinding.

**In one sentence.** The endpoint copies whatever fields the request body contains straight onto
the object, so the caller can set fields they should never control — `isAdmin`, `balance`,
`orgId`, `emailVerified`.

**What it looks like.**

```js
// generated, and wrong
await db.user.update({ where: { id: session.userId }, data: req.body })
```

`PATCH /api/me` with `{"name":"x","role":"admin"}` promotes the caller.

**How it shows up in AI-generated code.** Spreading the request body is the shortest correct-looking
way to write an update handler, so models write it constantly. The inverse also appears: a `GET`
returning the whole row, including `password_hash`, `stripe_customer_id` and internal flags,
because `SELECT *` was easier than naming columns.

**Controls:** `INPUT-02` (server-side allowlist schema on every input), `AUTH-02`.

**In the corpus:** no incident is tagged specifically for this.

**How to test.** For every write endpoint, send a body containing a field the caller must not
control and confirm it is rejected or ignored. For every read endpoint, diff the response against
the list of fields that client is entitled to.

---

## Missing authentication

**Also called:** OWASP API2:2023 adjacent, unauthenticated endpoint, open API.

**In one sentence.** The endpoint returns user data to anyone who asks.

**How it shows up in AI-generated code.** A debug or internal route written during development and
never gated — `/api/users/all`, `/api/debug/config`, a health check that dumps environment. Also:
a serverless function deployed with its own URL, outside whatever middleware protects the rest.

**Controls:** `AUTH-03`, `DATA-04`, `CLOUD-01`.

**In the corpus:** 12 incidents. `grep -rl 'entry/unauth-api' incidents/20*/`

- **Optus, 2022** — one internet-facing API endpoint with no authentication: 9.8 million customers
  and 2.1 million identity document numbers.
- **Justdial, 2019** — an unauthenticated API nobody owned, exposing over 100 million records
  since 2015.
- **Indane, 2019** and **Ehteraz (Qatar), 2020** — national-scale government systems, same flaw.

**How to test.** Hit every route with no credentials. Then hit it with a valid session for an
unrelated account. Do this against the deployed build, not the dev server.

---

## Missing row-level authorization

**Also called:** RLS off, tenant bleed, broken multi-tenancy.

**In one sentence.** The client talks to the database directly, and the database has no policy, so
the "public" key is a full read-write credential.

**How it shows up in AI-generated code.** This is the defining failure of the AI app-builder stack.
A model asked for "a Supabase table for user profiles" writes the `CREATE TABLE` and stops. Row
level security is off until someone enables it, the anon key ships in the browser bundle, and the
application works flawlessly for every user including the one reading everyone else's rows.

**Controls:** `DATA-01`, `DATA-02`, `DATA-05`, `CRED-02`, `AGENT-11`.

**In the corpus:** 3 incidents, all recent.

- **Lovable, 2025 (CVE-2025-48757)** — the builder generated Supabase applications without RLS;
  170+ production applications confirmed exposed.
- **Moltbook, 2026** — anon key in the client bundle, RLS off: 1.5 million API tokens, 35,000
  email addresses, 4,060 private messages.
- A 2025 scan of 1,072 AI-built applications found 98% carrying at least one security flaw; this
  is the flaw that recurs.

**How to test.**

```sql
SELECT tablename FROM pg_tables WHERE schemaname='public'
  AND tablename NOT IN (SELECT tablename FROM pg_policies);
```

Empty result, then read every policy: `USING (true)` is not a policy. Then the negative test.

---

# B. Injection

One family, one cause: data and instruction sharing a channel, with the parser deciding which is
which.

## SQL injection

**In one sentence.** User input is concatenated into a query string, so the input can change what
the query does.

**How it shows up in AI-generated code.** Models write parameterized queries when asked to write
"a query". They write concatenation when asked for something that feels dynamic — a search filter,
an optional sort column, an admin report, a migration script. Watch for template literals inside
`db.query()`, `raw()`, `$queryRawUnsafe`, f-strings in `cursor.execute()`, and anywhere an ORM was
"escaped from" because the ORM could not express the query.

Dynamic identifiers are the trap: you cannot parameterize a column or table name, so `ORDER BY
${column}` looks unavoidable. It is not — allowlist the column names.

**Controls:** `INPUT-01`.

**In the corpus:** 13 incidents. `grep -rl 'entry/sqli' incidents/20*/`

- **MOVEit, 2023** — SQL injection in a managed file-transfer appliance. 2,700+ organisations,
  90 million+ people, most of them customers of customers.
- **Bulgarian National Revenue Agency, 2019** — a legacy VAT-refund endpoint, roughly 5 million
  citizens, most of the adult population.
- **Kaseya VSA, 2021** — SQL injection plus authentication bypass, then a fake hotfix pushed down
  the agent channel to ~1,500 downstream businesses.

**How to test.** Grep for concatenation into query calls, then run a scanner against the routes it
finds. `grep -rInE "(execute|query|raw)\s*\(\s*[\"'\`].*(\+|\$\{|%s|f[\"'])"`.

---

## NoSQL, command and LDAP injection

**In one sentence.** Same mechanism, different interpreter — a Mongo query object, a shell, an
LDAP filter.

**How it shows up in AI-generated code.** NoSQL injection is easy to miss because it does not look
like a string: passing `req.body` straight into a Mongo filter lets `{"password": {"$ne": null}}`
match every user. Command injection appears whenever generated code shells out for something a
library would do — `exec(\`convert ${file} out.png\`)`, `ffmpeg`, `git`, `curl`, `unzip`.

**Controls:** `INPUT-01`, `INPUT-02`.

**How to test.** Look for `exec`, `execSync`, `spawn` with a shell, `os.system`, `subprocess` with
`shell=True`. For Mongo, confirm every filter value is cast to the expected primitive type before
it reaches the driver.

---

## Template injection

**Also called:** SSTI (server-side template injection).

**In one sentence.** User input reaches a template *engine* rather than a template *variable*, so
the input is evaluated as template code, which in most engines means code execution.

**How it shows up in AI-generated code.** Email and document generation. A prompt like "let admins
customise the welcome email" produces a stored template rendered with the full engine, and now
anyone who can edit that template can run code. Also `render_template_string(user_input)` in Flask
and its equivalents.

**Controls:** `INPUT-06`.

**How to test.** Find every call that compiles a template from a runtime string rather than from a
file on disk. Each one is a finding until proven otherwise.

---

## XML external entity

**Also called:** XXE.

**In one sentence.** An XML parser configured to resolve external entities will fetch files and
URLs named in the document it parses.

**How it shows up in AI-generated code.** Anywhere XML is still used: SAML assertions, SOAP
integrations, RSS ingestion, SVG upload, `.docx` and `.xlsx` processing. Generated parser setup
usually omits the two lines that disable entity resolution, because the defaults were unsafe for
years and the training data reflects that.

**Controls:** `INPUT-06`, and `INPUT-04` because XXE is frequently an SSRF delivery mechanism.

**How to test.** For every XML parser in the codebase, confirm external entity and DTD processing
are explicitly disabled. Do not rely on the library default.

---

## Unsafe deserialization

**Also called:** object injection, pickle execution, insecure deserialization.

**In one sentence.** Turning attacker-controlled bytes back into objects runs code as a side
effect of the format itself.

**How it shows up in AI-generated code.** Session and cache layers that store objects rather than
JSON. Python `pickle` for anything crossing a trust boundary. And most sharply in machine
learning: loading a model file is deserialization, and a `.pkl` or unsafetensors checkpoint from a
public hub executes on load.

**Controls:** `INPUT-06`, `DEPS-09`.

**In the corpus:** 1 incident, plus the model-artifact cases below.

- **Equifax, 2017** — Apache Struts CVE-2017-5638, a deserialization-adjacent parser flaw with a
  patch available for two months. 147 million people.
- **Hugging Face, 2024** — roughly 100 published models carrying malicious pickle payloads that
  execute when the model loads.

**How to test.** Enumerate every place bytes become objects. For each, answer where the bytes came
from. If the answer involves a user, a queue, a cache or a download, it is a finding.

---

## Log injection

**Also called:** lookup injection, the Log4Shell class, format-string abuse.

**In one sentence.** The logging library interprets something inside the message it was asked to
record.

**How it shows up in AI-generated code.** Rarely introduced directly — this is inherited from
dependencies. What generated code does contribute is interpolating raw user input into a log
format string rather than passing it as a structured field, which is the precondition that makes
the class exploitable.

**Controls:** `INPUT-07`, `DEPS-07`.

**In the corpus:** 1 incident, and it is the largest of its kind.

- **Log4Shell, 2021 (CVE-2021-44228)** — a JNDI lookup triggered by a string that reached a log
  message, inside a transitive dependency most organisations could not enumerate. CVSS 10.0, still
  being exploited years later.

**How to test.** Structured logging only: `log.info("login failed", {user})`, never
`log.info(\`login failed for ${user}\`)`. Then keep the logging library patched, because you will
not spot the next one yourself.

---

# C. Request forgery

## Server-side request forgery

**Also called:** SSRF.

**In one sentence.** You give the server a URL, and the server fetches it — from inside your
network, with your network's trust.

**What it looks like.** A thumbnail generator, a webhook tester, a "import from URL" feature, a
PDF renderer, an OG-preview fetcher. Point it at `http://169.254.169.254/` and cloud credentials
come back.

**How it shows up in AI-generated code.** Any generated feature that takes a URL. The model writes
`fetch(req.body.url)` because that is what the feature needs, and the cloud metadata endpoint is
not something a prompt about image thumbnails ever mentions. Blocklists written by hand are
insufficient — `127.0.0.1`, `[::1]`, `0177.0.0.1`, `localtest.me`, DNS rebinding and redirect
chains all bypass them.

**Controls:** `INPUT-04` (allowlist destinations, block link-local), `CLOUD-02` (IMDSv2 so the
metadata service needs a session token).

**In the corpus:** 4 incidents.

- **Capital One, 2019** — SSRF through a misconfigured WAF reached the EC2 instance metadata
  service, yielding IAM role credentials, then S3: 106 million applicants. AWS shipped IMDSv2 in
  response.
- **ProxyLogon, 2021** — an SSRF chain in on-premises Exchange, exploited against 30,000+ US
  organisations before most had read the advisory. The Norwegian Parliament and the European
  Banking Authority are both in this corpus as named victims.

**How to test.** Request `http://169.254.169.254/latest/meta-data/` through the feature and confirm
it is refused. Then try a redirect to it, and a hostname that resolves to it.

---

## Cross-site request forgery

**Also called:** CSRF, XSRF.

**In one sentence.** Another site makes the victim's browser send an authenticated request to
yours, and the browser attaches the cookie automatically.

**How it shows up in AI-generated code.** Modern frameworks mostly handle this, which is exactly
why generated code that steps outside the framework loses it: a hand-rolled API route, a form
posting to a different origin, `SameSite=None` set to make a third-party embed work.

**Controls:** `INPUT-08`, `AUTH-04`.

**How to test.** For every state-changing endpoint, confirm it requires a token the other origin
cannot read, or a `SameSite` cookie policy that prevents the send. `GET` must never change state.

---

## Open redirect

**In one sentence.** Your domain will forward the visitor anywhere the URL says, which lends your
reputation to a phishing link.

**How it shows up in AI-generated code.** Login flows: `?next=`, `?redirect_to=`, `?returnUrl=`.
Generated auth handlers redirect to whatever was passed, because validating it was not part of the
prompt. Also an OAuth `redirect_uri` allowlist that permits a wildcard subdomain.

**Controls:** `INPUT-08`.

**How to test.** Pass an absolute external URL to every redirect parameter. Anything that follows
it is a finding, including protocol-relative `//evil.example`.

---

# D. Client-side

## Cross-site scripting

**Also called:** XSS — stored, reflected, DOM-based.

**In one sentence.** Attacker-controlled text is rendered as markup, so it runs as script in
another user's session.

**How it shows up in AI-generated code.** React and its peers escape by default, so generated XSS
concentrates in the escape hatches: `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, rendering
Markdown without sanitising the HTML it permits, and injecting a user-supplied value into an
inline `<script>` block or an `href` that can be `javascript:`.

**Controls:** `INPUT-03` (output encoding and a content security policy).

**In the corpus:** 1 incident tagged. The related client-side script-injection cases are larger:
**British Airways, 2018** (a modified script on the payment page, £20M fine), **Ticketmaster,
2018** (a supplier's chatbot script), **BadgerDAO, 2021** (a stolen Cloudflare API key used to
inject a front-end script, $119M).

**How to test.** `grep -rn "dangerouslySetInnerHTML\|innerHTML\s*=\|v-html"`. For each hit, trace
the value to its source. Then add a content security policy and watch what breaks — what breaks is
usually what would have been exploitable.

---

## Prototype pollution

**In one sentence.** A deep merge or property-set with an attacker-controlled key writes to
`__proto__`, changing the behaviour of every object in the process.

**How it shows up in AI-generated code.** Hand-written deep-merge and query-parsing helpers, and
older utility dependencies. Generated "merge user config over defaults" code is the archetype.

**Controls:** `INPUT-02`, `DEPS-07`.

**How to test.** Send `{"__proto__": {"isAdmin": true}}` into every JSON body and config-merge
path, then check whether an unrelated object gained the property.

---

## Clickjacking

**In one sentence.** Your page is framed inside someone else's and the victim clicks something
they cannot see.

**Controls:** `INPUT-03` (`frame-ancestors` in the content security policy).

**How to test.** Try to load your own sensitive pages in an iframe from another origin.

---

# E. Resource handling

## Path traversal

**Also called:** directory traversal, zip slip (the archive variant).

**In one sentence.** A filename from the request contains `../` and escapes the directory it was
meant to stay in.

**How it shows up in AI-generated code.** File download and export endpoints that join a
user-supplied name onto a base path. Archive extraction that trusts the paths inside the archive —
zip slip — which generated "unzip the upload" code does essentially every time.

**Controls:** `INPUT-05`.

**How to test.** Request `../../etc/passwd` and its encoded variants through every file parameter.
For archives, build one containing `../` entries and confirm extraction refuses it.

---

## Unrestricted file upload

**In one sentence.** The application stores what it is given, where it can be served, under a name
the uploader chose.

**How it shows up in AI-generated code.** Generated upload handlers validate the file extension
from the filename, which the client controls, and store into a directory the web server will
execute from. The combination is a web shell.

**Controls:** `INPUT-05`.

**How to test.** Upload a file whose extension and content type disagree with its content. Confirm
it is rejected, stored outside any executable path, renamed, and served from a different origin
with `Content-Disposition: attachment`.

---

## Unrestricted resource consumption

**Also called:** OWASP API4:2023.

**In one sentence.** One caller can make the endpoint do unbounded work — or unbounded spending.

**How it shows up in AI-generated code.** No pagination cap, so `?limit=1000000` is honoured. No
rate limit on an endpoint that sends SMS, email or an LLM request, each of which costs money per
call. GraphQL without depth or complexity limits. This class has become sharply more expensive
since generated applications routinely call a paid model API on an unauthenticated route.

**Controls:** `AUTH-06`, `DATA-11`.

**How to test.** Ask for a million rows. Call the expensive endpoint in a loop. Watch the bill.

---

# F. Business logic

## Race conditions

**Also called:** TOCTOU (time of check, time of use).

**In one sentence.** Two requests arrive between your check and your write, and both pass the
check.

**How it shows up in AI-generated code.** Check-then-act on money, stock, quotas, invite codes and
one-time tokens: `if (balance >= amount) { await debit() }`, `if (!used) { await redeem() }`.
Generated code almost never reaches for a transaction, a row lock, or a unique constraint, because
the sequential reading of the requirement is correct and the concurrent one is not.

**Controls:** `INPUT-02`, `HUMAN-08` (separation of duties on payments).

**How to test.** Fire the same request fifty times concurrently and count how many succeeded. The
answer should be one.

---

## Business-logic abuse

**In one sentence.** Every request is valid, every check passes, and the sequence still produces an
outcome you never intended.

**How it shows up in AI-generated code.** Price, quantity or currency taken from the client and
trusted. A discount that can be applied repeatedly. A multi-step flow whose steps can be skipped by
calling step three directly. Refund and cancellation paths that do not re-verify state.

**Controls:** `INPUT-02`, `DATA-11`, `HUMAN-08`.

**In the corpus:** 10 incidents.

- **Tesco Bank, 2016** — a design flaw in card handling let attackers guess valid numbers at
  scale; £2.26M debited from 9,000 accounts overnight, and a £16.4M regulatory fine.
- **Facebook "View As", 2018** — a bug chain in an ordinary feature minted access tokens for other
  users.
- **US Small Business Administration, 2020** — an emergency-loan portal showed applicants each
  other's data.

**How to test.** Write down what the feature must never allow, in business terms — "a user must
never receive more than they paid for" — then try to make each one happen. Automated scanners do
not find this class; a person asking "what if I do it out of order" does.

---

## Enumeration and scraping

**Also called:** OWASP API6:2023, unrestricted access to sensitive business flows.

**In one sentence.** The endpoint is working exactly as designed, one record at a time, several
million times.

**How it shows up in AI-generated code.** Any lookup by email, phone or username — signup,
password reset, "find friends", invite. Generated code returns a different response for "no such
user" than for "wrong password", which is an enumeration oracle, and rate limiting is rarely part
of the prompt.

**Controls:** `AUTH-06`, `DATA-10` (features that fan out one account's data), `DATA-11`.

**In the corpus:** 2 tagged, several more in substance.

- **Dell, 2024** — roughly 49 million records enumerated through a partner portal with weak rate
  limiting.
- **Facebook, 2021** — 533 million phone numbers harvested through contact import.
- **23andMe, 2023** — 14,000 credential-stuffed accounts became 6.9 million exposed profiles
  because an opt-in relatives feature fanned each one out.

**How to test.** Script your own lookup endpoint against a wordlist and see how far you get before
anything stops you. Then check whether an alert fired.

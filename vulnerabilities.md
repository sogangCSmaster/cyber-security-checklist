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

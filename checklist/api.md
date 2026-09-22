# API · Object authorization, mass assignment, and shape

[`auth.md`](./authentication.md) establishes *who is calling*. This file is about the question that
comes next and is missed far more often: *may this caller do this, to this specific object?* The
happy path — you fetching your own record — works perfectly whether or not the check exists, which
is exactly why the check is so often absent. This is the single most common serious flaw in
AI-generated backends.

← [Back to the checklist](../checklist.md) · Related: [`AUTH`](./authentication.md), [`DATA`](./data.md), [`LEAK`](./leakage.md), [`INPUT`](./input.md)

---

### API-01
**P0 · code** — Every request that names an object checks that the caller may access *that* object, server-side, from the session.

- **Why:** this is IDOR / BOLA (OWASP API1), the top API risk, and the API-layer view of [`AUTH-02`](./authentication.md#auth-02) (which the corpus cites for these cases). First American Financial, 2019 — document IDs in the URL with no ownership check, 885M documents back to 2003, readable by editing a number. McHire, 2025 — an IDOR plus a default credential, 64M applicant chats. Panera, Fiserv, and T-Mobile all lost data the same way.
- **Detect:** read every handler that takes an id (path, query, or body). Does it check the object belongs to — or is shared with — the session user, or does it just look the object up and return it? An endpoint that trusts the id is an IDOR.
- **Fix:** derive the user from the session, then scope the query by that user (`WHERE id = ? AND owner_id = ?`) or check ownership before acting. Never trust an id, a role, or an owner field from the request to decide access.
- **Verify:** authenticate as user A, request user B's object by id, assert `403`/`404`. Make it a test in CI, run for read, update, and delete. This is [`DATA-02`](./data.md#data-02) from the API side.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record).

### API-02
**P0 · code** — Authorization is enforced on every function and every verb, not just on reads and not just in the UI.

- **Why:** broken function-level authorization (OWASP API5) — an admin-only action reachable by an ordinary user who just calls it, because the check was "don't render the button" rather than "refuse the request". The write verbs are the dangerous ones: an endpoint may check ownership on `GET` but not on `PUT`/`DELETE`.
- **Detect:** list privileged actions (admin, bulk, destructive) and confirm each verifies role/permission server-side. Trace an object through all four verbs — is the ownership check on each?
- **Fix:** a server-side permission check on every handler, keyed to role and object; deny by default; do not rely on the client hiding anything.
- **Verify:** as a non-admin, call an admin endpoint directly and assert refusal; as user A, `PUT`/`DELETE` user B's object and assert refusal.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record) and [§8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### API-03
**P1 · code** — The server decides which fields a client may set. Role, owner, price, balance, and status are never taken from the request body.

- **Why:** mass assignment / BOPLA (OWASP API3) — a handler that binds the whole request body onto a model lets a client send `"role":"admin"` or `"balance":100000` and have it stick. AI scaffolds love `Model(**request.json)` and `Object.assign(user, req.body)`.
- **Detect:** grep for whole-body binding — `**request`, `Object.assign`, `...req.body`, `Model.update(req.body)`, `attributes = params.permit!`. Check whether sensitive fields are reachable that way.
- **Fix:** bind only an explicit allowlist of client-settable fields; set privileged fields server-side from policy, never from input.
- **Verify:** send an extra privileged field (`role`, `owner_id`, `price`) in a create/update body and confirm it is ignored.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record) — try the id/role in the body and headers.

### API-04
**P1 · code** — Responses contain only the fields the caller is entitled to. No returning the whole object and hiding fields in the client.

- **Why:** excessive data exposure — an endpoint returns the full user record (password hash, email, internal flags) and the UI shows a subset; the data is all there in the network tab. The inverse of mass assignment.
- **Detect:** read what handlers serialize. Is it the raw DB row, or an explicit view/DTO? Grep for returning models directly.
- **Fix:** serialize through an explicit response schema that lists exactly the fields to expose; never return raw rows.
- **Verify:** inspect a representative response and confirm it carries no field the caller should not see.
- **Probe:** read the raw JSON responses during the authenticated walkthrough — sensitive fields present but UI-hidden is the finding.

### API-05
**P1 · code** — Every API has rate limits and quotas; enumerable and expensive endpoints have stricter ones.

- **Why:** unrestricted resource consumption (OWASP API4) and the enabler of mass scraping — Salesloft Drift (2025) bulk-exported CRM data from 700+ organizations through endpoints working exactly as designed; every scraping incident in the corpus ran through an unthrottled endpoint. Also the direct DoS/cost vector.
- **Detect:** check for per-user and per-IP limits on login, search, lookup-by-identifier, export, and any endpoint doing real work (payments, mail, model calls).
- **Fix:** rate limits with backoff, quotas per account, and tighter limits on enumerable/expensive routes; treat any endpoint returning many records as a bulk export ([`DATA-11`](./data.md#data-11)).
- **Verify:** a test confirms the limit trips and returns `429`.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path) — staging only.

### API-06
**P1 · code** — Authorization is consistent across methods. No bypass via an alternate verb, `HEAD`, `X-HTTP-Method-Override`, or a different content type.

- **Why:** frameworks route `GET`, `POST`, `HEAD`, and override headers differently; a check bolted onto one path is missing on another. A `403` on the browser verb can become `200` on an unusual one.
- **Detect:** for a protected endpoint, try each verb and the override header; check the routing for per-verb handlers that don't share the check.
- **Fix:** enforce authorization in shared middleware that runs regardless of verb; disable method-override unless needed.
- **Verify:** call a protected route with `POST`, `PUT`, `HEAD`, and `X-HTTP-Method-Override` and confirm consistent refusal.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### API-07
**P1 · config** — No shadow or zombie APIs. Old versions, debug routes, and undocumented endpoints are inventoried and turned off.

- **Why:** zombie APIs (an old `/v1` still routed and weaker than `/v2`) and shadow APIs (endpoints no one documented) are unmonitored and unpatched. They are what enumeration in [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all) is looking for.
- **Detect:** enumerate routes from the code *and* from the deployed surface (the JS bundle, common paths) and diff — anything live but undocumented is a finding. Check for `/v1` when `/v2` exists.
- **Fix:** decommission old versions and debug endpoints at the server; keep an endpoint inventory that CI can diff against.
- **Verify:** confirm decommissioned routes return `404`/`410`, not a weaker `200`.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all) and [§8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path).

### API-08
**P2 · code** — GraphQL and batch endpoints have depth, complexity, and rate limits, and enforce authorization in resolvers.

- **Why:** a single GraphQL query can be nested to exhaust the server, or can batch thousands of object lookups that each need — and may skip — an authorization check. Introspection left on maps the whole schema.
- **Detect:** check for query depth/complexity limits, per-resolver authorization, and whether introspection is enabled in production.
- **Fix:** depth and cost limits, authorization in each resolver (not just at the query root), disable introspection in production, and rate-limit.
- **Verify:** send a deeply nested and a batched query and confirm limits apply; confirm a resolver denies an object the caller cannot access.

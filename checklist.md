# The Breach-Driven Security Checklist

Every control here exists because of a documented breach. Nothing is in this list because it
sounded prudent; the evidence for each item is in [`incidents/`](./incidents/), which records how
organizations were actually broken into between 2016 and 2026.

This is the **entry point**. The controls themselves live in [`checklist/`](./checklist/), one
file per domain, so that an AI applying this list — or a person hardening one part of a system —
can load exactly the domain that matters and nothing else. The order across domains, and within
each file, is by how often the corresponding failure appears in the corpus, not alphabetically.

## How to use this

| You are | Start at |
| --- | --- |
| About to ship in the next hour | [The fifteen-minute triage](#the-fifteen-minute-triage) |
| Building something new | [`skills/secure-by-default`](./skills/secure-by-default/SKILL.md), then the domain file for what you are touching |
| Auditing source you can read | Work the domains below in order; do the **P0** items everywhere first, then **P1** |
| Testing an app you already run | [`checklist/probe-playbook.md`](./checklist/probe-playbook.md) — black-box checks against a live URL you are authorized to test |
| Not using Claude Code | [`prompts/`](./prompts/) — the same content as copy-paste text |

Each control has a stable ID (`AUTH-02`), a priority, a layer, the incident that proves it
matters, and — the point of this rewrite — a way to both **find** the flaw and **prove** it is
gone. Incident records point at these IDs, skills cite them, and you can reference one in a pull
request.

[`vulnerabilities.md`](./vulnerabilities.md) is the same ground indexed the other way — by the
named class (IDOR, BOLA, SSRF, mass assignment, prompt injection) rather than by the control.
[`incidents/CONTROL-INDEX.md`](./incidents/CONTROL-INDEX.md) lists, for every control, every
incident in the corpus it would have broken. It is generated, so it cannot drift from the
evidence.

### How to read a control

Every item in the domain files has the same shape, so an agent can act on it without prose
parsing:

- **`ID` · `Pn` · `layer`** — the one-line control.
  - **Why:** the incident(s) that prove the failure is real, with numbers.
  - **Detect:** how to *find* the flaw — usually a `grep`, a file to read, or a config to inspect. This is the white-box, source-review path.
  - **Fix:** the concrete remediation. Where it is short, the corrected code.
  - **Verify:** how to *prove the fix holds* — the assertion or test that fails before and passes after. A control you cannot verify is a hope.
  - **Probe:** *(where meaningful)* how to confirm the flaw from the outside, against a running deployment, with no source access — the black-box path. See [`checklist/probe-playbook.md`](./checklist/probe-playbook.md) for the mechanics and the rules of engagement.

Not every control has a Probe: a committed secret or a missing lockfile is invisible from the
outside. Not every control has a code-level Detect: a help-desk that resets anything for anyone is
found by calling it, not by grep. The fields present are the ones that apply.

### Priorities

| | Meaning |
| --- | --- |
| **P0** | Do not put this in front of users without it. Each P0 maps to a breach that happened exactly this way |
| **P1** | Fix before you have real users or real data. These are what turn an incident into a catastrophe |
| **P2** | The difference between surviving an incident and being defined by it |

### Layers

The layer tells you *where* the fix lives, which tells you *who* can make it and *when*.

| | Where it lives | Fixed by |
| --- | --- | --- |
| **code** | Application source | Changing and re-deploying code |
| **config** | Framework, headers, IaC, dashboard settings | A setting, often without a code change |
| **infra** | Network, cloud, DNS, hosts | Platform / ops |
| **process** | People, review, response | A decision and a habit, not a diff |

### Does this domain apply to me?

Skip nothing on a guess, but do not chase controls for a surface you do not have. Match your
project to its domains:

| If your project… | The domains that earn their keep |
| --- | --- |
| Stores or returns user data | CRED, AUTH, DATA, API, LEAK, OBSV |
| Has a browser front end | WEB, INPUT, LEAK |
| Accepts uploads | FILE, INPUT, DATA |
| Stores passwords, national IDs, card numbers, health, or biometric data | DATA (06, 07, 13, 14), CRYPTO, OBSV |
| Has money, quotas, credits, or multi-step workflows | LOGIC, API, OBSV |
| Calls other services, or is called by them | API, INPUT (SSRF), VENDOR, CRYPTO |
| Runs on a cloud account | CLOUD, CRED, CICD, DNS |
| Ships or deploys through a pipeline | CICD, DEPS |
| Wires up an AI agent, tool, or MCP server | AGENT, CRED, DATA |
| Has a mobile app | MOBILE, CRED, API |
| Has humans with production access, a help desk, or contractors | HUMAN, AUTH, CRED |
| Has a public domain / sends email | DNS, WEB |

---

## The fifteen-minute triage

If you do nothing else, do these. They cover the failure modes behind the large majority of
incidents in the corpus, and every one is checkable in about a minute. Each links to the control
with the full Detect / Fix / Verify / Probe.

- [ ] **No secret in the repository, git history, or the built client bundle.** Build the bundle and grep it — reading the source is a different check. → [`CRED-01`](./checklist/secrets.md#cred-01), [`CRED-02`](./checklist/secrets.md#cred-02)
- [ ] **Row-level authorization is on, default-deny, on every table a client can reach.** `USING (true)` is not a policy. → [`DATA-01`](./checklist/data.md#data-01)
- [ ] **A test proves user A cannot read user B's data.** Assert the failure, not the success. → [`DATA-02`](./checklist/data.md#data-02)
- [ ] **No storage bucket, database, or index is reachable from the internet** — including ones left over from an earlier version. → [`DATA-03`](./checklist/data.md#data-03), [`DATA-04`](./checklist/data.md#data-04)
- [ ] **Every endpoint that returns user data checks who is asking and that they own this specific record.** → [`API-01`](./checklist/api.md#api-01)
- [ ] **No endpoint returns or accepts user data without authentication** — including write endpoints like upload. → [`AUTH-03`](./checklist/authentication.md#auth-03), [`FILE-01`](./checklist/files.md#file-01)
- [ ] **MFA on every account that can reach production**, including contractors and the account nobody uses any more. → [`AUTH-01`](./checklist/authentication.md#auth-01)
- [ ] **`service_role` and admin keys are server-side only** — not in client code, not in an agent's context. → [`DATA-05`](./checklist/data.md#data-05), [`AGENT-02`](./checklist/agents.md#agent-02)
- [ ] **Parameterized queries everywhere.** → [`INPUT-01`](./checklist/input.md#input-01)
- [ ] **Passwords are hashed (argon2id, scrypt, or bcrypt), never encrypted; national-ID, card, and health fields are encrypted by the application with keys the database cannot read; nothing sensitive is logged.** The database's own "encryption at rest" is not this. → [`DATA-06`](./checklist/data.md#data-06), [`DATA-07`](./checklist/data.md#data-07), [`OBSV-04`](./checklist/observability.md#obsv-04)
- [ ] **Lockfile committed, install scripts off in CI.** → [`DEPS-01`](./checklist/dependencies.md#deps-01), [`DEPS-02`](./checklist/dependencies.md#deps-02)
- [ ] **Login, signup, and password reset reveal nothing** — same message, same status, same timing whether the account exists or not — **and there is no `admin` to find**: no predictable privileged account, and privileged users never sign in through the public form. → [`LEAK-01`](./checklist/leakage.md#leak-01), [`AUTH-13`](./checklist/authentication.md#auth-13), [`AUTH-14`](./checklist/authentication.md#auth-14)
- [ ] **A real Content-Security-Policy** — not `default-src *` with `unsafe-inline`, which is the same as none. → [`WEB-01`](./checklist/web.md#web-01)
- [ ] **Nothing an agent reads is treated as an instruction**, and no agent both reads untrusted content and has an outbound channel while holding data access. → [`AGENT-01`](./checklist/agents.md#agent-01), [`AGENT-03`](./checklist/agents.md#agent-03)
- [ ] **An alert fires if one account suddenly reads everything.** → [`OBSV-02`](./checklist/observability.md#obsv-02)

---

## The domains

Nineteen domains. The first block is where the corpus is heaviest; work top to bottom.

| Domain | File | What it covers |
| --- | --- | --- |
| **CRED** | [`secrets.md`](./checklist/secrets.md) | Secrets, credentials, keys, rotation, scoping |
| **AUTH** | [`authentication.md`](./checklist/authentication.md) | Who you are: login, MFA, sessions, recovery, admin |
| **DATA** | [`data.md`](./checklist/data.md) | The data layer: tenant isolation, storage, encryption, retention |
| **API** | [`api.md`](./checklist/api.md) | Per-object authorization, BOLA/BFLA, mass assignment, shadow APIs, rate limits |
| **INPUT** | [`input.md`](./checklist/input.md) | Injection: SQL, command, SSRF, deserialization, log injection |
| **WEB** | [`web.md`](./checklist/web.md) | Browser trust: CSP, security headers, cookies, CSRF, clickjacking, XSS defense |
| **FILE** | [`files.md`](./checklist/files.md) | Uploads, path traversal, how files are stored and served |
| **LOGIC** | [`logic.md`](./checklist/logic.md) | Business logic: workflow bypass, race conditions, price and quota abuse |
| **LEAK** | [`leakage.md`](./checklist/leakage.md) | What you give away for free: enumeration, timing oracles, verbose errors, metadata |
| **CRYPTO** | [`crypto.md`](./checklist/crypto.md) | Hashing, tokens, randomness, transport, and what not to invent |
| **DEPS** | [`dependencies.md`](./checklist/dependencies.md) | Dependencies and the software supply chain |
| **AGENT** | [`agents.md`](./checklist/agents.md) | AI agents, MCP, tools, and prompt injection |
| **CLOUD** | [`cloud.md`](./checklist/cloud.md) | Cloud and infrastructure configuration |
| **DNS** | [`dns.md`](./checklist/dns.md) | Domains, subdomains, certificates, and email authentication |
| **CICD** | [`cicd.md`](./checklist/cicd.md) | Pipeline, build, deploy, and developer machines |
| **VENDOR** | [`vendors.md`](./checklist/vendors.md) | Third parties, integrations, and granted access |
| **MOBILE** | [`mobile.md`](./checklist/mobile.md) | Mobile app specifics |
| **HUMAN** | [`people.md`](./checklist/people.md) | People and process |
| **OBSV** | [`observability.md`](./checklist/observability.md) | Logging, detection, response, disclosure |

**Testing a running app:** [`checklist/probe-playbook.md`](./checklist/probe-playbook.md) gathers
every **Probe** into one ordered black-box pass — the checks an external tester (or an AI you
point at your own deployment) runs with no source access: unauthenticated endpoint sweep, timing
comparison, header inspection, object-reference walking, upload attempts. It leads with the rules
of engagement, because these are tests you run against systems **you own or are authorized to
test**, and nothing else.

---

## What this list will not do for you

It will not make you secure. It will remove the specific failures that have repeatedly turned
small mistakes into large ones, which is a different and more achievable thing.

Three honest limits:

1. **It is derived from disclosed breaches.** Undisclosed and undetected incidents are, by
   definition, missing. The corpus is skewed toward whatever gets reported.
2. **It is a floor, not a ceiling.** Regulated data, payments, healthcare, and safety-critical
   systems carry obligations this list does not touch.
3. **Controls decay.** Equifax had traffic inspection. It had been broken for ten months. A
   checklist is a snapshot of intent; only the Verify and Probe steps tell you whether the intent
   is still true today.

---

*Evidence: [`incidents/`](./incidents/) · Frequencies: [`incidents/STATS.md`](./incidents/STATS.md)
· By vulnerability class: [`vulnerabilities.md`](./vulnerabilities.md) · Apply it:
[`skills/`](./skills/) · Paste it: [`prompts/`](./prompts/)*

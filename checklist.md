# The Breach-Driven Security Checklist

Every control here exists because of a documented breach. Nothing is in this list because it
sounded prudent; the evidence for each item is in [`incidents/`](./incidents/), which records how
organizations were actually broken into between 2016 and 2026.

The order is not alphabetical and it is not by how satisfying the control is to implement. It is
by how often the corresponding failure appears in the corpus.

## How to use this

| You are | Start at |
| --- | --- |
| About to ship something in the next hour | [The fifteen-minute triage](#the-fifteen-minute-triage) |
| Building something new | [`skills/secure-by-default`](./skills/secure-by-default/SKILL.md), then this list as you go |
| Auditing something already built | Work the P0 items in order, then P1 |
| Not using Claude Code | [`prompts/`](./prompts/) — the same content as copy-paste text |

Each control has an ID (`CRED-01`), a priority, the incident that proves it matters, and a way to
verify it. The ID is stable: incident records point at it, skills cite it, and you can reference
it in a pull request.

[`vulnerabilities.md`](./vulnerabilities.md) is the same ground indexed the other way — by the
named class (IDOR, BOLA, SSRF, mass assignment, prompt injection) rather than by the control — and
says how each one tends to appear in AI-generated code.

[`incidents/CONTROL-INDEX.md`](./incidents/CONTROL-INDEX.md) lists, for every control, every
incident in the corpus it would have broken. It is generated, so it cannot drift from the
evidence — and the three controls with no incidents behind them are marked as such below rather
than quietly left to look supported.

### Priorities

| | Meaning |
| --- | --- |
| **P0** | Do not put this in front of users without it. Each P0 maps to a breach that happened exactly this way |
| **P1** | Fix before you have real users or real data. These are what turn an incident into a catastrophe |
| **P2** | The difference between surviving an incident and being defined by it |

---

## The fifteen-minute triage

If you do nothing else, do these twelve. They cover the failure modes behind the large majority of
incidents in the corpus, and every one of them is checkable in about a minute.

- [ ] **No secret in the repository, the git history, or the built client bundle.** Build the
      bundle and grep it — reading the source is a different check. → `CRED-01`, `CRED-02`
- [ ] **Row-level security is on, with a default-deny policy, on every table a client can reach.**
      `USING (true)` is not a policy. → `DATA-01`
- [ ] **A test proves user A cannot read user B's data.** Assert the failure, not the success. → `DATA-02`
- [ ] **No storage bucket, database, or search index is reachable from the internet** — including
      ones left over from an earlier version of the project. → `DATA-03`, `DATA-04`
- [ ] **Every endpoint that returns user data checks the session for who is asking, and checks
      that they own this specific record.** → `AUTH-02`
- [ ] **No endpoint returns user data without authentication.** → `AUTH-03`
- [ ] **MFA on every account that can reach production**, including contractors and the account
      nobody uses any more. → `AUTH-01`
- [ ] **`service_role` and admin keys are server-side only** — not in client code, not in an agent's
      context. → `DATA-05`, `AGENT-02`
- [ ] **Parameterized queries everywhere.** → `INPUT-01`
- [ ] **Lockfile committed, install scripts off in CI.** → `DEPS-01`, `DEPS-02`
- [ ] **Nothing an agent reads is treated as an instruction**, and no agent both reads untrusted
      content and has an outbound channel while holding data access. → `AGENT-01`, `AGENT-03`
- [ ] **An alert fires if one account suddenly reads everything.** → `OBSV-02`

---

## CRED · Secrets and credentials

The single largest category in the corpus. Roughly a third of recorded incidents begin with a
credential somewhere it should not have been.

- [ ] **CRED-01** · **P0** — No secret in source, configuration, client bundle, or git history.
  - *Why:* Uber, 2016 — an AWS key in a **private** repository, 57M records, $148M settlement and a
    criminal conviction for the CSO. Toyota, 2022 — a key in a **public** repository for five
    years, 296k records. Internet Archive, 2024 — a GitLab config file with a token, reachable
    since 2022, 31M records.
  - *Verify:* `gitleaks detect --no-git` and `gitleaks detect` over full history. Without it:
    `git log --all -p -S'BEGIN PRIVATE KEY'` and grep for `AKIA`, `sk-`, `ghp_`, `xox`, `eyJ`.
- [ ] **CRED-02** · **P0** — Anything the client can read is public. Secrets are server-side only.
  - *Why:* Moltbook, 2026 — Supabase anon key in the client bundle with RLS off: 1.5M API tokens,
    4,060 private messages. Every `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*` value
    ships to the browser.
  - *Verify:* build, then `grep -rE "(sk-|service_role|AKIA|-----BEGIN)" dist/ .next/ build/`.
- [ ] **CRED-03** · **P0** — Rotate on exposure, including anything an AI tool, a vendor, or a
      support ticket has seen.
  - *Why:* Okta, 2023 — service-account credentials saved into a personal Google profile, then
    session tokens inside support HAR files. s1ngularity, 2025 — AI CLIs were driven to collect
    local secrets. Vendor tallies of what was taken differ; Wiz counted over a thousand valid
    GitHub tokens plus cloud and npm credentials.
  - *Verify:* a rotation was performed and the old credential now fails. Removing the commit is
    not rotation.
- [ ] **CRED-04** · **P1** — Secrets injected at runtime from a manager or the environment, never
      baked into images or repositories.
  - *Verify:* `docker history --no-trunc <image> | grep -iE "key|secret|token"` returns nothing.
- [ ] **CRED-05** · **P1** — Secret file patterns ignored before the first commit.
  - *Why:* the window between "created `.env`" and "added it to `.gitignore`" is where it gets
    committed. A `.env` added to `.gitignore` after it was tracked stays in history.
  - *Verify:* `git ls-files | grep -E '^\.env|\.pem$|\.key$'` is empty.
- [ ] **CRED-06** · **P1** — Credentials scoped to one job, one resource, one permission.
  - *Why:* Microsoft AI research, 2023 — one Azure SAS token scoped to an entire storage account,
    with write permission, expiring in 2051: 38 TB including workstation backups. Capital One,
    2019 — an IAM role that could list every bucket.
  - *Verify:* no IAM policy attached to an application role contains `"Resource": "*"` or
    `"Action": "*"`.
- [ ] **CRED-07** · **P1** — Credentials expire. No indefinite lifetimes.
  - *Why:* Klue, 2026 — a credential issued in 2022 for a pilot, never used and never revoked,
    reached ~200 customer companies four years later.
  - *Verify:* list every long-lived token in the account and give each one an expiry or an owner.
- [ ] **CRED-08** · **P1** — Per-environment secrets; development cannot reach production.
  - *Evidence:* **none in this corpus.** Several records show a non-production *environment* with a
    path into production (`CLOUD-06`), but none turns specifically on a shared secret. Kept as a
    preventive control, marked so you can weigh it accordingly.
  - *Why:* Optus, 2022 — a test network with a path to production, 9.8M customers.
- [ ] **CRED-09** · **P2** — A rotation and revocation runbook with a named owner and a stated
      maximum time-to-revoke.
  - *Verify:* someone can answer "how long to kill every credential?" with a number, not a shrug.
- [ ] **CRED-10** · **P1** — No default or shared credential in anything you ship or deploy. A
      unique one is forced at first use.
  - *Why:* Mirai, 2016 — default factory credentials on IoT cameras and DVRs assembled a botnet
    that took a DNS provider offline across much of the US. VPNFilter, 2018 — the same class, on
    consumer routers.
  - *Verify:* no credential in firmware, images, or seed data, and first boot refuses to proceed
    until one is set.

---

## AUTH · Identity, authentication, authorization

- [ ] **AUTH-01** · **P0** — Phishing-resistant MFA on every human account with production reach,
      including contractors, legacy accounts, and test tenants.
  - *Why:* Change Healthcare, 2024 — a Citrix portal with no MFA, nine days of undetected lateral
    movement, ~190M people, $3B+ cost. Colonial Pipeline, 2021 — one legacy VPN account, no MFA,
    password present in a credential dump.
  - *Verify:* enumerate every account with production access and confirm MFA on each. The gap is
    always the account nobody remembered.
- [ ] **AUTH-02** · **P0** — Authorization checked server-side, per object, on every request.
  - *Why:* First American Financial, 2019 — sequential document IDs in the URL with no
    authorization check: 885M documents going back to 2003, readable by editing a number.
  - *Verify:* authenticate as user A, request user B's record by id, confirm a 403. Automate it.
- [ ] **AUTH-03** · **P0** — No unauthenticated endpoint returns user data.
  - *Why:* Optus, 2022 — one internet-facing API endpoint with no authentication, 9.8M customers,
    2.1M identity document numbers.
  - *Verify:* hit every route with no credentials and confirm nothing sensitive comes back.
- [ ] **AUTH-04** · **P1** — Sessions are short-lived, revocable, and rotated on privilege change.
  - *Why:* CircleCI, 2022 — malware stole a valid, 2FA-backed SSO session cookie. A session is a
    bearer token; MFA already happened.
- [ ] **AUTH-05** · **P1** — Account recovery and help-desk paths are as strong as the login path.
  - *Why:* MGM Resorts, 2023 — ten minutes of LinkedIn research, one call to the help desk, an
    Okta password and MFA reset, ~$100M. Instructure, 2026 — voice phishing posing as IT support,
    30M+ students and staff. Meta, 2026 — their own AI chatbot used to reset passwords.
  - *Verify:* call your own help desk and try to reset an account you do not own.
- [ ] **AUTH-06** · **P1** — Rate limiting, lockout, and breached-password checks on all auth
      surfaces.
  - *Why:* 23andMe, 2023 — credential stuffing against ~14k accounts with reused passwords.
- [ ] **AUTH-07** · **P1** — Admin and impersonation tooling behind separate authentication and
      full audit.
  - *Why:* Twitter, 2020 — vishing employees reached an internal account-management tool with no
    per-action approval: 130 high-profile accounts.
- [ ] **AUTH-08** · **P1** — Access is inventoried, owned, and expires when unused.
- [ ] **AUTH-09** · **P1** — MFA cannot be satisfied by a tap. Number matching or hardware keys.
  - *Why:* Uber, 2022 — MFA push-bombing a contractor until they approved.
- [ ] **AUTH-10** · **P1** — Legacy and alternative login paths are disabled, not merely
      deprecated.
- [ ] **AUTH-11** · **P1** — Every state-changing interface authenticates its caller, including
      the ones that are not HTTP.
  - *Why:* St. Jude implantable cardiac devices, 2016 — a radio command interface accepted
    state-changing commands from an unauthenticated party nearby. The same gap appears in message
    queues, serial and Bluetooth interfaces, and internal services assumed to be "behind the
    firewall".
  - *Verify:* enumerate every interface that can change state, not just the HTTP routes.
  - *Why:* Nintendo, 2020 — credential stuffing against the legacy NNID login. Microsoft, 2024 —
    password spraying a legacy non-production test tenant with no MFA, which held an OAuth app
    with corporate reach.

---

## DATA · Data layer, tenant isolation, storage

- [ ] **DATA-01** · **P0** — Row-level authorization enabled and default-deny on every
      client-reachable table.
  - *Why:* Lovable, 2025 (CVE-2025-48757) — generated Supabase apps without RLS, 170+ production
    applications exposed. Moltbook, 2026 — the same failure, 1.5M tokens.
  - *Verify:* `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN
    (SELECT tablename FROM pg_policies);` returns nothing. Then read each policy: `USING (true)`
    fails this control.
- [ ] **DATA-02** · **P0** — A negative test proves user A cannot read, update, or delete user B's
      data.
  - *Verify:* it is a test in CI, not a thing you did once by hand.
- [ ] **DATA-03** · **P0** — Object storage private by default; legacy buckets audited.
  - *Why:* Tea, 2025 — a legacy Firebase bucket left publicly readable: 13,000 government IDs and
    selfies, 1.1M private messages. A hotel check-in system, 2026 — 1M passports and licences.
  - *Verify:* enumerate every bucket including ones from earlier versions of the project, and
    check public-access settings on each.
- [ ] **DATA-04** · **P0** — Databases and search indexes not reachable from the public internet.
  - *Why:* Exactis, 2018 — an ElasticSearch instance on a public IP: 340M records. Ecuador, 2019 —
    an unsecured Elasticsearch server: effectively the entire population.
- [ ] **DATA-05** · **P0** — Admin or service-role database keys never reach a client or an agent
      context.
  - *Why:* 2025 research — a Cursor agent connected with a Supabase `service_role` key dumped the
    integration-tokens table into a support ticket after reading instructions embedded in it.
- [ ] **DATA-06** · **P1** — Passwords hashed with argon2id, bcrypt, or scrypt.
  - *Why:* Yahoo used MD5. Zynga used SHA-1 for some accounts and legacy MD5 for others.
- [ ] **DATA-07** · **P1** — Sensitive fields encrypted at rest; identity documents deleted after
      they have served their purpose.
  - *Why:* Marriott, 2018 — 5.25M unencrypted passport numbers. Tea, 2025 — verification selfies
    and IDs retained long after verification.
- [ ] **DATA-08** · **P1** — Backups exist, are restore-tested, and are not writable by production
      credentials.
  - *Why:* NotPetya, 2017 — Maersk rebuilt Active Directory from one surviving domain controller
    in Ghana, found by accident.
- [ ] **DATA-09** · **P2** — Data minimization and enforced retention limits.
  - *Why:* First American's exposure reached back to 2003. You cannot lose what you deleted.
- [ ] **DATA-10** · **P1** — Features that fan out one account's data to others are rate-limited
      and opt-in.
  - *Why:* 23andMe, 2023 — the "DNA Relatives" feature turned 14,000 compromised logins into 6.9M
    exposed profiles. Facebook, 2021 — contact import, 533M phone numbers.
- [ ] **DATA-11** · **P1** — Bulk export is a privileged, logged, alerting action.
- [ ] **DATA-12** · **P1** — What a single compromise can reach is capped, in value and in volume.
  - *Why:* Youbit, 2017 and Coinrail, 2018 — hot wallets held the full balance, so one compromise
    took everything, and Youbit filed for bankruptcy the same day. The general form: put a ceiling
    on what any internet-connected system holds at one time and sweep the rest out of reach.
  - *Verify:* for any store of value or bulk data, a documented ceiling exists on what one
    compromise reaches.
  - *Why:* Salesloft Drift, 2025 — stolen OAuth tokens used for bulk CRM export across 700+
    organizations. Every mass-scraping incident in the corpus ran through an endpoint working
    exactly as designed.

---

## INPUT · Input handling and injection

- [ ] **INPUT-01** · **P0** — Parameterized queries everywhere. No concatenated SQL, including in
      internal tooling.
  - *Why:* MOVEit, 2023 — SQL injection in a file-transfer app: 2,700+ organizations, 90M+ people,
    most of them customers of customers. Kaseya VSA, 2021 — SQLi plus auth bypass, ~1,500
    downstream businesses.
- [ ] **INPUT-02** · **P0** — Server-side schema validation on every input. Client validation is
      user experience, not a control.
- [ ] **INPUT-03** · **P1** — Output encoding and a content security policy. No raw HTML from user
      data.
- [ ] **INPUT-04** · **P1** — Outbound requests to user-supplied URLs are allowlisted; link-local
      metadata addresses blocked; IMDSv2 enforced.
  - *Why:* Capital One, 2019 — SSRF through a misconfigured WAF reached the EC2 metadata service,
    yielding IAM role credentials, then S3: 106M applicants.
  - *Verify:* request `http://169.254.169.254/` through the feature and confirm it is refused.
- [ ] **INPUT-05** · **P1** — Uploads type-checked, size-limited, stored off-host, served from a
      separate origin, never executed.
  - *Evidence:* **none in this corpus.** Web shells appear in several records, but they arrive
    through remote code execution rather than through an upload handler. Preventive.
- [ ] **INPUT-06** · **P1** — No deserialization, template rendering, or evaluation of untrusted
      data.
  - *Why:* Equifax, 2017 — Apache Struts CVE-2017-5638, patch available for two months: 147M
    people. Hugging Face, 2024 — model files carrying pickle payloads that execute on load.
- [ ] **INPUT-07** · **P1** — Logging cannot be made to fetch or execute. Structured logging only.
  - *Why:* Log4Shell, 2021 — a JNDI lookup triggered by a string that reached a log message, in a
    transitive dependency most organizations could not enumerate. CVSS 10.0.
- [ ] **INPUT-08** · **P2** — Redirects and webhook destinations allowlisted.
- [ ] **INPUT-09** · **P1** — Identifiers unguessable, and unguessability never the only control.
  - *Why:* sequential IDs made First American trivial, but random IDs would only have slowed it
    down. The missing authorization check is the finding; the sequence was the convenience.

---

## DEPS · Dependencies and supply chain

Roughly a fifth of the corpus. The category that has grown fastest since 2020.

- [ ] **DEPS-01** · **P0** — Lockfile committed; installs frozen and reproducible.
  - *Verify:* CI uses `npm ci`, `--frozen-lockfile`, or `uv sync --frozen`, never a bare install.
- [ ] **DEPS-02** · **P0** — Install scripts disabled by default on developer machines and in CI.
  - *Why:* s1ngularity, 2025 — the entire payload was a `postinstall` script, which then invoked
    the developer's own AI CLI to hunt for secrets. The stolen tokens were then used to flip over
    5,500 private repositories to public across more than 400 users and organizations.
  - *Verify:* `npm config get ignore-scripts` is `true`, or CI passes `--ignore-scripts`.
- [ ] **DEPS-03** · **P0** — A cooldown before adopting a newly published version.
  - *Why:* the `chalk`/`debug` compromise of September 2025 was live for hours across packages
    with ~2B weekly downloads. A version published this morning has had no review.
- [ ] **DEPS-04** · **P1** — Every suggested package is verified to exist and to be the intended
      one.
  - *Why:* `ua-parser-js` and `torchtriton` were name-based attacks. Models now invent package
    names confidently, and attackers register them — slopsquatting.
- [ ] **DEPS-05** · **P1** — Internal package names reserved on public registries.
  - *Evidence:* **none in this corpus.** The canonical case, the `torchtriton` dependency-confusion
    package on PyPI, was not captured by the quarter that would have held it. The mechanism is well
    documented elsewhere; this list simply does not carry the proof.
- [ ] **DEPS-06** · **P1** — No script or stylesheet loaded from a URL you do not control.
  - *Why:* Polyfill.io, 2024 — the domain was sold and began serving malware to 100,000+ sites
    that had pinned a hostname rather than a version. British Airways, 2018 — a modified script on
    the payment page, £20M fine.
- [ ] **DEPS-07** · **P1** — Dependency scanning in CI that fails the build on known-exploited
      vulnerabilities, with a patch SLA for critical severity.
- [ ] **DEPS-08** · **P2** — New transitive dependencies surfaced and reviewed in pull requests.
  - *Why:* `event-stream`, 2018 — the payload was in `flatmap-stream`, a transitive dependency
    added by a new maintainer who had simply asked for the package.
- [ ] **DEPS-09** · **P2** — Maintainer health is a selection criterion.
  - *Why:* XZ Utils, 2024 — a two-year social engineering campaign against one burned-out
    maintainer nearly produced a global SSH backdoor. It was caught by a 0.5-second latency
    anomaly, not by any control.
- [ ] **DEPS-10** · **P2** — A named, rehearsed response for "a package we depend on was
      compromised".
  - *Why:* Shai-Hulud, 2025-2026 — the first self-replicating npm worm. The question is not
    whether this happens again but how fast you can answer it.

---

## AGENT · AI agents, MCP, and prompt injection

The newest domain and the one with the least accumulated practice. Every control here traces to an
incident from 2025 or later.

- [ ] **AGENT-01** · **P0** — Everything an agent reads is untrusted data, never instruction.
  - *Why:* EchoLeak, 2025 (CVE-2025-32711, CVSS 9.3) — a zero-click prompt injection; an email
    with hidden instructions was enough. A malicious GitHub issue was enough to make an agent with
    a GitHub MCP server read private repositories and publish their contents.
  - *Verify:* there is no path where retrieved content is concatenated into a prompt and treated
    with the same authority as the user's own instruction.
- [ ] **AGENT-02** · **P0** — Agent credentials scoped to the task. Never admin or service-role.
- [ ] **AGENT-03** · **P0** — Private data, untrusted content, and an external channel never
      combine unsupervised.
  - *Why:* any two of the three are manageable. All three is exfiltration waiting for a trigger —
    the mechanism behind every agent incident in the corpus.
- [ ] **AGENT-04** · **P1** — MCP servers and IDE extensions pinned, reviewed, and version-diffed.
  - *Why:* `postmark-mcp`, 2025 — fifteen clean versions, then one line that BCC'd every email to
    the author's domain. GlassWorm, 2025 — invisible Unicode hiding code in marketplace extensions.
- [ ] **AGENT-05** · **P1** — No MCP server or agent endpoint exposed without authentication.
  - *Why:* researchers found hundreds of MCP servers open on the public internet with no auth.
- [ ] **AGENT-06** · **P1** — Human approval before an agent writes to production, moves money, or
      changes access.
- [ ] **AGENT-07** · **P1** — Agent actions logged with their originating prompt, and reversible.
- [ ] **AGENT-08** · **P1** — Repository-level agent configuration reviewed as executable code.
  - *Why:* February 2026 — remote code execution through repository configuration files, and 1,184
    malicious skills poisoning an agent marketplace, within two weeks. Cloning a repository and
    opening it in an agentic IDE is an install step.
- [ ] **AGENT-09** · **P2** — Generated code scanned for invisible and homoglyph characters.
  - *Verify:* `grep -rlP "[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}]" .`
- [ ] **AGENT-10** · **P2** — Production secrets and customer data never placed in a prompt.
- [ ] **AGENT-11** · **P1** — AI-generated security defaults verified, never assumed.
  - *Why:* a 2025 scan of 1,072 AI-built applications found 98% carrying at least one security
    flaw. The generated code works. That is what makes the failure invisible.

---

## CLOUD · Cloud and infrastructure configuration

Misconfiguration is the most common root cause among the largest breaches ever recorded.

- [ ] **CLOUD-01** · **P0** — Nothing publicly reachable unless it was decided to be. Enumerate
      regularly.
- [ ] **CLOUD-02** · **P0** — Instance metadata requires a session token (IMDSv2).
  - *Why:* Capital One, 2019. AWS shipped IMDSv2 in direct response.
- [ ] **CLOUD-03** · **P1** — Least-privilege IAM. No wildcard actions or resources for application
      roles.
- [ ] **CLOUD-04** · **P1** — Signed URLs per-object, read-only, and short-lived.
- [ ] **CLOUD-05** · **P1** — Network segmentation between tiers and between environments.
  - *Why:* Equifax, 2017 — credentials found in plaintext on a file share opened 48 unrelated
    databases because the network was flat.
- [ ] **CLOUD-06** · **P1** — Non-production carries production-grade authentication or has no
      production reach.
- [ ] **CLOUD-07** · **P2** — Infrastructure declared as code; drift detected.
- [ ] **CLOUD-08** · **P1** — Admin interfaces not on the public internet.
- [ ] **CLOUD-09** · **P2** — An asset inventory exists; unowned and forgotten assets are found and
      removed.
- [ ] **CLOUD-10** · **P1** — A patch SLA for internet-facing and laterally-reachable systems, an
      inventory of what cannot be patched, and a staged rollout.
  - *Why:* WannaCry and NotPetya both ran on MS17-010, patched two months earlier. Equifax's
    Struts patch had been available for two months. And the counterweight, from the same corpus:
    Intel's first Meltdown and Spectre microcode caused enough reboot instability that it had to
    be pulled and reissued — a patch SLA without a staged rollout trades one outage for another.
  - *Verify:* a number exists for "critical patch applied within N days", and someone can name
    what is not patchable and why.
  - *Why:* T-Mobile, 2021 — an unprotected internet-facing router nobody owned.

---

## CICD · Pipeline, build, deploy, and developer machines

- [ ] **CICD-01** · **P0** — CI secrets per-job and unavailable to untrusted pull-request builds.
  - *Why:* Codecov, 2021 — a modified uploader script sent every environment variable in the
    customer's CI job to the attacker. HashiCorp had to rotate its GPG release-signing key.
- [ ] **CICD-02** · **P0** — Branch protection and required review on anything that reaches users.
  - *Why:* Amazon Q Developer extension, 2025 — an attacker with no special privileges opened a
    pull request from an ordinary GitHub account, it was merged, and a released version shipped
    with a prompt instructing the agent to wipe the user's filesystem and AWS resources. AWS
    reported the payload failed on a syntax error, so nothing was confirmed destroyed: the review
    gate is what should have caught it, and did not.
- [ ] **CICD-03** · **P1** — Build provenance and artifact signing. Verify what ships is what was
      built.
  - *Why:* SolarWinds, 2020 — malicious code injected during compilation, then signed and shipped
    to 18,000 customers. CCleaner, 2017. 3CX, 2023. A signature proves who built it, not what it
    does.
- [ ] **CICD-04** · **P1** — Actions and pipeline steps pinned to a commit, with minimal token
      permissions. No `pull_request_target` with untrusted checkout.
- [ ] **CICD-05** · **P1** — Deploy credentials per-repository, least-privilege, and expiring.
- [ ] **CICD-06** · **P2** — A rehearsed rollback path.
- [ ] **CICD-07** · **P1** — Developer machines managed: encrypted, patched, no personal browser
      credential sync into work accounts.
  - *Why:* LastPass, 2022 — a DevOps engineer's **home** computer, via an unpatched third-party
    media server, yielded the decryption keys for customer vault backups. Cisco, 2022 — an
    employee's personal Google account with browser password sync.
- [ ] **CICD-08** · **P1** — The build system is treated as production and monitored as such.
- [ ] **CICD-09** · **P2** — Release approval requires a second human.

---

## VENDOR · Third parties and integrations

- [ ] **VENDOR-01** · **P0** — An inventory of every third party holding your data or a token to
      your systems.
  - *Why:* Salesloft Drift, 2025 — attackers sat in Drift's GitHub for three months, took the
    OAuth tokens Drift held for its customers, and bulk-exported CRM data from 700+ organizations,
    then searched the exports for more credentials.
- [ ] **VENDOR-02** · **P0** — Granted OAuth tokens scoped, expiring, and reviewed. Unused ones
      revoked.
- [ ] **VENDOR-03** · **P1** — Authorizing a new connected application requires review.
  - *Why:* the 2025 Salesforce campaign stole no passwords. Victims were talked into clicking
    "Allow" on a malicious connected app. An OAuth consent screen is a credential.
- [ ] **VENDOR-04** · **P1** — Support artifacts sanitized before being shared.
  - *Why:* Okta, 2023 — HAR files in support cases contained live session tokens.
- [ ] **VENDOR-05** · **P1** — Third-party scripts on sensitive pages minimized, pinned, or
      isolated.
- [ ] **VENDOR-06** · **P2** — Contractual notification windows; you monitor vendor advisories.
- [ ] **VENDOR-07** · **P2** — Acquired and inherited systems audited before being connected.
  - *Why:* Marriott, 2018 — intruders were in Starwood's network from 2014 and were acquired along
    with the company. 383M guest records, four years undetected.
- [ ] **VENDOR-08** · **P2** — Vendor access time-boxed and separately monitored.
- [ ] **VENDOR-09** · **P2** — What a bundled third-party component actually does at runtime is
      verified, not assumed.
  - *Why:* BLU Products, 2016 — pre-installed update-agent firmware copied users' text messages,
    call logs, contacts, and location to servers abroad every 72 hours, by the vendor's own
    account without their knowledge. `postmark-mcp`, 2025 — fifteen clean versions, then one line
    that BCC'd every email. What it claims to do and what it sends are different questions.
  - *Verify:* for any component with network access, observe what it actually transmits.

---

## HUMAN · People and process

Social engineering is the entry vector in roughly a tenth of the corpus, and it is the fastest
growing. No technical control in this document survives contact with a help desk that will reset
anything for anyone who sounds stressed.

- [ ] **HUMAN-01** · **P0** — Identity verification for any credential or MFA reset, independent of
      what the caller claims.
  - *Why:* MGM, 2023; Instructure, 2026; Charter and Carnival, 2026. All voice. The cheapest
    attack in the corpus and among the most effective.
  - *Verify:* try it against your own help desk. Do not warn them.
- [ ] **HUMAN-02** · **P1** — High-impact actions require a second person.
- [ ] **HUMAN-03** · **P1** — Joiners, movers, and leavers are a tracked process with a maximum
      revocation time.
  - *Why:* Klue, 2026 — a credential nobody had used in four years.
- [ ] **HUMAN-04** · **P1** — Contractors and subprocessors get the same controls as employees.
  - *Why:* Okta/Sitel, 2022; Medibank, 2022; Uber, 2022. All contractor accounts.
- [ ] **HUMAN-05** · **P1** — Training reflects current technique, including voice and AI-assisted
      impersonation.
- [ ] **HUMAN-06** · **P1** — Reporting a mistake is safe and fast. No blame for self-reported
      errors.
  - *Why:* the gap between "I think I clicked something" and someone acting on it is where dwell
    time comes from. A culture that punishes the report buys silence, not safety.
- [ ] **HUMAN-07** · **P2** — Sensitive operations have a checklist, not just a competent operator.
- [ ] **HUMAN-08** · **P2** — Separation of duties on payments, access grants, and releases.
  - *Why:* Bangladesh Bank, 2016 — $81M moved with valid SWIFT operator credentials, with the
    confirmation printer tampered with to delay discovery.
- [ ] **HUMAN-09** · **P2** — Insider risk monitored by behaviour, not by trust.
  - *Why:* Coinbase, 2025 — bribed overseas support contractors, $180-400M estimated cost.
    Desjardins, 2019 — one employee, two years, 9.7M members.
- [ ] **HUMAN-10** · **P1** — Recipients and destinations confirmed before data leaves the
      organization.
  - *Why:* the most common breach in most regulators' statistics is not an attack. It is
    an email to the wrong address.

---

## OBSV · Logging, detection, response, disclosure

- [ ] **OBSV-01** · **P0** — Authentication, authorization failures, admin actions, and exports
      centrally logged.
- [ ] **OBSV-02** · **P0** — Alerts on abnormal read or export volume per account.
  - *Why:* dwell time in the corpus is routinely measured in weeks. Change Healthcare had nine
    days of lateral movement. Marriott had four years.
- [ ] **OBSV-03** · **P1** — Detection is itself monitored. A broken sensor is an incident.
  - *Why:* Equifax, 2017 — an expired TLS certificate left the traffic-inspection appliance blind
    for ten months. The control existed. It had been dead since the previous year.
- [ ] **OBSV-04** · **P1** — Logs contain no secrets, tokens, or full identifiers.
- [ ] **OBSV-05** · **P1** — A written incident plan naming the decider, the communicator, and the
      disclosure clock.
  - *Why:* Uber, 2016 — the concealment produced the criminal conviction, not the breach. Okta,
    2022 — the disclosure delay did more damage than the access.
- [ ] **OBSV-06** · **P1** — A published way for an outsider to report a vulnerability.
  - *Verify:* `/.well-known/security.txt` exists and the address in it is read by someone.
- [ ] **OBSV-07** · **P2** — The "our credentials are already public" scenario is rehearsed.
- [ ] **OBSV-08** · **P2** — Log retention exceeds realistic dwell time.
  - *Why:* you cannot answer "how far did they get" with 30 days of logs and a four-year intrusion.
- [ ] **OBSV-09** · **P2** — Post-incident review produces a control change, not just a report.

---

## What this list will not do for you

It will not make you secure. It will remove the specific failures that have repeatedly turned
small mistakes into large ones, which is a different and more achievable thing.

Three honest limits:

1. **It is derived from disclosed breaches.** Undisclosed and undetected incidents are, by
   definition, missing. The corpus is skewed toward whatever gets reported — consumer data,
   regulated industries, and English-language coverage.
2. **It is a floor, not a ceiling.** Regulated data, payments, healthcare, and safety-critical
   systems carry obligations this list does not touch.
3. **Controls decay.** Equifax had traffic inspection. It had been broken for ten months. A
   checklist is a snapshot of intent; only `OBSV-03` tells you whether the intent is still true.

---

*Evidence: [`incidents/`](./incidents/) · Frequencies: [`incidents/STATS.md`](./incidents/STATS.md)
· Apply it: [`skills/`](./skills/) · Paste it: [`prompts/`](./prompts/)*

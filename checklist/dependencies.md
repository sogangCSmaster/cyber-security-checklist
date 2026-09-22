# DEPS · Dependencies and supply chain

Roughly a fifth of the corpus, and the category that has grown fastest since 2020. You are running
far more code you did not write than code you did, and most of it installs and runs scripts on
your machine with your privileges.

← [Back to the checklist](../checklist.md) · Related: [`CICD`](./cicd.md), [`AGENT`](./agents.md), [`WEB`](./web.md), [`VENDOR`](./vendors.md)

---

### DEPS-01
**P0 · config** — Lockfile committed; installs frozen and reproducible.

- **Why:** without a lockfile, "the same install" resolves to different code over time — including a version published between your last build and this one.
- **Detect:** a lockfile is committed; CI uses `npm ci`, `--frozen-lockfile`, `uv sync --frozen`, never a bare install.
- **Fix:** commit the lockfile; switch CI to the frozen install command.
- **Verify:** CI fails if the lockfile and manifest disagree.

### DEPS-02
**P0 · config** — Install scripts disabled by default on developer machines and in CI.

- **Why:** s1ngularity, 2025 — the entire payload was a `postinstall` script, which then invoked the developer's own AI CLI to hunt for secrets; the stolen tokens flipped 5,500+ private repositories to public across 400+ users and orgs.
- **Detect:** `npm config get ignore-scripts` is `true`, or CI passes `--ignore-scripts`.
- **Fix:** disable install scripts globally; allow them only for the specific reviewed package that needs one.
- **Verify:** a package with a `postinstall` does not execute it on install.

### DEPS-03
**P0 · process** — A cooldown before adopting a newly published version.

- **Why:** the `chalk`/`debug` compromise of September 2025 was live for hours across packages with ~2B weekly downloads. A version published this morning has had no review.
- **Detect:** check whether the resolver pulls latest immediately or respects a minimum age.
- **Fix:** pin versions; adopt a cooldown (e.g. only versions older than N days) for non-security updates.
- **Verify:** a freshly published version is not auto-adopted before the cooldown.

### DEPS-04
**P1 · process** — Every suggested package is verified to exist and to be the intended one.

- **Why:** `ua-parser-js` and `torchtriton` were name-based attacks. Models invent package names confidently and attackers register them — slopsquatting.
- **Detect:** review new dependencies for near-miss names (hyphen vs dot, singular vs plural, scope swaps).
- **Fix:** confirm the package's identity, publisher, and repository before adding it.
- **Verify:** each new dependency maps to the intended upstream project.

### DEPS-05
**P1 · config** — Internal package names reserved on public registries.

- **Evidence:** none in this corpus; the canonical case (`torchtriton` dependency confusion) fell outside the captured quarter. Preventive.
- **Detect:** are your internal scope/names registered (or scoped) publicly so they cannot be squatted?
- **Fix:** reserve internal names/scopes on public registries; pin the internal registry.
- **Verify:** an attacker cannot publish a public package that your resolver would prefer.

### DEPS-06
**P1 · config** — No script or stylesheet loaded from a URL you do not control.

- **Why:** Polyfill.io, 2024 — the domain was sold and served malware to 100,000+ sites that had pinned a hostname rather than a version. British Airways, 2018 — a modified script on the payment page, £20M fine.
- **Detect:** grep HTML/JSX for `<script src="https://…">` and `<link href="https://…">` pointing off-origin.
- **Fix:** self-host, or pin with subresource integrity (SRI) and a version; back it with [`WEB-01`](./web.md#web-01).
- **Verify:** third-party scripts are self-hosted or carry an SRI hash that fails if the file changes.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all) lists the off-origin scripts a page loads.

### DEPS-07
**P1 · config** — Dependency scanning in CI that fails the build on known-exploited vulnerabilities, with a patch SLA for critical severity.

- **Detect:** is there an `npm audit`/`pip-audit`/`osv-scanner`/Dependabot gate, and does it fail the build?
- **Fix:** add the scan to CI as a blocking step for known-exploited/critical; set a patch SLA.
- **Verify:** a known-vulnerable dependency fails CI.

### DEPS-08
**P2 · process** — New transitive dependencies surfaced and reviewed in pull requests.

- **Why:** `event-stream`, 2018 — the payload was in `flatmap-stream`, a transitive dependency added by a new maintainer who had simply asked for the package.
- **Detect:** does the PR show lockfile diffs and new transitive packages?
- **Fix:** surface dependency additions in review; question new maintainers and new transitives.
- **Verify:** a new transitive dependency appears in the PR diff for a human to see.

### DEPS-09
**P2 · process** — Maintainer health is a selection criterion.

- **Why:** XZ Utils, 2024 — a two-year social-engineering campaign against one burned-out maintainer nearly produced a global SSH backdoor, caught by a 0.5-second latency anomaly, not by any control.
- **Detect:** for critical dependencies, how many maintainers, how active, how funded?
- **Fix:** prefer well-maintained projects; contribute or vendor critical single-maintainer ones.
- **Verify:** critical dependencies are not single points of unmaintained failure.

### DEPS-10
**P2 · process** — A named, rehearsed response for "a package we depend on was compromised".

- **Why:** Shai-Hulud, 2025-2026 — the first self-replicating npm worm. The question is not whether this happens again but how fast you can answer it.
- **Detect:** is there a runbook and an owner for a compromised dependency?
- **Fix:** write it: how to identify affected builds, pin/rollback, rotate exposed secrets, and communicate.
- **Verify:** a tabletop exercise runs end to end.

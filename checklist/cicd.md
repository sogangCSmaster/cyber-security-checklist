# CICD · Pipeline, build, deploy, and developer machines

The build system is production: it holds credentials to everything and ships code to your users.
A compromise here is a compromise of every downstream customer at once.

← [Back to the checklist](../checklist.md) · Related: [`DEPS`](./dependencies.md), [`CRED`](./secrets.md), [`CLOUD`](./cloud.md), [`VENDOR`](./vendors.md)

---

### CICD-01
**P0 · config** — CI secrets per-job and unavailable to untrusted pull-request builds.

- **Why:** Codecov, 2021 — a modified uploader script sent every environment variable in the customer's CI job to the attacker; HashiCorp had to rotate its GPG release-signing key.
- **Detect:** can a fork PR's build read repository secrets? Are secrets scoped per job?
- **Fix:** withhold secrets from untrusted PR builds; scope secrets to the jobs that need them.
- **Verify:** a PR from a fork cannot access production secrets.

### CICD-02
**P0 · process** — Branch protection and required review on anything that reaches users.

- **Why:** Amazon Q Developer extension, 2025 — an attacker with an ordinary account opened a PR, it was merged, and a released version shipped with a destructive prompt. AWS reported the payload failed on a syntax error, so nothing was confirmed destroyed — the review gate is what should have caught it and did not.
- **Detect:** is review required on the branches that deploy? Can anyone push straight to them?
- **Fix:** protect release branches; require review from someone other than the author.
- **Verify:** an unreviewed change cannot reach a release branch.

### CICD-03
**P1 · config** — Build provenance and artifact signing. Verify what ships is what was built.

- **Why:** SolarWinds, 2020 — malicious code injected during compilation, then signed and shipped to 18,000 customers. CCleaner, 2017. 3CX, 2023. A signature proves who built it, not what it does — provenance closes the gap.
- **Detect:** are artifacts signed, and is provenance (SLSA-style) recorded and checked on deploy?
- **Fix:** sign artifacts; generate and verify provenance; deploy only verified artifacts.
- **Verify:** an unsigned or unattested artifact is refused at deploy.

### CICD-04
**P1 · config** — Actions and pipeline steps pinned to a commit, with minimal token permissions. No `pull_request_target` with untrusted checkout.

- **Detect:** are third-party actions pinned to a SHA? Is the workflow token read-only by default? Any `pull_request_target` checking out PR code?
- **Fix:** pin to commit SHAs; set least-privilege `permissions:`; avoid `pull_request_target` with untrusted checkout.
- **Verify:** actions are SHA-pinned and the default token is minimal.

### CICD-05
**P1 · config** — Deploy credentials per-repository, least-privilege, and expiring.

- **Detect:** does one deploy credential work across many repos/environments? Does it expire?
- **Fix:** scope deploy credentials per repo/environment; prefer short-lived OIDC federation.
- **Verify:** a deploy credential cannot deploy outside its scope.

### CICD-06
**P2 · process** — A rehearsed rollback path.

- **Detect:** can you roll back a bad release quickly, and has it been practiced?
- **Fix:** a documented, tested rollback; keep the previous known-good artifact.
- **Verify:** a rollback drill succeeds within its target time.

### CICD-07
**P1 · process** — Developer machines managed: encrypted, patched, no personal browser credential sync into work accounts.

- **Why:** LastPass, 2022 — a DevOps engineer's *home* computer, via an unpatched third-party media server, yielded the decryption keys for customer vault backups. Cisco, 2022 — an employee's personal Google account with browser password sync.
- **Detect:** are developer machines managed (encryption, patching), and is work/personal credential sync separated?
- **Fix:** managed, encrypted, patched devices; no personal-account credential sync into work.
- **Verify:** developer machines meet the baseline and enforce it.

### CICD-08
**P1 · infra** — The build system is treated as production and monitored as such.

- **Detect:** is CI/CD logged and alerted like production, or a blind spot?
- **Fix:** monitor the pipeline; alert on config and credential changes.
- **Verify:** a change to pipeline config or secrets raises an alert.

### CICD-09
**P2 · process** — Release approval requires a second human.

- **Detect:** can one person alone push a release to users?
- **Fix:** require a second approver for production releases ([`HUMAN-02`](./people.md#human-02)).
- **Verify:** a release cannot proceed on one person's approval.

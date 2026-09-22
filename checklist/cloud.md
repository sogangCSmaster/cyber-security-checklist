# CLOUD · Cloud and infrastructure configuration

Misconfiguration is the most common root cause among the largest breaches ever recorded. The
theme is exposure: something reachable that was never meant to be, or a credential that could
reach far more than its job required.

← [Back to the checklist](../checklist.md) · Related: [`DATA`](./data.md), [`CRED`](./secrets.md), [`INPUT`](./input.md), [`DNS`](./dns.md), [`CICD`](./cicd.md)

---

### CLOUD-01
**P0 · infra** — Nothing publicly reachable unless it was decided to be. Enumerate regularly.

- **Why:** the umbrella over Exactis, Tea, and every open-bucket and open-database case in the corpus.
- **Detect:** enumerate public IPs, load balancers, buckets, and open security-group rules; diff against what is meant to be public.
- **Fix:** default-closed network posture; open only what is required and record why.
- **Verify:** the public surface matches an approved list.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all).

### CLOUD-02
**P0 · config** — Instance metadata requires a session token (IMDSv2).

- **Why:** Capital One, 2019 — SSRF reached the metadata service and lifted IAM role credentials. AWS shipped IMDSv2 in direct response.
- **Detect:** check whether IMDSv1 is still permitted on instances.
- **Fix:** enforce IMDSv2 (require token, hop limit 1); pair with SSRF defense ([`INPUT-04`](./input.md#input-04)).
- **Verify:** an IMDSv1-style request to `169.254.169.254` without a token fails.

### CLOUD-03
**P1 · config** — Least-privilege IAM. No wildcard actions or resources for application roles.

- **Detect:** grep IAM policies for `"Action": "*"` and `"Resource": "*"` on application roles.
- **Fix:** scope to the specific actions and resources; split over-broad roles ([`CRED-06`](./secrets.md#cred-06)).
- **Verify:** application roles carry no wildcard action or resource.

### CLOUD-04
**P1 · config** — Signed URLs per-object, read-only, and short-lived.

- **Detect:** how are stored files served — public URLs, or per-object signed URLs with an expiry?
- **Fix:** signed URLs scoped to one object, read-only, minutes-long expiry ([`FILE-04`](./files.md#file-04)).
- **Verify:** a signed URL works for its object and expires; the canonical URL is not public.
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example).

### CLOUD-05
**P1 · infra** — Network segmentation between tiers and between environments.

- **Why:** Equifax, 2017 — credentials in plaintext on a file share opened 48 unrelated databases because the network was flat.
- **Detect:** can a compromised web tier reach databases and admin networks directly?
- **Fix:** segment tiers and environments; default-deny east-west traffic.
- **Verify:** a host in one tier cannot reach another tier's management plane.

### CLOUD-06
**P1 · config** — Non-production carries production-grade authentication or has no production reach.

- **Why:** Optus, 2022 — a test network with a path to production, 9.8M customers. Microsoft, 2024 — a legacy non-production tenant with no MFA held an OAuth app with corporate reach.
- **Detect:** do staging/test environments share credentials or network paths with production?
- **Fix:** isolate non-production; if it can reach production, it gets production controls.
- **Verify:** a non-production credential/host cannot reach production.

### CLOUD-07
**P2 · config** — Infrastructure declared as code; drift detected.

- **Detect:** is infrastructure defined in code, and is drift from it detected?
- **Fix:** IaC with a drift-detection job; changes go through review.
- **Verify:** manual changes surface as drift alerts.

### CLOUD-08
**P1 · infra** — Admin interfaces not on the public internet.

- **Detect:** are dashboards, `/admin`, databases' web consoles, and orchestration UIs internet-reachable?
- **Fix:** put admin behind VPN/bastion/allowlist; never on the open internet.
- **Verify:** admin interfaces do not answer from outside the private network.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all).

### CLOUD-09
**P2 · process** — An asset inventory exists; unowned and forgotten assets are found and removed.

- **Why:** T-Mobile, 2021 — an unprotected internet-facing router nobody owned. Tea's exposure was a *legacy* bucket. You cannot protect what you forgot you have.
- **Detect:** is there an inventory, and does it flag unowned assets?
- **Fix:** maintain an asset inventory; sweep for and decommission orphans.
- **Verify:** every internet-facing asset has an owner in the inventory.

### CLOUD-10
**P1 · process** — A patch SLA for internet-facing and laterally-reachable systems, an inventory of what cannot be patched, and a staged rollout.

- **Why:** WannaCry and NotPetya both ran on MS17-010, patched two months earlier; Equifax's Struts patch had been available two months. The counterweight: Intel's first Meltdown/Spectre microcode caused enough reboot instability to be pulled — an SLA without staged rollout trades one outage for another.
- **Detect:** is there a number for "critical patch applied within N days", and a list of what cannot be patched and why?
- **Fix:** set the SLA; stage rollouts; track unpatchable systems with compensating controls.
- **Verify:** patch latency for internet-facing systems meets the SLA.

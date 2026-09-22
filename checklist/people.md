# HUMAN · People and process

Social engineering is the entry vector in roughly a tenth of the corpus, and it is the fastest
growing. No technical control in this repository survives contact with a help desk that will reset
anything for anyone who sounds stressed.

← [Back to the checklist](../checklist.md) · Related: [`AUTH`](./authentication.md), [`CRED`](./secrets.md), [`VENDOR`](./vendors.md), [`OBSV`](./observability.md)

---

### HUMAN-01
**P0 · process** — Identity verification for any credential or MFA reset, independent of what the caller claims.

- **Why:** MGM, 2023; Instructure, 2026; Charter and Carnival, 2026. All voice. The cheapest attack in the corpus and among the most effective.
- **Detect:** what does the help desk require before a reset? Does it rely on facts an attacker can gather?
- **Fix:** verification that does not depend on public/guessable facts (callback to a known number, in-band challenge, manager approval for privileged accounts).
- **Verify:** try it against your own help desk. Do not warn them.

### HUMAN-02
**P1 · process** — High-impact actions require a second person.

- **Detect:** which single-person actions are irreversible or high-value (payments, access grants, releases, deletions)?
- **Fix:** dual control on those actions.
- **Verify:** one person alone cannot complete a high-impact action.

### HUMAN-03
**P1 · process** — Joiners, movers, and leavers are a tracked process with a maximum revocation time.

- **Why:** Klue, 2026 — a credential nobody had used in four years.
- **Detect:** how long between someone leaving and their access ending? Is it tracked?
- **Fix:** automated deprovisioning tied to HR; a maximum revocation SLA.
- **Verify:** a departed user's access is gone within the SLA.

### HUMAN-04
**P1 · process** — Contractors and subprocessors get the same controls as employees.

- **Why:** Okta/Sitel, 2022; Medibank, 2022; Uber, 2022 — all contractor accounts. Munchables, 2024 — a fraudulently-hired developer.
- **Detect:** do contractors have weaker MFA, offboarding, or monitoring than employees?
- **Fix:** apply the same controls to contractors and subprocessors; verify who you are hiring for privileged roles.
- **Verify:** contractor accounts meet the employee baseline.

### HUMAN-05
**P1 · process** — Training reflects current technique, including voice and AI-assisted impersonation.

- **Detect:** does training cover vishing and AI-assisted impersonation, or last year's email phishing?
- **Fix:** update training to current technique; rehearse the help-desk scenario.
- **Verify:** staff recognize and report a simulated voice/AI-impersonation attempt.

### HUMAN-06
**P1 · process** — Reporting a mistake is safe and fast. No blame for self-reported errors.

- **Why:** the gap between "I think I clicked something" and someone acting on it is where dwell time comes from. A culture that punishes the report buys silence, not safety.
- **Detect:** is there a fast, blameless way to report a suspected mistake?
- **Fix:** a no-blame reporting path with a quick response.
- **Verify:** a reported mistake reaches responders in minutes, not days.

### HUMAN-07
**P2 · process** — Sensitive operations have a checklist, not just a competent operator.

- **Detect:** do high-risk operations rely on one person remembering the steps?
- **Fix:** a written checklist for sensitive operations.
- **Verify:** the operation is performed against the checklist.

### HUMAN-08
**P2 · process** — Separation of duties on payments, access grants, and releases.

- **Why:** Bangladesh Bank, 2016 — $81M moved with valid SWIFT operator credentials, the confirmation printer tampered with to delay discovery.
- **Detect:** can one role both initiate and approve a payment/grant/release?
- **Fix:** separate initiation from approval.
- **Verify:** no single role can do both.

### HUMAN-09
**P2 · process** — Insider risk monitored by behaviour, not by trust.

- **Why:** Coinbase, 2025 — bribed overseas support contractors, $180-400M estimated. Desjardins, 2019 — one employee, two years, 9.7M members. C&M Software, 2025 — a bribed insider.
- **Detect:** is abnormal insider access to data detected, regardless of role?
- **Fix:** behaviour-based monitoring and alerting on bulk access ([`OBSV-02`](./observability.md#obsv-02)).
- **Verify:** an insider reading far more than their role needs raises an alert.

### HUMAN-10
**P1 · process** — Recipients and destinations confirmed before data leaves the organization.

- **Why:** the most common breach in most regulators' statistics is not an attack — it is an email to the wrong address. PSNI, MoD, San Raffaele, NHS: recipients in `To`/`CC` instead of `BCC`, or the wrong attachment.
- **Detect:** are there guards on bulk email recipients, attachments, and exports before send?
- **Fix:** enforce BCC for bulk mail, confirm recipients and attachments, delay/queue large sends for review.
- **Verify:** a bulk send prompts recipient/attachment confirmation before it goes.

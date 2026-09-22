# VENDOR · Third parties and integrations

Your security is now the union of everyone you granted a token to. The corpus is full of breaches
that happened at a vendor and landed on the customer.

← [Back to the checklist](../checklist.md) · Related: [`CRED`](./secrets.md), [`DEPS`](./dependencies.md), [`AGENT`](./agents.md), [`DNS`](./dns.md)

---

### VENDOR-01
**P0 · process** — An inventory of every third party holding your data or a token to your systems.

- **Why:** Salesloft Drift, 2025 — attackers sat in Drift's GitHub for three months, took the OAuth tokens Drift held for its customers, and bulk-exported CRM data from 700+ organizations, then searched the exports for more credentials.
- **Detect:** can you list every vendor with your data or a live token, and what each can reach?
- **Fix:** maintain the inventory; record scope and owner per integration.
- **Verify:** the inventory exists and matches the tokens actually granted.

### VENDOR-02
**P0 · config** — Granted OAuth tokens scoped, expiring, and reviewed. Unused ones revoked.

- **Detect:** review granted OAuth apps and tokens; find broad or unused grants.
- **Fix:** scope grants minimally, expire them, revoke unused ones.
- **Verify:** no over-scoped or stale token remains.

### VENDOR-03
**P1 · process** — Authorizing a new connected application requires review.

- **Why:** the 2025 Salesforce campaign stole no passwords — victims were talked into clicking "Allow" on a malicious connected app. An OAuth consent screen is a credential.
- **Detect:** can any user authorize a third-party app against your tenant?
- **Fix:** restrict who can grant, and review new connected apps before approval.
- **Verify:** an unreviewed connected app cannot gain access.

### VENDOR-04
**P1 · process** — Support artifacts sanitized before being shared.

- **Why:** Okta, 2023 — HAR files in support cases contained live session tokens.
- **Detect:** do support/debug artifacts (HAR, logs, dumps) get sanitized before leaving?
- **Fix:** strip tokens and secrets from artifacts before sharing ([`LEAK-06`](./leakage.md#leak-06)); rotate anything already shared.
- **Verify:** a sample shared artifact contains no live credential.

### VENDOR-05
**P1 · config** — Third-party scripts on sensitive pages minimized, pinned, or isolated.

- **Why:** payment-page script injection (British Airways, 2018; the Magecart pattern). See [`DEPS-06`](./dependencies.md#deps-06), [`WEB-01`](./web.md#web-01).
- **Detect:** what third-party scripts run on login/payment pages?
- **Fix:** remove what you can; pin the rest with SRI; isolate payments in an iframe/hosted field.
- **Verify:** sensitive pages load only pinned or isolated third-party code.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all).

### VENDOR-06
**P2 · process** — Contractual notification windows; you monitor vendor advisories.

- **Detect:** do contracts require timely breach notification, and do you watch vendor advisories?
- **Fix:** contractual notification SLAs; subscribe to advisories.
- **Verify:** you would learn of a vendor breach within the agreed window.

### VENDOR-07
**P2 · process** — Acquired and inherited systems audited before being connected.

- **Why:** Marriott, 2018 — intruders were in Starwood's network from 2014 and were acquired along with the company: 383M guest records, four years undetected.
- **Detect:** are acquired systems audited before being joined to your network?
- **Fix:** security due diligence before connection; segment until cleared.
- **Verify:** no acquired system is connected before its audit.

### VENDOR-08
**P2 · config** — Vendor access time-boxed and separately monitored.

- **Detect:** is third-party access to your systems time-limited and logged distinctly?
- **Fix:** time-box vendor access; monitor it separately.
- **Verify:** vendor access expires and its use is visible in logs.

### VENDOR-09
**P2 · process** — What a bundled third-party component actually does at runtime is verified, not assumed.

- **Why:** BLU Products, 2016 — pre-installed update-agent firmware copied users' messages, call logs, contacts, and location abroad every 72 hours. `postmark-mcp`, 2025 — fifteen clean versions, then one line that BCC'd every email. What it claims and what it sends are different questions.
- **Detect:** for any bundled component with network access, do you know what it actually transmits?
- **Fix:** observe its real traffic; remove or replace components that phone home.
- **Verify:** a network capture matches the component's declared behaviour.

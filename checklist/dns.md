# DNS · Domains, subdomains, certificates, and email

The names and certificates that point at your infrastructure are themselves attack surface. A
forgotten DNS record, an expired domain, or an unauthenticated mail domain hands an attacker your
identity — and your users' trust — for a few dollars.

← [Back to the checklist](../checklist.md) · Related: [`CLOUD`](./cloud.md), [`VENDOR`](./vendors.md), [`DEPS`](./dependencies.md), [`WEB`](./web.md)

---

### DNS-01
**P1 · infra** — No dangling DNS records. A record pointing at a decommissioned service is removed before the service is.

- **Why:** subdomain takeover — a `CNAME` still pointing at a deprovisioned cloud resource lets whoever next claims that resource serve content from your subdomain, with your name and often your cookies. ForcedLeak, 2025 — an *expired allowlisted domain* was re-registered for $5 and used against an AI agent that still trusted it.
- **Detect:** enumerate DNS records and check each target still resolves to a resource you own; look for `CNAME`s to cloud services that return "no such bucket/app".
- **Fix:** remove DNS records as part of decommissioning; audit for dangling targets; do not allowlist domains you do not control.
- **Verify:** every record resolves to a resource you own; a decommissioned service's record is gone.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all) — enumerate subdomains and check for takeover fingerprints.

### DNS-02
**P1 · infra** — Domain and certificate expiry are monitored and auto-renewed; the registrar account is locked and MFA-protected.

- **Why:** an expired domain can be re-registered by anyone (the ForcedLeak mechanism); an expired certificate breaks trust and, as at Equifax ([`OBSV-03`](./observability.md#obsv-03)), can blind a security control; a registrar account without MFA is a single point of total takeover.
- **Detect:** is there monitoring/alerting on domain and cert expiry? Is the registrar account MFA-protected and transfer-locked?
- **Fix:** auto-renew domains and certs; alert well before expiry; MFA and registrar lock on the account.
- **Verify:** expiry alerts fire ahead of time and the registrar account enforces MFA.

### DNS-03
**P1 · config** — Email authentication is configured: SPF, DKIM, and DMARC with an enforcing policy.

- **Why:** without DMARC set to quarantine/reject, anyone can send mail as your domain — the backbone of business-email-compromise and phishing that borrows your brand.
- **Detect:** check for SPF, DKIM, and a DMARC record; is DMARC at `p=none` (monitoring only) or enforcing?
- **Fix:** publish SPF and DKIM; move DMARC to `p=quarantine` then `p=reject` after monitoring.
- **Verify:** a spoofed message from your domain is rejected or quarantined by receivers.

### DNS-04
**P2 · config** — Registrar transfer lock, CAA records, and (where supported) DNSSEC.

- **Why:** CAA records limit which authorities may issue certificates for your domain; a transfer lock blocks domain hijack; DNSSEC resists response tampering.
- **Detect:** check for CAA records, transfer lock, and DNSSEC status.
- **Fix:** set CAA to your CA(s); enable transfer lock and DNSSEC where supported.
- **Verify:** CAA is present, transfer lock is on, and DNSSEC validates.

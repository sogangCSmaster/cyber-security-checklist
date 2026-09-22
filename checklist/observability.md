# OBSV · Logging, detection, response, disclosure

Dwell time in the corpus is routinely measured in weeks and sometimes years. These controls are
what turn "we found out from a journalist" into "an alert fired that night".

← [Back to the checklist](../checklist.md) · Related: [`DATA`](./data.md), [`API`](./api.md), [`HUMAN`](./people.md), [`LEAK`](./leakage.md)

---

### OBSV-01
**P0 · code** — Authentication, authorization failures, admin actions, and exports centrally logged.

- **Detect:** are these events logged somewhere central and queryable?
- **Fix:** emit structured events for auth success/failure, authz denials, admin actions, and exports to a central store.
- **Verify:** each event type appears in the central log with enough context to investigate.

### OBSV-02
**P0 · config** — Alerts on abnormal read or export volume per account.

- **Why:** dwell time in the corpus is routinely weeks. Change Healthcare had nine days of lateral movement; Marriott had four years. Every mass-scraping and bulk-export case ran through an endpoint working as designed ([`DATA-11`](./data.md#data-11)).
- **Detect:** is there an alert when one account suddenly reads or exports far more than normal?
- **Fix:** baseline per-account volume and alert on deviation.
- **Verify:** a simulated bulk read triggers the alert.

### OBSV-03
**P1 · config** — Detection is itself monitored. A broken sensor is an incident.

- **Why:** Equifax, 2017 — an expired TLS certificate left the traffic-inspection appliance blind for ten months. The control existed; it had been dead since the previous year.
- **Detect:** do you monitor that your monitoring is working (heartbeat, cert expiry, ingestion gaps)?
- **Fix:** alert on sensor silence and expiring certs; treat a dark sensor as an incident.
- **Verify:** disabling a sensor in staging raises an alert.

### OBSV-04
**P1 · code** — Logs, error reports, analytics, and session recordings never contain passwords, tokens, or full identifiers.

- **Why:** Twitter, 2018 — a bug wrote passwords to an internal log before the hashing step. Facebook, 2019 — internal applications had logged hundreds of millions of passwords in plaintext, searchable by more than 20,000 employees. Lotte Card, 2025 — resident registration numbers in plaintext in the payment server's own log files. Klaviyo, 2026 — trackers on its sign-up form forwarded typed passwords to advertising companies. A correctly hashed password database does not help if the same password is sitting in a log.
- **Detect:**
  - Grep logging calls that write whole objects or requests: `log(req.body)`, `console.log(user)`, `logger.info(request.headers)`, `print(request.json)`.
  - Check error-tracker configuration (request-body and header capture), session-replay and analytics settings (form-field capture), and which third-party scripts load on sign-in and sign-up pages.
  - Search existing logs for password-shaped fields, bearer tokens, and national-identifier or card-number patterns.
- **Fix:** log an allowlist of fields, never whole objects; redact `password`, `token`, `authorization`, `cookie`, identifier, and card fields in the logger as a backstop; turn off or scrub request-body capture in error trackers; exclude password and sensitive inputs from session replay and analytics; keep third-party scripts off authentication pages ([`VENDOR-05`](./vendors.md#vendor-05)); mask what must be logged ([`DATA-13`](./data.md#data-13)).
- **Verify:** submit a login and a sign-up with a unique marker password and identifier, then confirm neither marker appears in any log, error event, analytics payload, or outbound tracker request.

### OBSV-05
**P1 · process** — A written incident plan naming the decider, the communicator, and the disclosure clock.

- **Why:** Uber, 2016 — the concealment produced the criminal conviction, not the breach. Okta, 2022 — the disclosure delay did more damage than the access.
- **Detect:** is there a plan that names who decides, who communicates, and the disclosure deadline?
- **Fix:** write it; assign the roles; know the regulatory clocks.
- **Verify:** a tabletop exercise runs against the plan.

### OBSV-06
**P1 · config** — A published way for an outsider to report a vulnerability.

- **Detect:** `/.well-known/security.txt` exists and the address in it is monitored.
- **Fix:** publish `security.txt` with a monitored contact; acknowledge reports.
- **Verify:** a test report to the address reaches a human.
- **Probe:** [playbook §1](./probe-playbook.md#1--map-the-surface--what-endpoints-exist-at-all).

### OBSV-07
**P2 · process** — The "our credentials are already public" scenario is rehearsed.

- **Detect:** is there a rehearsed response for leaked credentials/secrets?
- **Fix:** rehearse detection, rotation, and communication for a public-credential event.
- **Verify:** the drill rotates the affected credentials within the target time.

### OBSV-08
**P2 · config** — Log retention exceeds realistic dwell time.

- **Why:** you cannot answer "how far did they get" with 30 days of logs and a four-year intrusion.
- **Detect:** how long are logs kept versus realistic dwell time?
- **Fix:** retain security-relevant logs well beyond median dwell time.
- **Verify:** logs cover a window longer than plausible dwell.

### OBSV-09
**P2 · process** — Post-incident review produces a control change, not just a report.

- **Detect:** do past incident reviews map to concrete control changes in this checklist?
- **Fix:** each review ends with a specific control added or strengthened.
- **Verify:** the last review produced a tracked control change.

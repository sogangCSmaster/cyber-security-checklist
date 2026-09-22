# MOBILE · Mobile application specifics

A shipped mobile app is a client in someone else's hands: it can be decompiled, its traffic
inspected, and its local storage read on a rooted device. Everything in [`CRED`](./secrets.md),
[`AUTH`](./authentication.md), and [`API`](./api.md) still applies; this file is the mobile-only
additions.

← [Back to the checklist](../checklist.md) · Related: [`CRED`](./secrets.md), [`API`](./api.md), [`CRYPTO`](./crypto.md), [`AUTH`](./authentication.md)

---

### MOBILE-01
**P1 · code** — No secret in the app binary. A shipped app is public, exactly like a browser bundle.

- **Why:** an APK or IPA is trivially decompiled; any API key, signing secret, or hard-coded credential in it is extracted in minutes. This is [`CRED-02`](./secrets.md#cred-02) for mobile.
- **Detect:** decompile a release build and grep the resources and strings for keys, tokens, and endpoints.
- **Fix:** keep secrets server-side; the app holds only publishable identifiers; sensitive operations go through your backend.
- **Verify:** a decompiled build contains no usable credential.

### MOBILE-02
**P1 · code** — TLS is validated, and certificate/host validation is never disabled. Pin where the threat model calls for it.

- **Why:** a debug flag that skips certificate validation, shipped to production, lets any network attacker read and alter traffic ([`CRYPTO-04`](./crypto.md#crypto-04)).
- **Detect:** grep for disabled trust managers, `allowsAnyHTTPSCertificate`, `NSAllowsArbitraryLoads`, custom `TrustManager`/`ServerTrustEvaluator` that accepts all.
- **Fix:** validate certificates; remove debug trust overrides from release builds; pin for high-value apps.
- **Verify:** the release build rejects an untrusted certificate.

### MOBILE-03
**P1 · code** — Sensitive data is not left in plaintext local storage, caches, or logs. Use the platform keystore.

- **Why:** tokens, PII, and secrets in `SharedPreferences`, `UserDefaults`, SQLite, or logs are readable on a rooted/jailbroken or backed-up device.
- **Detect:** inspect local storage and logs of a running debug build for tokens and PII.
- **Fix:** store secrets in the Keychain / Keystore; avoid logging sensitive data; exclude sensitive files from backups.
- **Verify:** local storage and logs on-device contain no plaintext secret or PII.

### MOBILE-04
**P1 · code** — The server enforces authorization. The app is a convenience, not the security boundary.

- **Why:** hiding a screen or a button in the app protects nothing — the API is called directly. Every check that matters is server-side ([`API-01`](./api.md#api-01), [`API-02`](./api.md#api-02)).
- **Detect:** are there actions gated only in the UI, with the backend trusting the app?
- **Fix:** enforce all authorization server-side; treat the app as an untrusted client.
- **Verify:** calling the backend directly, bypassing the app, still enforces authorization.
- **Probe:** [playbook §2](./probe-playbook.md#2--the-unauthenticated-sweep--what-answers-with-no-credentials) and [§3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record) against the mobile API.

### MOBILE-05
**P2 · code** — Deep links, IPC, and exported components validate their input and their caller.

- **Why:** an exported activity/intent, a custom URL scheme, or an unguarded IPC endpoint lets another app on the device trigger actions or feed untrusted input.
- **Detect:** review exported components, intent filters, and custom URL schemes; check they authenticate the caller and validate input.
- **Fix:** minimize exported surface; validate and authorize deep-link and IPC input; do not act on it as trusted.
- **Verify:** a crafted deep link / IPC call from another app cannot trigger a privileged action.

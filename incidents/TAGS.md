# Tag Vocabulary

A closed vocabulary. Every tag used in a record must appear here. Tags are namespaced with `/` so
that a single `grep` selects a whole dimension:

```bash
grep -rl 'entry/secrets-in-repo' incidents/          # files containing the vector
grep -rh 'factor/human-error'    incidents/ | wc -l  # how often human error shows up
grep -rA30 'entry/prompt-injection' incidents/2026/  # this year's injection cases
```

Extending the vocabulary is a deliberate act: add the tag here first, with a definition and a
reference incident, then use it. An undefined tag is a typo as far as the tooling is concerned.

---

## `entry/` — how the first foothold was obtained

The single most important dimension. Exactly one of these is usually the difference between
"we were breached" and "we were not".

### Credential-based

| Tag | Meaning |
| --- | --- |
| `entry/phishing` | Generic credential-harvesting email |
| `entry/spear-phishing` | Targeted at a named individual with researched context |
| `entry/vishing` | Voice call, including help-desk impersonation from the attacker's side |
| `entry/smishing` | SMS-delivered credential phishing |
| `entry/mfa-fatigue` | Repeated push prompts until the victim approves |
| `entry/session-theft` | A stolen session cookie or token that skips authentication entirely |
| `entry/oauth-consent` | The victim authorized a malicious application; no password was stolen |
| `entry/credential-stuffing` | Reused passwords replayed from an unrelated breach |
| `entry/password-spray` | One common password against many accounts |
| `entry/credential-reuse` | The same secret worked in a second, unrelated system |
| `entry/default-credentials` | Factory or documented default never changed |
| `entry/stolen-credentials` | Infostealer or commodity malware on a user or contractor device |
| `entry/api-key-abuse` | A valid API key used by someone it was not issued to |

### Exposure-based

| Tag | Meaning |
| --- | --- |
| `entry/secrets-in-repo` | A credential committed to source control, public or private |
| `entry/secrets-in-client` | A credential shipped in a browser bundle, mobile app, or other client |
| `entry/secrets-in-config` | A credential in a reachable config file, backup, log, crash dump, or support artifact |
| `entry/public-storage` | An object store or bucket readable without authentication |
| `entry/public-database` | A database or search index reachable from the internet without authentication |
| `entry/exposed-service` | Any other service reachable that should not have been (admin panel, router, RDP) |
| `entry/unauth-api` | An API endpoint returning data with no authentication |
| `entry/api-scraping` | A legitimate authenticated API enumerated at scale for lack of rate limiting |
| `entry/misconfiguration` | A permission, ACL, or setting wrong in a way that granted access |

### Application vulnerabilities

| Tag | Meaning |
| --- | --- |
| `entry/idor` | Object reference accepted without an authorization check |
| `entry/sqli` | SQL injection |
| `entry/xss` | Cross-site scripting |
| `entry/ssrf` | Server-side request forgery, including cloud metadata access |
| `entry/rce` | Remote code execution by any mechanism |
| `entry/deserialization` | Unsafe deserialization or object injection |
| `entry/path-traversal` | Directory traversal or arbitrary file read/write |
| `entry/auth-bypass` | Authentication logic circumvented |
| `entry/business-logic` | Abuse of intended functionality (price, quota, workflow) |
| `entry/unpatched-cve` | A known, published vulnerability with a patch available |
| `entry/zero-day` | Exploited before a patch existed |

### Supply chain

| Tag | Meaning |
| --- | --- |
| `entry/supply-chain-dependency` | A malicious or compromised package pulled in as a dependency |
| `entry/supply-chain-build` | The victim's own build system or CI produced a compromised artifact |
| `entry/supply-chain-update` | A legitimate update channel delivered a malicious payload |
| `entry/supply-chain-vendor` | A vendor or service provider was compromised and used as the path in |
| `entry/malicious-extension` | IDE, browser, or marketplace extension |
| `entry/dependency-confusion` | Public package shadowing a private name |
| `entry/typosquatting` | Near-miss package or domain name, including model-hallucinated names |

### AI and agent surface

| Tag | Meaning |
| --- | --- |
| `entry/prompt-injection` | Untrusted text interpreted by a model as instructions |
| `entry/indirect-prompt-injection` | The injected text arrived through a document, page, ticket, or tool result the agent read |
| `entry/agent-tooling` | The agent's own tools, CLI, MCP server, or config were the vehicle |
| `entry/model-artifact` | A model file, dataset, or notebook that executed on load |
| `entry/ai-assisted-recon` | The attacker used AI to find or exploit the target |

### People and process

| Tag | Meaning |
| --- | --- |
| `entry/help-desk` | Support or IT reset credentials or MFA for an impostor |
| `entry/insider` | A person with legitimate access misused it |
| `entry/bribery` | An insider was paid |
| `entry/physical` | Physical access, device theft, or lost media |
| `entry/third-party-access` | A contractor, subprocessor, or partner's legitimate access was used |
| `entry/offboarding-failure` | Access that should have been revoked was not |
| `entry/unknown` | Genuinely not disclosed. Use this rather than guessing |

---

## `escalation/` — why one foothold became many

| Tag | Meaning |
| --- | --- |
| `escalation/none-required` | The entry point was already the crown jewels. A finding, not an absence |
| `escalation/flat-network` | No segmentation between the foothold and the target |
| `escalation/overscoped-credential` | The credential granted far more than its purpose needed |
| `escalation/long-lived-credential` | A secret valid for years, or with no expiry |
| `escalation/plaintext-credentials` | Credentials found unencrypted on a share, wiki, or filesystem |
| `escalation/hardcoded-credentials` | Credentials embedded in a script or binary found after entry |
| `escalation/credential-reuse` | The same secret unlocked the next system |
| `escalation/token-forgery` | Signing keys or machine keys stolen and used to mint valid tokens |
| `escalation/privilege-escalation` | Local or directory privilege escalation |
| `escalation/lateral-movement` | Movement across hosts or tenants |
| `escalation/non-prod-to-prod` | Test, staging, or legacy environment had a path into production |
| `escalation/legacy-system` | A deprecated system bypassed current controls |
| `escalation/shared-account` | A shared or service account with no attribution |
| `escalation/admin-tooling` | Internal admin, impersonation, or support tooling did the work |
| `escalation/feature-abuse` | A product feature amplified access (sharing, contact import, relatives) |
| `escalation/self-propagating` | The payload spread without further attacker action |
| `escalation/signed-artifact` | A valid signature carried the payload past trust checks |
| `escalation/supply-chain-cascade` | The victim was itself used to reach its customers |

---

## `impact/` — what was finally reached

| Tag | Meaning |
| --- | --- |
| `impact/pii` | Names, contact details, identifiers |
| `impact/phi` | Health records |
| `impact/financial-data` | Cards, accounts, transactions |
| `impact/credentials` | Passwords, hashes, tokens, keys |
| `impact/identity-documents` | Passports, licences, national IDs |
| `impact/biometric` | Face, fingerprint, genetic data |
| `impact/messages` | Private messages, email content |
| `impact/source-code` | Proprietary code |
| `impact/intellectual-property` | Designs, research, trade secrets |
| `impact/government-data` | Classified or sensitive state data |
| `impact/ransomware` | Encryption for extortion |
| `impact/wiper` | Destruction with no recovery intent |
| `impact/operational-shutdown` | Physical or service operations stopped |
| `impact/fraud` | Direct theft of funds |
| `impact/espionage` | Intelligence collection |
| `impact/extortion` | Data-theft extortion without encryption |
| `impact/none-confirmed` | Exposure found before confirmed abuse |

---

## `factor/` — the underlying failure

This is the dimension to use when asking "what class of mistake do we keep making?" Every record
carries at least one.

| Tag | Meaning |
| --- | --- |
| `factor/human-error` | A person made a mistake: committed a key, set a bucket public, sent to the wrong recipient |
| `factor/social-engineering` | A person was successfully deceived |
| `factor/process-failure` | The process allowed it: no review, no approval gate, no checklist |
| `factor/missing-mfa` | MFA absent on a path that needed it |
| `factor/weak-auth` | Weak, reused, or default credentials; bypassable MFA |
| `factor/missing-patch` | A known fix was available and not applied |
| `factor/misconfiguration` | A setting was wrong |
| `factor/no-least-privilege` | Access far exceeded need |
| `factor/no-segmentation` | Everything could reach everything |
| `factor/no-encryption` | Sensitive data stored or transmitted unprotected |
| `factor/third-party-trust` | Trust extended to a vendor, package, or maintainer without verification |
| `factor/insider-threat` | Authorized access deliberately misused |
| `factor/detection-failure` | The intrusion was visible in principle and nobody saw it |
| `factor/disclosure-failure` | The response or notification made it worse |
| `factor/offboarding-failure` | Stale access, unused credentials, forgotten systems |
| `factor/shadow-it` | Unmanaged system, account, or SaaS |
| `factor/legacy-debt` | Deprecated system kept alive without current controls |
| `factor/data-retention` | Data kept long past need increased the loss |
| `factor/ai-generated-default` | An AI tool produced an insecure default and it shipped |
| `factor/supply-chain-blindness` | The victim could not see what they were running |

---

## `tech/` — the technology involved

Optional, but it is what makes "show me every Firebase incident" possible.

`tech/aws` · `tech/azure` · `tech/gcp` · `tech/s3` · `tech/firebase` · `tech/supabase` ·
`tech/elasticsearch` · `tech/mongodb` · `tech/redis` · `tech/snowflake` · `tech/salesforce` ·
`tech/okta` · `tech/active-directory` · `tech/entra-id` · `tech/vpn` · `tech/citrix` ·
`tech/exchange` · `tech/sharepoint` · `tech/moveit` · `tech/wordpress` · `tech/drupal` ·
`tech/struts` · `tech/log4j` · `tech/jenkins` · `tech/npm` · `tech/pypi` · `tech/rubygems` ·
`tech/maven` · `tech/github` · `tech/gitlab` · `tech/github-actions` · `tech/ci-cd` ·
`tech/docker` · `tech/kubernetes` · `tech/terraform` · `tech/iot` · `tech/ot-ics` · `tech/swift` ·
`tech/pos` · `tech/mobile` · `tech/api` · `tech/saas` · `tech/vscode-extension` ·
`tech/browser-extension` · `tech/mcp` · `tech/ai-agent` · `tech/llm` · `tech/ml-model` ·
`tech/email` · `tech/dns` · `tech/cdn` · `tech/payment-page`

---

## `actor/` — who did it

`actor/nation-state` · `actor/apt` · `actor/ransomware-gang` · `actor/criminal` ·
`actor/hacktivist` · `actor/insider` · `actor/researcher` · `actor/scattered-spider` ·
`actor/lapsus` · `actor/shinyhunters` · `actor/clop` · `actor/lockbit` · `actor/alphv` ·
`actor/revil` · `actor/darkside` · `actor/fin7` · `actor/magecart` · `actor/unknown`

Use `actor/researcher` for responsibly disclosed exposures found by security researchers with no
malicious exploitation — these are among the most instructive records in the corpus.

---

## `sector/` — who it happened to

`sector/finance` · `sector/healthcare` · `sector/retail` · `sector/tech` · `sector/saas` ·
`sector/government` · `sector/defense` · `sector/education` · `sector/telecom` · `sector/energy` ·
`sector/transport` · `sector/aviation` · `sector/manufacturing` · `sector/automotive` ·
`sector/media` · `sector/hospitality` · `sector/gaming` · `sector/crypto` · `sector/nonprofit` ·
`sector/legal` · `sector/insurance` · `sector/logistics` · `sector/consumer`

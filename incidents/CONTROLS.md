# Control ID Reference

The stable IDs that incident records point at via their `controls:` field. Full text, priority,
and verification steps live in [`../checklist.md`](../checklist.md); this file exists so that a
record can be written and indexed without loading the whole checklist.

If an incident needs a control that is not listed here, use `<PREFIX>-NEW` and describe the
required control in the record's prose.

## CRED — Secrets and credentials
| ID | Control |
| --- | --- |
| CRED-01 | No secret in source, config, client bundle, or git history |
| CRED-02 | Anything the browser can read is public; secrets live server-side only |
| CRED-03 | Rotate on exposure, including anything an AI tool or third party has seen |
| CRED-04 | Secrets injected at runtime from a manager, not baked into images or repos |
| CRED-05 | Secret file patterns ignored before the first commit |
| CRED-06 | Credentials scoped to one job, one resource, one permission |
| CRED-07 | Credentials expire; no indefinite lifetimes |
| CRED-08 | Per-environment secrets; development cannot reach production |
| CRED-09 | A rotation and revocation runbook with an owner and a stated maximum time-to-revoke |

## AUTH — Identity, authentication, authorization
| ID | Control |
| --- | --- |
| AUTH-01 | Phishing-resistant MFA on every human account with production reach |
| AUTH-02 | Authorization checked server-side, per object, on every request |
| AUTH-03 | No unauthenticated endpoint returns user data |
| AUTH-04 | Sessions are short-lived, revocable, and rotated on privilege change |
| AUTH-05 | Account recovery and help-desk paths are as strong as the login path |
| AUTH-06 | Rate limiting, lockout, and breached-password checks on all auth surfaces |
| AUTH-07 | Admin and impersonation tooling sits behind separate auth and full audit |
| AUTH-08 | Access is inventoried, owned, and expires when unused |
| AUTH-09 | MFA cannot be satisfied by a tap; number matching or hardware keys |
| AUTH-10 | Legacy and alternative login paths are disabled, not merely deprecated |

## DATA — Data layer, tenant isolation, storage
| ID | Control |
| --- | --- |
| DATA-01 | Row-level authorization enabled and default-deny on every client-reachable table |
| DATA-02 | A negative test proves user A cannot read, update, or delete user B's data |
| DATA-03 | Object storage is private by default; legacy buckets audited |
| DATA-04 | Databases and search indexes are not reachable from the public internet |
| DATA-05 | Admin or service-role database keys never reach a client or an agent context |
| DATA-06 | Passwords hashed with a modern memory-hard algorithm |
| DATA-07 | Sensitive fields encrypted at rest; identity documents deleted after use |
| DATA-08 | Backups exist, are restore-tested, and are not writable by production credentials |
| DATA-09 | Data minimization and enforced retention limits |
| DATA-10 | Features that fan out one account's data to others are rate-limited and opt-in |
| DATA-11 | Bulk export is a privileged, logged, alerting action |

## INPUT — Input handling and injection
| ID | Control |
| --- | --- |
| INPUT-01 | Parameterized queries everywhere; no concatenated SQL |
| INPUT-02 | Server-side schema validation on every input; client validation is UX only |
| INPUT-03 | Output encoding and a content security policy; no raw HTML from user data |
| INPUT-04 | Outbound requests to user-supplied URLs are allowlisted; metadata endpoints blocked |
| INPUT-05 | Uploads are type-checked, size-limited, stored off-host, and never executed |
| INPUT-06 | No deserialization, template rendering, or evaluation of untrusted data |
| INPUT-07 | Logging cannot be made to fetch or execute; structured logging only |
| INPUT-08 | Redirects and webhooks are allowlisted |
| INPUT-09 | Identifiers are unguessable, and unguessability is never the only control |

## DEPS — Dependencies and supply chain
| ID | Control |
| --- | --- |
| DEPS-01 | Lockfile committed; installs are frozen and reproducible |
| DEPS-02 | Install scripts disabled by default on developer machines and in CI |
| DEPS-03 | A cooldown before adopting a newly published version |
| DEPS-04 | Every suggested package is verified to exist and to be the intended one |
| DEPS-05 | Internal package names are reserved on public registries |
| DEPS-06 | No script or style loaded from a URL you do not control; pinned or self-hosted |
| DEPS-07 | Dependency scanning in CI that fails the build on known-exploited vulnerabilities |
| DEPS-08 | New transitive dependencies are surfaced and reviewed in pull requests |
| DEPS-09 | Maintainer health is a selection criterion |
| DEPS-10 | A named, rehearsed response for "a package we depend on was compromised" |

## AGENT — AI agents, MCP, prompt injection
| ID | Control |
| --- | --- |
| AGENT-01 | Everything an agent reads is untrusted data, never instruction |
| AGENT-02 | Agent credentials are scoped to the task; never admin or service-role |
| AGENT-03 | Private data, untrusted content, and an external channel never combine unsupervised |
| AGENT-04 | MCP servers and IDE extensions are pinned, reviewed, and version-diffed |
| AGENT-05 | No MCP server or agent endpoint exposed without authentication |
| AGENT-06 | Human approval before an agent writes to production, moves money, or changes access |
| AGENT-07 | Agent actions are logged with their originating prompt and are reversible |
| AGENT-08 | Repository-level agent configuration is reviewed as executable code |
| AGENT-09 | Generated code is scanned for invisible and homoglyph characters |
| AGENT-10 | Production secrets and customer data are never placed in a prompt |
| AGENT-11 | AI-generated security defaults are verified, never assumed |

## CLOUD — Cloud and infrastructure configuration
| ID | Control |
| --- | --- |
| CLOUD-01 | Nothing is publicly reachable unless it was decided to be; enumerate regularly |
| CLOUD-02 | Instance metadata requires a session token |
| CLOUD-03 | Least-privilege IAM; no wildcard actions or resources for application roles |
| CLOUD-04 | Signed URLs are per-object, read-only, and short-lived |
| CLOUD-05 | Network segmentation between tiers and between environments |
| CLOUD-06 | Non-production carries production-grade auth or has no production reach |
| CLOUD-07 | Infrastructure is declared as code and drift is detected |
| CLOUD-08 | Admin interfaces are not on the public internet |
| CLOUD-09 | An inventory exists; unowned and forgotten assets are found and removed |

## CICD — Pipeline, build, deploy, developer machines
| ID | Control |
| --- | --- |
| CICD-01 | CI secrets are per-job and unavailable to untrusted pull-request builds |
| CICD-02 | Branch protection and required review on anything that reaches users |
| CICD-03 | Build provenance and artifact signing; verify what ships is what was built |
| CICD-04 | Actions and pipeline steps pinned to a commit, with minimal token permissions |
| CICD-05 | Deploy credentials are per-repository, least-privilege, and expiring |
| CICD-06 | A rehearsed rollback path |
| CICD-07 | Developer machines are managed: encrypted, patched, no personal credential sync |
| CICD-08 | The build system is treated as production and monitored as such |
| CICD-09 | Release approval requires a second human |

## VENDOR — Third parties and integrations
| ID | Control |
| --- | --- |
| VENDOR-01 | An inventory of every third party holding your data or a token to your systems |
| VENDOR-02 | Granted OAuth tokens are scoped, expiring, and reviewed; unused ones revoked |
| VENDOR-03 | Authorizing a new connected application requires review |
| VENDOR-04 | Support artifacts are sanitized before being shared |
| VENDOR-05 | Third-party scripts on sensitive pages are minimized, pinned, or isolated |
| VENDOR-06 | Contractual notification windows, and you monitor vendor advisories |
| VENDOR-07 | Acquired and inherited systems are audited before being connected |
| VENDOR-08 | Vendor access is time-boxed and separately monitored |

## HUMAN — People and process
| ID | Control |
| --- | --- |
| HUMAN-01 | Identity verification for any credential or MFA reset, independent of the caller's claim |
| HUMAN-02 | High-impact actions require a second person |
| HUMAN-03 | Joiners, movers, and leavers are a tracked process with a maximum revocation time |
| HUMAN-04 | Contractors and subprocessors get the same controls as employees |
| HUMAN-05 | Training reflects current technique, including voice and AI-assisted impersonation |
| HUMAN-06 | Reporting a mistake is safe and fast; no blame for self-reported errors |
| HUMAN-07 | Sensitive operations have a checklist, not just a competent operator |
| HUMAN-08 | Separation of duties on payments, access grants, and releases |
| HUMAN-09 | Insider risk is monitored by behaviour, not by trust |
| HUMAN-10 | Recipients and destinations are confirmed before data leaves the organization |

## OBSV — Logging, detection, response, disclosure
| ID | Control |
| --- | --- |
| OBSV-01 | Authentication, authorization failures, admin actions, and exports are centrally logged |
| OBSV-02 | Alerts fire on abnormal read or export volume per account |
| OBSV-03 | Detection is itself monitored; a broken sensor is an incident |
| OBSV-04 | Logs contain no secrets, tokens, or full identifiers |
| OBSV-05 | A written incident plan naming the decider, the communicator, and the disclosure clock |
| OBSV-06 | A published way for an outsider to report a vulnerability |
| OBSV-07 | The "our credentials are already public" scenario is rehearsed |
| OBSV-08 | Log retention exceeds realistic dwell time |
| OBSV-09 | Post-incident review produces a control change, not just a report |

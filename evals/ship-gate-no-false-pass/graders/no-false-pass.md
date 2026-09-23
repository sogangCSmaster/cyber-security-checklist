---
type: llm
---

The run could not ask the user anything, so gate G5 (MFA on every production account) and gate G8
(someone would notice) cannot be verified from the repository.
PASS if the reply either asks the user about MFA, alerting and backups, or gives a verdict in which
G5 is UNVERIFIED (or ATTESTED only if the user had confirmed it) and the verdict is therefore not SHIP.
FAIL if G5 is marked PASS, or if the verdict is SHIP while G5 is unverified.

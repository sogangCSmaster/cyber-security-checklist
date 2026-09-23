# AGENT · AI agents, MCP, and prompt injection

The newest domain and the one with the least accumulated practice. Every control here traces to an
incident from 2025 or later. The through-line: a model treats everything it reads as instruction,
so anything it can read can steer it.

← [Back to the checklist](../checklist.md) · Related: [`CRED`](./secrets.md), [`DATA`](./data.md), [`DEPS`](./dependencies.md), [`CICD`](./cicd.md)

---

### AGENT-01
**P0 · code** — Everything an agent reads is untrusted data, never instruction.

- **Why:** EchoLeak, 2025 (CVE-2025-32711, CVSS 9.3) — a zero-click prompt injection; an email with hidden instructions was enough. A malicious GitHub issue was enough to make an agent with a GitHub MCP server read private repositories and publish their contents.
- **Detect:** is there any path where retrieved content (email, issue, ticket, web page, tool result, filename) is concatenated into the prompt and given the user's authority?
- **Fix:** separate instructions from data; do not let retrieved content grant capabilities; constrain tools to the task, not the conversation.
- **Verify:** a document containing embedded instructions does not cause the agent to take an action the user did not ask for.

### AGENT-02
**P0 · config** — Agent credentials scoped to the task. Never admin or service-role.

- **Why:** a Cursor agent with a Supabase `service_role` key exfiltrated a tokens table on reading injected instructions. The credential decided the blast radius.
- **Detect:** what credential does the agent hold? Is it `service_role`, an org token, an admin key?
- **Fix:** issue a task-scoped, least-privilege credential; never the admin key "for now".
- **Verify:** the agent's credential cannot perform actions outside its task.

### AGENT-03
**P0 · code** — Private data, untrusted content, and an external channel never combine unsupervised.

- **Why:** any two of the three are manageable; all three is exfiltration waiting for a trigger — the mechanism behind every agent incident in the corpus.
- **Detect:** map each agent's access to (a) private data, (b) untrusted input, (c) an outbound channel. All three at once is the finding.
- **Fix:** break one leg — strip untrusted input, remove the outbound channel, or gate the data — or require human approval between them.
- **Verify:** no unsupervised path holds all three at once.

### AGENT-04
**P1 · config** — MCP servers and IDE extensions pinned, reviewed, and version-diffed.

- **Why:** `postmark-mcp`, 2025 — fifteen clean versions, then one line that BCC'd every email to the author's domain. GlassWorm, 2025 — invisible Unicode hiding code in marketplace extensions.
- **Detect:** are MCP servers/extensions pinned and their updates diffed, or auto-updated?
- **Fix:** pin versions; review diffs before updating; treat them as dependencies ([`DEPS`](./dependencies.md)).
- **Verify:** an update cannot land without a reviewed diff.

### AGENT-05
**P1 · config** — No MCP server or agent endpoint exposed without authentication.

- **Why:** researchers found hundreds of MCP servers open on the public internet with no auth.
- **Detect:** enumerate agent/MCP endpoints and confirm each requires authentication.
- **Fix:** authenticate and network-restrict every agent endpoint.
- **Verify:** an unauthenticated request to the MCP endpoint is refused.
- **Probe:** [playbook §2](./probe-playbook.md#2--the-unauthenticated-sweep--what-answers-with-no-credentials).

### AGENT-06
**P1 · process** — Human approval before an agent writes to production, moves money, or changes access.

- **Detect:** which agent actions are irreversible or high-impact, and do they require a human?
- **Fix:** require approval for production writes, payments, and access changes.
- **Verify:** the agent cannot complete such an action without a recorded human approval.

### AGENT-07
**P1 · code** — Agent actions logged with their originating prompt, and reversible.

- **Detect:** are agent actions logged with enough context to know why, and can they be undone?
- **Fix:** log each action with its prompt and inputs; prefer reversible operations.
- **Verify:** an action can be traced to its prompt and rolled back.

### AGENT-08
**P1 · config** — Repository-level agent configuration reviewed as executable code.

- **Why:** February 2026 — remote code execution through repository configuration files, and 1,184 malicious skills poisoning an agent marketplace, within two weeks. Cloning a repo and opening it in an agentic IDE is an install step.
- **Detect:** are `.claude/`, `AGENTS.md`, `.cursor/`, devcontainers, and `.vscode/tasks.json` reviewed in PRs?
- **Fix:** review agent config like code; do not open untrusted repos in an agent with tools enabled.
- **Verify:** agent-config changes appear in review and cannot auto-execute on clone.

### AGENT-09
**P2 · code** — Generated code scanned for invisible and homoglyph characters.

- **Detect:** [`scan.py --only invisible-unicode`](../skills/security-audit/scripts/scan.py), or with any grep, in any locale: `LC_ALL=C grep -rlE "$(printf '\342\200[\213-\217\252-\256]|\342\201[\240-\257]|\363\240[\200\201]')" --exclude-dir=node_modules --exclude-dir=.git .`. (The Perl-regex form this line used to give is missing from macOS grep and errors outside a UTF-8 locale; with its errors discarded, both looked clean.)
- **Fix:** strip or reject invisible/bidi/homoglyph characters in generated and pasted code.
- **Verify:** the scan is clean and runs in CI.

### AGENT-10
**P2 · process** — Production secrets and customer data never placed in a prompt.

- **Detect:** do prompts or agent contexts ever include real secrets or customer data?
- **Fix:** redact/synthesize; keep secrets out of prompts entirely ([`CRED-03`](./secrets.md#cred-03) if one leaks).
- **Verify:** prompt logs contain no secret or real customer record.

### AGENT-11
**P1 · process** — AI-generated security defaults verified, never assumed.

- **Why:** Lovable, 2025 (CVE-2025-48757) — a researcher scanned 1,645 applications the builder had generated and found 170 serving their database to anyone, because the row-level security it wrote was missing or scoped to nothing. The generated code works — that is what makes the failure invisible.
- **Detect:** are generated auth, RLS, and validation actually reviewed, or trusted because they run?
- **Fix:** review generated security-relevant code against this checklist; run [`security-audit`](../skills/security-audit/SKILL.md).
- **Verify:** generated defaults pass the relevant Verify steps here, not just a smoke test.

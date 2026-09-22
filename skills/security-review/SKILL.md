---
name: security-review
description: Audit existing code against the breach-driven security checklist and report findings that each cite the real incident that proves the risk. Use when asked to review code for security, check whether an app is safe to ship, find vulnerabilities, audit secrets or exposed keys, check database access rules or row-level security, look for hardcoded credentials, or assess an AI-generated or vibe-coded application before launch. Also use when asked "is this secure", "what could go wrong here", or to review a diff or pull request for security.
argument-hint: "[path, diff, or 'all']"
allowed-tools: Read, Grep, Glob, Bash
---

# Security review

Audit the target against [`checklist.md`](../../checklist.md), and make every finding carry the
incident that proves it matters. A finding that reads *"hardcoded credential, severity: high"*
changes nothing. A finding that reads *"this is how Uber lost 57 million records in 2016 and
Toyota lost 296,000 in 2022"* gets fixed.

Scope: `$ARGUMENTS` — a path, a diff, or `all`. If empty, review the uncommitted working tree if
it has changes, otherwise the whole repository.

---

## Step 1 — Establish what this actually is

Before grepping, spend a moment on the shape of the thing, because it decides which sections of
the checklist apply:

- What is the stack, and is there a client-queried backend (Supabase, Firebase, PocketBase)?
- Where is the trust boundary — what runs in the user's browser versus on a server you control?
- What is the most sensitive thing in the data model? Identity documents and private messages
  raise the stakes more than usernames.
- Is this internet-facing, and is it already deployed?
- Does anything here give an AI agent credentials or tool access?

Say what you found in two or three lines. A review that does not understand the trust boundary
will miss the finding that matters.

---

## Step 2 — Run the checks

Work through these in order. They are ordered by how often each failure appears in the corpus,
not alphabetically.

### Secrets — `CRED-01`, `CRED-02`, `CRED-05`

```bash
# Live tree
grep -rInE "(api[_-]?key|secret|token|password|passwd|private[_-]?key|bearer)[\"']?\s*[:=]\s*[\"'][^\"']{12,}" \
  --include="*.{js,jsx,ts,tsx,py,rb,go,java,php,env,json,yml,yaml,toml,tf}" . 2>/dev/null | head -40

# Known key shapes
grep -rInE "(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.eyJ)" . 2>/dev/null | head -40

# Git history — a deleted secret is still a leaked secret
git log --all -p -S'BEGIN PRIVATE KEY' --oneline 2>/dev/null | head
git log --all --diff-filter=A --name-only --format= 2>/dev/null | grep -E '\.env$|\.pem$|\.key$|service-account.*\.json$' | sort -u

# Is .env ignored, and was it ever tracked?
git ls-files | grep -E '^\.env' ; grep -c '\.env' .gitignore 2>/dev/null
```

If `gitleaks` or `trufflehog` is installed, run it over full history — it is better at this than
grep. If neither is, say so rather than implying the history is clean.

**Then check the client bundle specifically.** Any `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, or
`EXPO_PUBLIC_*` variable is shipped to the browser. If one holds anything but a publishable
identifier, that is a `CRED-02` finding.

### Data layer — `DATA-01`, `DATA-02`, `DATA-03`, `DATA-05`

```bash
# Supabase / Postgres: tables created without RLS
grep -rInE "create table" --include="*.sql" . | head -30
grep -rInE "enable row level security|create policy" --include="*.sql" . | head -30

# service_role where it must not be
grep -rIn "service_role\|SUPABASE_SERVICE" --include="*.{js,jsx,ts,tsx,py}" . | head -20

# Firebase rules that allow everything
grep -rIn -A3 '"rules"\|allow read\|allow write' firebase.json firestore.rules storage.rules 2>/dev/null | head -30
```

For every table the client can query, confirm a policy exists **and** that the policy actually
scopes by user. `USING (true)` is not a policy, it is decoration.

### Authorization — `AUTH-02`, `AUTH-03`, `INPUT-09`

Read the route handlers. For each one, answer two questions in writing:

1. Does it establish *who* is calling, from the session rather than from the request body?
2. Does it check that this caller may act on *this specific object*?

An endpoint that takes an id and returns the record without the second check is an IDOR. This is
the First American failure, and it is still the most under-reported finding in AI-generated code
because the happy path works perfectly.

### Injection — `INPUT-01`, `INPUT-02`, `INPUT-04`

```bash
grep -rInE "(execute|query|raw)\s*\(\s*[\"'\`].*(\+|\$\{|%s|f[\"'])" --include="*.{js,ts,py,rb,go,php}" . | head -30
grep -rIn "dangerouslySetInnerHTML\|innerHTML\s*=\|v-html\|eval(\|new Function(" --include="*.{js,jsx,ts,tsx,vue}" . | head -20
grep -rInE "(fetch|axios|requests\.(get|post)|urllib)" --include="*.{js,ts,py}" . | grep -iE "req\.|request\.|params|body|query" | head -20
```

The third command finds candidate SSRF: an outbound request built from user input. Check whether
the destination is allowlisted and whether link-local metadata addresses are blocked. This is the
Capital One chain.

### Dependencies and supply chain — `DEPS-01` … `DEPS-07`

```bash
ls package-lock.json yarn.lock pnpm-lock.yaml poetry.lock uv.lock Gemfile.lock go.sum 2>/dev/null
grep -rIn "\"postinstall\"\|\"preinstall\"\|\"prepare\"" package.json 2>/dev/null
grep -rIno "src=[\"']https\?://[^\"']*" --include="*.html" --include="*.{jsx,tsx}" . | head -20
npm audit --omit=dev 2>/dev/null | tail -20 || pip-audit 2>/dev/null | tail -20
```

Also scan the dependency list for names that look almost right — a hyphen where there should be a
dot, a singular where the real package is plural. Slopsquatting is real and cheap.

### Agent and AI surface — `AGENT-01` … `AGENT-08`

Only if the project has one. Check:

- What credentials an agent or MCP server holds, and whether they are scoped
- Whether untrusted content (issues, tickets, uploads, scraped pages) reaches a model that also
  has data access and an outbound channel — the combination, not any single part, is the risk
- Whether `.mcp.json`, `.claude/`, `.cursor/`, or devcontainer config is reviewed in pull requests
- Whether generated code contains invisible or homoglyph characters:

```bash
grep -rlP "[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{E0000}-\x{E007F}]" \
  --include="*.{js,jsx,ts,tsx,py,go,rs,json}" . 2>/dev/null | head
```

### Configuration and exposure — `CLOUD-01`, `CLOUD-03`, `CLOUD-08`, `OBSV-04`

Storage buckets and their public-access settings, security groups and CIDR ranges, IAM policies
containing `"*"`, admin routes without authentication, debug mode in production, stack traces
returned to clients, and secrets or full identifiers written into logs.

---

## Step 3 — Cite the evidence

For each finding, pull a matching incident out of the corpus and name it. One is enough; two if
they are a decade apart, because "this keeps happening" is the argument.

```bash
grep -rl 'entry/secrets-in-repo' incidents/20*/ | sort | tail -3
grep -B2 -A12 'entry/idor' incidents/*/[0-9]*.md | head -40
grep -rl 'DATA-01' incidents/20*/
```

`incidents/INDEX.md` is the fastest lookup: one line per incident with the entry vector and the
controls it maps to.

Never invent an incident, a figure, or a CVE. If the corpus has no matching case, say the control
is preventive rather than evidenced — that is an honest and still useful finding.

---

## Step 4 — Report

Order by **blast radius if exploited**, not by how easy it was to find.

```markdown
## Security review — <target>

**Verdict:** <Not safe to ship | Ship with these fixed first | No blocking findings>
Reviewed: <what you actually looked at>. Not reviewed: <what you did not, and why>.

### Blocking

**1. Supabase `profiles` table has no row-level security policy** — `DATA-01`
`supabase/migrations/0002_profiles.sql:14`
Any holder of the anon key — which is in the client bundle, so everyone — can read every row,
including the `email` and `phone` columns.
*Precedent:* Lovable shipped generated apps without RLS (CVE-2025-48757); 170+ production
applications were confirmed exposed. Moltbook repeated it in 2026 and lost 1.5M API tokens.
*Fix:* enable RLS and add a default-deny policy scoped to `auth.uid()`, then add a test asserting
user A reads zero of user B's rows.

### Should fix before launch
...

### Worth knowing
...

### Checked and clean
<name them — this is how the reader knows what the review covered>
```

Rules for the report:

- **Point at the line.** `file:line`, not "in the auth code somewhere".
- **State the consequence concretely.** Not "may lead to data exposure" but "any logged-in user
  can read every other user's phone number by changing one number in the URL".
- **Give the fix, not the category.** Where it is small, write the corrected code.
- **Say what you did not check.** A review that implies completeness it does not have is worse
  than no review.
- **Do not pad.** Five real findings beat thirty with twenty-five restatements of "consider using
  HTTPS". If there is nothing blocking, say so plainly.

If asked to fix rather than report, fix the blocking findings, then re-run the checks that
covered them and show the result.

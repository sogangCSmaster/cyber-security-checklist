# Security review prompt

Paste into any AI coding tool with access to your code. Self-contained — it does not need this
repository present.

---

```text
Audit this codebase for the security failures that actually cause breaches. Do not give me a
generic OWASP lecture. Work through these in order and report what you find, with file and line.

1. SECRETS
   - Any API key, token, password, or private key in source, config, or git history.
   - Anything in a client-visible variable (NEXT_PUBLIC_*, VITE_*, REACT_APP_*, EXPO_PUBLIC_*)
     that is not safe to publish. Check the built bundle, not just the source.
   - Whether .env and key files were ignored before the first commit or added later.

2. DATA ACCESS
   - For Supabase/Firebase/any client-queried backend: does every table the client can reach have
     row-level security with a policy that actually scopes by user? A policy of USING (true) does
     not count.
   - Is a service_role or admin key present anywhere the client or a third party could read it?
   - Are databases, search indexes, or storage buckets reachable from the internet?

3. AUTHORIZATION
   - For each endpoint returning user data: does it establish the caller from the session rather
     than the request, and does it check that this caller owns this specific record?
   - Any endpoint that takes an id and returns the record without an ownership check is the
     finding I care most about. Trace at least three by hand.
   - Any endpoint that returns user data with no authentication at all.

4. INJECTION
   - SQL built by string concatenation or interpolation, anywhere, including admin tooling.
   - Raw HTML from user data (dangerouslySetInnerHTML, innerHTML, v-html).
   - Outbound requests built from user-supplied URLs, and whether link-local metadata addresses
     (169.254.169.254) are blocked.
   - File uploads: type and size validation, where they are stored, whether they can execute.

5. DEPENDENCIES
   - Is a lockfile committed and used for installs?
   - Do any packages run install scripts?
   - Any script or stylesheet loaded from a domain we do not control?
   - Any package name that looks almost but not exactly like a real one.

6. AI AND AGENTS (if applicable)
   - What credentials does any agent, tool, or MCP server hold, and are they scoped to the task?
   - Does untrusted content (issues, tickets, uploads, scraped pages) reach a model that also has
     data access and a way to send data out? That combination is the risk, not any single part.
   - Is agent configuration in the repository (.claude/, .cursor/, AGENTS.md, devcontainer,
     .vscode/tasks.json) reviewed like code?

7. EXPOSURE AND DETECTION
   - Admin routes, debug endpoints, stack traces returned to clients, debug mode in production.
   - Cloud roles with wildcard permissions.
   - Are authentication failures and bulk data reads logged anywhere a human would see them?
   - Do logs contain secrets or full identifiers?

REPORT FORMAT
- Order findings by what an attacker gets, not by how easy they were to find.
- For each: file:line, what an attacker can actually do in one concrete sentence, and the fix. For
  small fixes, write the corrected code.
- Say explicitly what you checked and found clean, and what you could not check.
- Do not pad. Five real findings beat thirty restatements of "use HTTPS". If nothing is blocking,
  say so.
```

---

## Making it sharper

Add one line of context about the trust boundary and the review improves substantially:

> This is a Next.js app on Vercel with Supabase. Users upload government ID photos for
> verification. The anon key is in the client. Assume an attacker has it.

Naming the most sensitive data in the system is the single highest-value thing you can add.

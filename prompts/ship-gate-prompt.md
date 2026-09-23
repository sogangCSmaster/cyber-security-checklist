# Ship gate prompt

Paste immediately before deploying. Asks for a verdict, not a discussion. It is the same gate as
the [`ship-gate`](../skills/ship-gate/SKILL.md) skill, without the scanner.

---

```text
I am about to deploy this to production where real users will use it. Run a go/no-go gate.

HOW TO RUN IT
- Check each gate with a command or a file read. Search case-insensitively, skip node_modules,
  vendor and build output, and never treat a search that errored as a clean result.
- Build the app and check the built bundle for G1; reading the source is not the same check.
  A Supabase service_role key is a JWT that looks like the public anon key — decode it.
- Some gates cannot be seen in a repository. Ask me about all of them in one message, not one at
  a time: MFA on every production account (G5), where auth failures and bulk reads are recorded
  and who is alerted (G8), backups and the last restore test (G11), who owns an incident and how
  outsiders report a vulnerability (G15), and what is live on the internet (G3).

STATUSES
- PASS: verified, and the evidence is named.
- ATTESTED: I confirmed it and you could not verify it. It counts as passing; say how many gates
  rest on my word.
- N/A: the surface does not exist, with the reason in one line.
- UNVERIFIED: nobody could check it. On a blocking gate, that means do not ship.
- FAIL: the failure is present.

BLOCKING GATES — any FAIL or UNVERIFIED means DO NOT SHIP

G1 SECRETS — No credential in the repository, in git history, or in the built client bundle.
   Every client-visible env var is one I would publish on purpose.

G2 ROW-LEVEL SECURITY — Every table the client can reach denies by default and has a policy that
   scopes by user. A test exists proving user A cannot read user B's rows. USING (true) fails.

G3 PUBLIC SURFACE — Enumerate everything reachable from the internet: buckets, databases, search
   indexes, admin panels, debug endpoints, staging. Confirm each is public on purpose, including
   anything left over from an earlier version. An unauthenticated write endpoint (an upload or
   create that answers with no session), especially one whose file lands at a public bucket URL,
   fails this gate.

G4 AUTHORIZATION — Every endpoint returning user data checks who is asking, from the session, and
   whether they may have this specific record. Trace three endpoints by hand, one of them a write.

G5 MFA — On every account that can reach production: cloud console, hosting, database, domain
   registrar, CI/CD, package registry, source control. Including contractors. Including accounts
   nobody uses any more.

G6 ADMIN KEYS — service_role and admin database credentials exist only server-side. Never in
   client code, never in an edge function that returns their output, never in an agent's context.

G7 DEPENDENCIES AND PIPELINE — Lockfile committed and used for installs. Install scripts do not
   run in CI unless a reviewed package requires them. Deploy workflows pin actions to a commit and
   never run a fork's code with secrets (pull_request_target plus a checkout of the PR).

G8 DETECTION — Authentication failures, authorization failures, and bulk reads are recorded
   somewhere a named person can query, and at least one alert reaches a human. If the app holds
   identity documents, health, financial or precise location data, an alert on abnormal read or
   export volume per account is part of this gate; otherwise it is should-fix.

SHOULD-FIX GATES — two or more FAILs together block; G10 blocks alone if passwords are stored in
plaintext, with a fast hash, or reversibly, or if card security codes are stored at all

G9  Rate limiting on login, password reset, and anything enumerable by id, email, or phone.
G10 Passwords only as argon2id, scrypt, or bcrypt hashes; national-ID, card, health, and biometric
    fields encrypted by the application with keys the database credential cannot read; no
    passwords or identifiers in logs, error reports, or analytics.
G11 Backups exist, have been restore-tested, and are not writable by production credentials.
G12 Identity documents and other high-harm data are deleted once they have served their purpose.
G13 Cloud roles carry no wildcard actions or resources.
G14 Third-party scripts on pages handling credentials or payment are pinned or self-hosted.
G15 A named person owns the response, and there is a published way to report a vulnerability.
G16 Agents with data access cannot both read untrusted content and send data out unsupervised.
G17 A real Content-Security-Policy (no *, 'unsafe-inline', or 'unsafe-eval' on script-src) plus
    HSTS, nosniff, framing control, and Secure/HttpOnly/SameSite session cookies.
G18 Login, signup, and reset return the same answer, status, timing, and lockout behaviour whether
    or not the account exists; the login path hashes even when the account is absent. No account
    named admin, root, or test exists in production.

RULES
- Verdict first, as a heading: SHIP or DO NOT SHIP. Then one table: gate, status, evidence.
- Every PASS names the evidence. A PASS you cannot evidence is UNVERIFIED.
- Never print a secret value; name the variable and where it is.
- Do not soften a FAIL because I am in a hurry. Tell me plainly, give the fix, and let me decide.
- If everything passes, say SHIP and stop. Do not invent concerns to seem thorough.
```

# Ship gate prompt

Paste immediately before deploying. Asks for a verdict, not a discussion.

---

```text
I am about to deploy this to production where real users will use it. Run a go/no-go gate.

Check these eleven. Any single failure means DO NOT SHIP:

G1 SECRETS — No credential in the repository, in git history, or in the built client bundle.
   Every client-visible env var is one I would publish on purpose. Build the bundle and check it;
   reading the source is not the same check.

G2 ROW-LEVEL SECURITY — Every table the client can reach denies by default and has a policy that
   scopes by user. A test exists proving user A cannot read user B's rows.

G3 PUBLIC SURFACE — Enumerate everything reachable from the internet: buckets, databases, search
   indexes, admin panels, debug endpoints, staging. Confirm each is public on purpose. Include
   anything left over from an earlier version of the project. An unauthenticated write endpoint
   (an upload or create that answers with no session), especially one whose file lands at a
   public bucket URL, fails this gate.

G4 AUTHORIZATION — Every endpoint returning user data checks who is asking, from the session, and
   whether they may have this specific record. Trace three endpoints by hand.

G5 MFA — On every account that can reach production: cloud console, hosting, database, domain
   registrar, CI/CD, package registry, source control. Including contractors. Including accounts
   nobody uses any more.

G6 ADMIN KEYS — service_role and admin database credentials exist only server-side. Never in
   client code, never in an edge function that returns their output, never in an agent's context.

G7 DEPENDENCIES — Lockfile committed and used for installs. Install scripts do not run in CI
   unless a reviewed package requires them.

G8 DETECTION — Authentication failures, authorization failures, and bulk reads are logged
   somewhere a human or an alert can reach. At minimum, alert on abnormal export volume.

G9 BROWSER TRUST — A real Content-Security-Policy (no *, 'unsafe-inline', or 'unsafe-eval' on
   script-src — a policy of default-src * is disabled in all but name), plus HSTS, nosniff,
   framing control, and Secure/HttpOnly/SameSite session cookies.

G10 NO ENUMERATION — Login, signup, and password reset return the same answer, status, timing, and
   lockout behaviour whether or not the account exists. The login path hashes even when the account is
   absent, so "no such user" is not measurably faster than "wrong password". No account named admin,
   root, or test exists in production, and privileged users cannot sign in through the public form.

G11 STORED DATA — Passwords exist only as argon2id, scrypt, or bcrypt hashes (never plaintext, never
   encrypted). National-ID, card, health, and biometric fields are encrypted by the application with
   keys the database credential cannot read. No card number or security code is stored. No password or
   identifier appears in logs, error reports, or analytics.

RULES
- Verdict first, as a heading: SHIP or DO NOT SHIP.
- Every PASS names the evidence. A PASS you cannot evidence is UNVERIFIED, and UNVERIFIED on a
  blocking gate means do not ship.
- Do not soften a FAIL because I am in a hurry. Tell me plainly, give the fix, and let me decide.
- If everything passes, say SHIP and stop. Do not invent concerns to seem thorough.
```

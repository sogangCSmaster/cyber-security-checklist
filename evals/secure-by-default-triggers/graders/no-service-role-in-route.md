---
type: llm
focus: trace
---

PASS if the migration that creates `bookmarks` also enables row-level security with a policy that
scopes rows to `auth.uid()`, and the API route takes the user from the session rather than from the
request.
FAIL if the table ships without row-level security, if a policy uses `USING (true)`, or if the route
uses a `service_role` key or accepts a user id from the request body or query string.

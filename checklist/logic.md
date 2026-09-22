# LOGIC · Business-logic and workflow abuse

These flaws are not injection or misconfiguration — the code does exactly what it says, but what
it says is exploitable. A scanner will not find them because nothing is malformed; the request is
valid, it just should not have been honoured. AI-generated code is especially prone here because
it implements the happy path and trusts the client to stay on it.

← [Back to the checklist](../checklist.md) · Related: [`API`](./api.md), [`AUTH`](./authentication.md), [`FILE`](./files.md), [`OBSV`](./observability.md)

---

### LOGIC-01
**P1 · code** — Multi-step workflows enforce their order and state on the server. A step cannot be skipped, replayed, or reached out of sequence.

- **Why:** checkout that ships before payment clears; a signup that reaches "verified" without the verification step; a password reset whose final step can be called directly. The client is made to follow the steps; an attacker calls them in any order they like.
- **Detect:** for each multi-step flow, is the current state stored and checked server-side at every step, or inferred from what the client sends?
- **Fix:** keep workflow state server-side keyed to the session/order; at each step verify the prior step completed; make the final action depend on server-recorded state, not a client flag.
- **Verify:** call the final step directly without the prior steps and confirm it is refused.
- **Probe:** [playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path) — call later-stage endpoints directly.

### LOGIC-02
**P1 · code** — Prices, quantities, totals, and discounts are computed and validated server-side. Never trust an amount from the client.

- **Why:** the classic e-commerce abuse — the client posts `price: 0` or a negative quantity, or edits the total, and the server honours it. Also negative-amount transfers and quantity underflow.
- **Detect:** grep for handlers that read `price`, `amount`, `total`, `quantity`, `discount` from the request and use them without recomputing.
- **Fix:** compute money and quantities from server-side source of truth (catalogue, cart) and validate ranges; reject negatives and out-of-bounds values.
- **Verify:** submit a modified price, a negative quantity, and an oversized amount, and confirm each is rejected or recomputed.
- **Probe:** [playbook §3](./probe-playbook.md#3--object-reference-walking--can-you-read-someone-elses-record) — tamper with amount fields in the body.

### LOGIC-03
**P1 · code** — Operations on shared state are atomic. No time-of-check/time-of-use gap to double-spend, reuse, or race.

- **Why:** race conditions turn "one coupon per user" into many, "withdraw up to balance" into an overdraft, and "one vote" into thousands, by firing concurrent requests in the window between the check and the update.
- **Detect:** find check-then-act sequences on shared resources (balance, stock, coupon, quota). Is there a transaction, row lock, or atomic update, or a read followed by a separate write?
- **Fix:** use atomic operations / `SELECT ... FOR UPDATE` / conditional updates (`UPDATE ... WHERE balance >= ?`) / unique constraints so concurrent requests cannot both succeed.
- **Verify:** fire N concurrent requests at the operation and confirm only the allowed number succeed.

### LOGIC-04
**P1 · code** — Quotas, limits, and entitlements are enforced server-side and cannot be bypassed by the client.

- **Why:** free-trial and credit abuse — the client tracks "uses remaining" or the server trusts a plan flag from the request. Also privilege obtained by sending a role/plan field ([`API-03`](./api.md#api-03)).
- **Detect:** where are limits and entitlements enforced — server-side from an authoritative record, or from client-supplied state?
- **Fix:** enforce quotas and entitlements from the server's record of the account; never accept the remaining-count or plan from the client.
- **Verify:** exhaust a quota, then attempt one more with a manipulated client state, and confirm refusal.

### LOGIC-05
**P2 · code** — Payments and one-time actions are idempotent and replay-protected.

- **Why:** a retried or replayed request that charges twice, redeems a token twice, or submits an order twice; a captured request replayed later.
- **Detect:** do payment and one-time-token endpoints use an idempotency key and reject replays?
- **Fix:** idempotency keys on payment/mutating endpoints; single-use tokens marked spent atomically; short validity windows.
- **Verify:** replay the same request twice and confirm the effect happens once.

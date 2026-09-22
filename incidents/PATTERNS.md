# What Keeps Happening

The rollup of [the corpus](./README.md). Every figure here comes from the records in
`incidents/<year>/`, counted by [`tools/build_index.py`](../tools/build_index.py); live frequencies
are in [`STATS.md`](./STATS.md).

> Counted across **470 records, 2016 Q1 – 2026 Q3**. Percentages are of all records, and tags are
> not exclusive — an incident usually carries several.

---

## Three findings that change how you read the rest

### 1. Half of all breaches involved no escalation at all

`escalation/none-required` appears in **49%** of records. Not "the attacker escalated quickly" —
there was nothing to escalate. The bucket was public. The database had no password. The endpoint
returned the records to anyone who asked. The identifier in the URL was sequential and nobody
checked who was asking.

The second most common escalation, lateral movement, is 24%. Everything else — privilege
escalation, token forgery, flat networks, credential reuse — is in single digits.

This is the opposite of how breaches are usually imagined. The mental model is a chain: foothold,
then privilege, then lateral movement, then exfiltration. In half the corpus there is no chain. A
person typed a URL, or ran a scanner, and the data was there.

**What follows from it:** most of the value in this checklist is in the controls that make the
front door not open, not in the ones that contain an intruder once inside. If you have limited
time, spend it on `DATA-01`, `DATA-03`, `DATA-04`, `AUTH-02`, `AUTH-03` — the ones that decide
whether "none required" applies to you.

### 2. The most common answer to "how did they get in" is that nobody said

`entry/unknown` is **30%** of records — nearly a third, and more than three times the next
vector. These are not cases the researchers failed to look up. They are cases where the victim
published a breach notification that described what was taken and never described how.

That has a practical consequence for anyone building a threat model from public reporting: **the
distribution of published entry vectors is not the distribution of real ones.** What you can see
is skewed toward the mechanisms that are legally required to be disclosed, embarrassing enough to
leak, or interesting enough for a vendor to write up.

It also means the honest ranking below is a ranking of *known* vectors among the 70% that said.

### 3. The top three root causes are organizational, not technical

| Root cause | Share |
| --- | --- |
| `factor/process-failure` — no review, no gate, no approval step | **24%** |
| `factor/detection-failure` — it was visible and nobody saw it | **22%** |
| `factor/third-party-trust` — a vendor, package, or maintainer trusted without verification | **21%** |
| `factor/misconfiguration` | 15% |
| `factor/social-engineering` | 14% |
| `factor/no-least-privilege` | 10% |
| `factor/no-segmentation` | 10% |

No purely technical failure class reaches the top three. The most common way an organization gets
breached is that it had no step where someone would have noticed — not that it ran vulnerable
code.

---

## Entry: how they actually get in

Among records where a vector was disclosed:

| Vector | Share of all records |
| --- | --- |
| `entry/stolen-credentials` — infostealer or commodity malware on a user or contractor device | 6% |
| `entry/supply-chain-vendor` — a vendor was compromised and used as the path in | 5% |
| `entry/misconfiguration` | 5% |
| `entry/unpatched-cve` — a published fix existed and was not applied | 5% |
| `entry/phishing` + `entry/spear-phishing` | 8% combined |
| `entry/public-database` + `entry/public-storage` | 7% combined |
| `entry/third-party-access` | 3% |
| `entry/zero-day` | 3% |

Two things worth noticing.

**Zero-days are 3%.** They dominate coverage and they are a rounding error in the corpus. The
overwhelming majority of intrusions use a credential that already worked, a patch that was already
available, or a door that was already open.

**Credential-shaped entry, added up, is the largest known category.** Stolen credentials, phishing,
credential stuffing, password spraying, credential reuse, session theft, MFA fatigue, default
credentials, OAuth consent and help-desk resets together exceed every other grouping. This is why
`AUTH-01` is the most-cited control in the corpus: it appears against **95 of 470 records**, one in
five.

---

## Escalation: where the damage actually comes from

Entry is usually cheap. What turned an incident into a catastrophe, in this corpus, was almost
always one of five things:

1. **Nothing was needed** (49%) — see above.
2. **Lateral movement across a flat or over-trusting network** (24%).
3. **Over-scoped credentials** (10%) — a token that could read one thing would have been an
   incident; a token that could read everything was a headline.
4. **Supply-chain cascade** (8%) — the victim was itself the path to its customers. This is the
   category that grew fastest across the decade.
5. **Long-lived credentials** — a secret in a public repository for five years, a pilot credential
   unused and unrevoked for four, a storage token set to expire in 2051.

---

## The human dimension

The corpus was built to over-represent ordinary human failure, because that is what most readers
will actually face. What it shows:

- **`factor/social-engineering` is in 14% of records**, and it is growing: help-desk impersonation,
  voice phishing and OAuth consent abuse carried some of the largest incidents of 2023–2026. No
  technical control in `checklist.md` survives a support desk that resets anything for anyone who
  sounds stressed. That is what `HUMAN-01` exists for.
- **Insider and inadvertent disclosure together are only 7 records** — rare, but they include some
  of the most expensive. Bribery of outsourced support staff cost one company a nine-figure sum.
- **69 records are `actor/researcher`** and **82 carry `impact/none-confirmed`** — roughly one in
  six of everything here is a case where somebody found the exposure before an attacker did. These
  are the most instructive records in the corpus: same mechanism, no damage. They are also the
  reason `OBSV-06`, a published way for an outsider to report a problem, is worth the ten minutes
  it costs.

---

## Detection: the gap nobody budgets for

`dwell_days` is recorded for 120 records — most breach notifications do not state it.

| | |
| --- | --- |
| Median dwell time | **19 days** |
| Longest | **3,449 days** (over nine years) |
| Over 90 days | **30 of 120** |

Two conclusions. First, the median is long enough that detection is not a nice-to-have; a
fortnight of undetected access is enough to reach everything. Second, the tail is what defines the
worst cases: the incidents with the largest blast radius in this corpus are almost all long-dwell.

And the control that fails most silently is detection itself. One organization in the corpus had
traffic inspection in place and blind for ten months because a certificate had expired. That is
`OBSV-03`: a control you do not verify is a control you do not have.

---

## What changed for AI-assisted development

AI- and agent-related records, by year:

| Year | AI-related | Total | Share |
| --- | --- | --- | --- |
| 2016–2022 | **0** | 289 | 0% |
| 2023 | 6 | 46 | 13% |
| 2024 | 5 | 41 | 12% |
| 2025 | 11 | 53 | 21% |
| 2026 (partial) | 10 | 41 | **24%** |

Zero for seven years, then a quarter of everything within four. Everything in the first two thirds
of this document still applies unchanged — the new mechanics sit on top of it, they do not replace
it. What is genuinely new:

| Mechanic | First documented | Why it matters when you build with an agent |
| --- | --- | --- |
| Untrusted text an agent reads is executable | 2023, at scale from 2025 | An issue, a ticket, a page, a filename, a tool result. There is no parser to harden: instruction and data share one channel |
| Your AI CLI is an attack tool, already installed, with your privileges | 2025 | Malware stopped shipping a secrets scanner and started asking the agent you installed to do the search |
| Repository configuration is executable | 2026 | Cloning a repository and opening it in an agentic IDE is an install step. By late 2026 a self-propagating worm was writing agent config hooks into every branch it reached |
| Agent, skill and MCP marketplaces are unvetted registries | 2025 | Clean for fifteen versions, malicious in the sixteenth — npm's entire history, replayed against tooling with far less scrutiny |
| The generated default is insecure | 2025 | Row-level security off, the anon key in the bundle, no server-side authorization. The code works perfectly in the demo and is publicly readable in production |
| Hallucinated and invisible code | 2025 | A package name the model invented can be registered by someone else; Unicode that does not render cannot be reviewed |

The same failure appearing twice, nine years apart, is the argument for this whole corpus:
pre-installed phone firmware quietly forwarding users' messages to a foreign server in 2016, and an
MCP server quietly BCC'ing every email it sent in 2025. Different decade, different stack,
identical control: verify what a bundled component actually does, rather than what it says it does.

---

## What this corpus cannot tell you

Stated plainly, because the numbers above are only as good as their limits:

1. **It is built from disclosed breaches.** Undetected and undisclosed incidents are absent by
   definition, and 31% of what *is* disclosed never says how. Treat the entry-vector ranking as a
   ranking of what gets published.
2. **It is skewed by sector.** `sector/tech` is 175 of 470 records, with government, SaaS and
   healthcare next. Manufacturing, agriculture, logistics and small business are under-represented
   relative to how often they are actually hit.
3. **It is skewed by geography.** 171 records are United States, 158 global, 21 United Kingdom, and
   120 are everywhere else — Japan, Australia, Germany, Canada, South Korea, China, France,
   India, the Philippines and others. That is deliberate coverage work, and it is still not
   proportional to where breaches happen.
4. **Confidence is mixed on purpose.** 225 records are `high` (a regulator, a court filing, or the
   victim's own post-mortem), 217 `medium`, 28 `low`. A `low` record is in the corpus because the
   mechanism is instructive, not because the numbers are trustworthy.
5. **Human error is under-counted, and systematically so.** Ordinary mistakes — a misdirected
   email, a spreadsheet with a hidden tab, a lost device — usually surface through a regulator's
   decision rather than through press coverage, and those decisions land a year or more after the
   incident. Several second-pass agents hunting for human-error cases in a given quarter found
   good candidates and had to move them forward by four to eight quarters. The effect is that
   this class is under-represented in recent quarters and over-represented in older ones, and the
   true share is higher than the `factor/human-error` count suggests.
6. **Scale figures are the least reliable field.** Breach counts are revised, duplicated across
   sources, and inflated by attackers. Where a figure is an attacker's claim, the record says so.

---

## How this ordered the checklist

The twelve items in the [fifteen-minute triage](../checklist.md#the-fifteen-minute-triage) are not
a matter of taste. They are the controls that sit against the largest slices above: the ones that
decide whether `escalation/none-required` applies to you, plus MFA, plus one alert that fires when
a single account reads everything.

The most-cited controls across the corpus, in order:

| Control | Records it would have broken |
| --- | --- |
| `AUTH-01` phishing-resistant MFA everywhere with production reach | 95 |
| `CLOUD-05` segmentation between tiers and environments | 76 |
| `OBSV-01` central logging of auth, authorization failures, admin actions, exports | 69 |
| `OBSV-02` alerting on abnormal read or export volume | 68 |
| `OBSV-05` a written incident plan with a named decider and a disclosure clock | 66 |
| `VENDOR-01` an inventory of every third party holding your data or a token | 57 |
| `CLOUD-01` nothing publicly reachable that was not decided to be | 56 |
| `HUMAN-05` training that reflects current technique | 49 |
| `DATA-09` data minimization and enforced retention | 44 |

Four of the top nine are detection, response and inventory — the things that do not prevent a
breach and decide entirely how bad it gets.

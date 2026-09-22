# Incident Record Schema

Every incident in this corpus is one record. Records are grouped into quarterly files at
`incidents/<YYYY>/<YYYY>-Q<N>.md`. This file defines the exact format. **Follow it literally** —
`tools/build_index.py` parses these files to generate `INDEX.md` and `index.jsonl`, and the skills in
`skills/` grep them. A record that deviates from the format is invisible to both.

---

## Quarterly file layout

Each quarterly file has exactly this shape:

````markdown
# <YYYY> Q<N> — <3-6 word characterization of the quarter>

> **Quarter at a glance**
> - **Dominant entry vector:** <tag> — <one clause>
> - **New technique this quarter:** <one clause, or "none">
> - **Recurring failure:** <one clause>
> - **Records in this file:** <count>

## Incidents

### I<YYYY>Q<N>-<NN> · <Organization or campaign name>

```yaml
id: I2016Q4-02
name: Uber rider and driver data breach
org: Uber Technologies
date_occurred: 2016-10
date_disclosed: 2017-11
region: global
sector: [sector/transport, sector/tech]
actor: [actor/criminal]
entry: [entry/secrets-in-repo, entry/credential-reuse]
escalation: [escalation/overscoped-credential]
impact: [impact/pii, impact/extortion]
factor: [factor/human-error, factor/disclosure-failure]
tech: [tech/aws, tech/s3, tech/github]
scale: 57000000 people
cost_usd: 148000000
dwell_days: unknown
confidence: high
controls: [CRED-01, CRED-03, CRED-06, OBSV-05]
sources:
  - https://www.ftc.gov/...
  - https://www.justice.gov/...
```

**What happened.** Two to four sentences. Plain narrative, no hype.

**Entry.** How the first foothold was obtained. Be specific about the mechanism: which file,
which endpoint, which credential, which human action.

**Escalation.** Why one foothold became many. If no escalation was needed, say so explicitly —
"none required, the data was directly readable" is a finding, not a gap.

**Blast radius.** What was finally reached, how much, over what period, and what it cost.

**Human factor.** The decision, habit, or process that made this possible. Every incident has one,
including the purely technical ones — someone chose the default, skipped the review, or deferred
the patch. If genuinely none, write "none identified".

**What would have stopped it.** One to three concrete controls, each naming the control ID from
`checklist.md` that encodes it.
````

Records inside a file are ordered by `date_disclosed`, earliest first.

---

## Field reference

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `id` | yes | `I<YYYY>Q<N>-<NN>` | Two-digit sequence within the quarter, starting at `01`. Must match the heading. |
| `name` | yes | string | How the incident is commonly referred to. |
| `org` | yes | string | Primary victim. For a campaign with many victims, name the campaign and list victims in the prose. |
| `date_occurred` | yes | `YYYY-MM` or `YYYY-MM-DD` or `unknown` | When the intrusion began, not when it was found. |
| `date_disclosed` | yes | `YYYY-MM` or `YYYY-MM-DD` | The quarter a record belongs to is decided by this field. |
| `region` | yes | string | `global`, or a country/region name. |
| `sector` | yes | list | From the `sector/` vocabulary. |
| `actor` | yes | list | From the `actor/` vocabulary. Use `actor/unknown` rather than guessing. |
| `entry` | yes | list | From the `entry/` vocabulary. **The most important field.** |
| `escalation` | yes | list | From the `escalation/` vocabulary. Use `escalation/none-required` when the data was directly reachable. |
| `impact` | yes | list | From the `impact/` vocabulary. |
| `factor` | yes | list | From the `factor/` vocabulary. Always include at least one. |
| `tech` | no | list | From the `tech/` vocabulary. Omit if nothing specific applies. |
| `scale` | yes | `<number> <unit>` or `undisclosed` | e.g. `57000000 people`, `2700 organizations`, `38 TB`. |
| `cost_usd` | no | integer or `undisclosed` | Direct cost, fine, or settlement, whichever is documented. |
| `dwell_days` | no | integer or `unknown` | Days between first access and detection. This field is what makes the detection argument. |
| `confidence` | yes | `high` / `medium` / `low` | `high` = regulator, court filing, or the victim's own post-mortem. `medium` = credible vendor analysis. `low` = single-source reporting or attacker claims. |
| `controls` | yes | list | Control IDs from `checklist.md` that would have broken this chain. |
| `sources` | yes | list of URLs | At least one. Prefer primary sources: regulators, court documents, the victim's own report, then vendor research, then press. |

All tag values come from `TAGS.md`. **Do not invent tags.** If nothing fits, use the closest
match and note the gap in the prose; the vocabulary is extended deliberately, not ad hoc.

---

## Control ID reference

`controls:` entries point at the per-domain files under [`../checklist/`](../checklist/),
indexed from [`../checklist.md`](../checklist.md). The stable prefixes are:

| Prefix | Domain |
| --- | --- |
| `CRED` | Secrets and credentials |
| `AUTH` | Identity, authentication, authorization |
| `DATA` | Data layer, tenant isolation, storage |
| `API` | Object authorization, mass assignment, API shape |
| `INPUT` | Input handling and injection |
| `WEB` | Browser trust: headers, CSP, cookies, CSRF |
| `FILE` | Uploads, storage, and serving |
| `LOGIC` | Business-logic and workflow abuse |
| `LEAK` | Information disclosure |
| `CRYPTO` | Hashing, tokens, randomness, transport |
| `DEPS` | Dependencies and supply chain |
| `AGENT` | AI agents, MCP, prompt injection |
| `CLOUD` | Cloud and infrastructure configuration |
| `DNS` | Domains, subdomains, certificates, email |
| `CICD` | Pipeline, build, deploy, developer machines |
| `VENDOR` | Third parties and integrations |
| `MOBILE` | Mobile application specifics |
| `HUMAN` | People, process, and social engineering |
| `OBSV` | Logging, detection, response, disclosure |

When writing a record before `checklist.md` covers the case, use the prefix plus `-NEW` and
describe the control in the prose — for example `controls: [AGENT-NEW]` with a sentence saying
what the control should require. These are reconciled when the checklist is regenerated.

The three-letter prefixes (`API`, `WEB`, `DNS`) are valid control IDs, not typos.

---

## Rules for accuracy

1. **Never invent a figure.** If the record count is disputed, give the range and set
   `confidence: medium`. If it was never disclosed, write `undisclosed`.
2. **Separate claim from confirmation.** An attacker's claim on a leak site is not a confirmed
   scale. Attribute it in the prose and set `confidence: low`.
3. **Distinguish occurred from disclosed.** Marriott occurred in 2014 and was disclosed in 2018.
   Both dates go in the record; the file it lands in is decided by disclosure.
4. **Prefer mechanism over adjective.** "An unauthenticated API endpoint returned customer records
   when the identifier was incremented" beats "a sophisticated attack".
5. **Record the boring ones.** A misconfigured bucket with no attacker and no ransom teaches more
   about prevention than a nation-state zero-day does. Coverage of ordinary human error is the
   point of this corpus, not a footnote to it.

## Coverage expectations per quarter

A quarterly file should contain **6–14 records** and should deliberately mix:

- at least one **human-error or process-failure** case (`factor/human-error`, `factor/process-failure`,
  `factor/offboarding-failure`, `factor/misconfiguration`)
- at least one **social-engineering** case (`factor/social-engineering`)
- at least one **supply-chain or third-party** case where the victim did nothing wrong themselves
- at least one **small or mid-sized** victim, not only household names
- for 2023 onward, any **AI, agent, or LLM-related** case in that quarter
- where the quarter has one, the **countermeasure or guidance** that emerged in response
  (a CISA advisory, an OWASP release, a regulation, a new default) — recorded in the
  `## Countermeasures and guidance` section at the end of the file, not as an incident record

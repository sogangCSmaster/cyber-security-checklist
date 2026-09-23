# The Incident Corpus

A quarter-by-quarter record of how organizations were actually breached from 2016 to 2026, written
so that both a person and an agent can answer one question quickly:

> *"Has anyone been breached the way I am about to be?"*

Every control in [`../checklist.md`](../checklist.md) traces back to records in here. Nothing in the
checklist is there because it sounded prudent.

---

## What is and is not in here

**In:** publicly disclosed incidents with a documented or credibly reported mechanism, across every
sector and region the sources cover. Famous breaches and forgettable ones. Nation-state operations
and someone emailing a spreadsheet to the wrong address. Exposures found by researchers before any
attacker arrived — those are among the most useful records, because the mechanism is documented and
the damage is zero.

**Not in:** every breach that ever happened. Thousands are disclosed annually and most are never
described in enough detail to learn anything from. This is a **curated, representative corpus** of
roughly 8–14 records per quarter, chosen to cover the full range of failure modes rather than the
largest headline numbers. Where a quarter was dominated by one event, the ordinary failures around
it are still recorded, because those are the ones most readers will repeat.

**Deliberately over-represented:** ordinary human error and process failure. A misconfigured bucket
teaches more about prevention than a zero-day does, and it is far more likely to be your problem.

---

## Layout

```
incidents/
├── README.md        you are here
├── SCHEMA.md        the record format — read before writing a record
├── TAGS.md          the closed tag vocabulary
├── CONTROLS.md      control IDs that records point at
├── INDEX.md         generated: one line per incident, greppable
├── STATS.md         generated: tag frequencies across the corpus
├── index.jsonl      generated: one JSON object per incident
├── PATTERNS.md      the rollup: what actually keeps happening, and why
├── CONTROL-INDEX.md generated: every control, and the incidents behind it
└── <YYYY>/
    └── <YYYY>-Q<N>.md
```

The quarterly files are the source of truth. `INDEX.md`, `STATS.md`, and `index.jsonl` are built
from them:

```bash
python3 tools/build_index.py           # rebuild all three
python3 tools/build_index.py --check   # validate without writing
```

The validator enforces the schema: required fields present, every tag defined in `TAGS.md`, every
control ID real, identifiers unique and matching their file's quarter, at least one source per
record. A record that fails validation is a record nothing can find.

---

## How to search it

The tag namespaces are designed so that one `grep` selects one dimension.

```bash
# Every incident that started with a secret in a repository
grep -rl 'entry/secrets-in-repo' incidents/20*/

# How often is plain human error the root cause?
grep -rho 'factor/human-error' incidents/20*/ | wc -l

# Everything involving Firebase or Supabase
grep -rlE 'tech/(firebase|supabase)' incidents/20*/

# All prompt-injection and agent-tooling cases, newest first
grep -rlE 'entry/(prompt-injection|indirect-prompt-injection|agent-tooling)' incidents/ | sort -r

# Which incidents does control DATA-01 answer for?
grep -rl 'DATA-01' incidents/20*/

# Machine-readable: every incident above 10M records, as JSON
jq -c 'select(.scale | test("[0-9]{8,}"))' incidents/index.jsonl
```

`INDEX.md` is the fastest way in for a human: one line per incident with the entry vector and the
controls, linked to the full record.

---

## How the skills use it

The three skills in [`../skills/`](../skills/) treat this corpus as evidence, not as background
reading. None of them loads the whole thing — that would be both slow and pointless.

| Skill | What it does with the corpus |
| --- | --- |
| `secure-by-default` | Does not read it during generation. The corpus is what produced the rules it applies |
| `security-audit` | On a finding, looks up the control in [`precedents.md`](../skills/security-audit/references/precedents.md) — generated from this corpus and shipped inside the skill — and cites a matching incident with its record ID and source, so the finding carries a consequence rather than a severity label |
| `ship-gate` | Orders its gates by how often each failure appears here ([`STATS.md`](./STATS.md)); the order is fixed in the skill and revisited when the corpus changes |

The pattern is deliberate: **the checklist carries the rule, the corpus carries the proof.** A
finding that says "this is CRED-01, and it is how Uber lost 57 million records in 2016 and Toyota
lost 296,000 in 2022" changes behaviour. A finding that says "hardcoded credential, severity high"
does not.

---

## Adding a record

1. Read [`SCHEMA.md`](./SCHEMA.md). Follow the format exactly.
2. Use only tags from [`TAGS.md`](./TAGS.md). To add a tag, define it there first.
3. Put the record in the quarter of its **disclosure**, not its intrusion. Marriott was breached in
   2014 and disclosed in 2018; it lives in `2018/2018-Q4.md` with both dates recorded.
4. Cite at least one source, preferring regulators, court filings, and the victim's own
   post-mortem over press coverage.
5. Run `python3 tools/build_index.py` and commit the regenerated index files with your record.

### On accuracy

Figures in breach reporting are frequently wrong, revised, or repeated from a single bad source.
The `confidence` field exists so that a reader can tell the difference between a regulator's
finding and an attacker's boast:

- `high` — a regulator, a court filing, or the victim's own published post-mortem
- `medium` — credible independent vendor analysis, or a disputed range
- `low` — single-source reporting, or a claim made by the attacker

If a number was never disclosed, the field says `undisclosed`. It does not say a guess.

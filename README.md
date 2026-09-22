# Cyber Security Checklist

**A security checklist derived from how organizations were actually breached between 2016 and
2026 — installable as a Claude Code plugin, usable as a copy-paste prompt, readable as a
document.**

Most security checklists are written from first principles and read like a list of things a
careful person would probably do. This one is written backwards: from a corpus of documented
breaches, through the mechanism each one used, to the control that would have broken the chain.
Every item cites the incident that produced it.

That matters because the failures are not exotic. A 2025 scan of 1,072 AI-built applications
found 98% carrying at least one security flaw, and they were overwhelmingly the same handful of
mistakes that cost Uber 57 million records in 2016. Knowing *that* a control exists changes
nothing. Knowing what it cost the last six companies that skipped it changes behaviour.

---

## What is in here

| | What it is | Who it is for |
| --- | --- | --- |
| **[`checklist.md`](./checklist.md)** | 110 controls across 11 domains, each with a priority, the incident behind it, and a way to verify it | Anyone. Start with the twelve-item triage at the top |
| **[`incidents/`](./incidents/)** | The evidence: a quarter-by-quarter corpus of documented breaches, tagged and indexed | Anyone asking "has this actually happened?" |
| **[`skills/`](./skills/)** | Three Claude Code skills that apply the checklist while you work | Claude Code users |
| **[`prompts/`](./prompts/)** | The same content as copy-paste text | Cursor, Copilot, ChatGPT, anything else |

---

## Install as a Claude Code plugin

```shell
/plugin marketplace add sogangCSmaster/cyber-security-checklist
/plugin install security-checklist@cyber-security-checklist
```

That gives you three skills:

### `secure-by-default` — applied while you write

Claude loads it automatically when generating code that touches user data, credentials,
authentication, database access, uploads, dependencies, or agent tooling. It does not ask
permission for defaults; it writes the secure version and tells you in one line what it did.

> Enabled RLS with a default-deny policy on `profiles` in the same migration, and added a test
> asserting user A gets zero rows for user B. Supabase tables are readable by anyone with the
> anon key until a policy exists.

### `/security-checklist:security-review` — audits what already exists

Runs concrete detection commands across secrets, the data layer, authorization, injection,
dependencies, the agent surface, and cloud configuration — then makes every finding carry the
incident that proves it matters:

> **Supabase `profiles` table has no row-level security policy** — `DATA-01`
> `supabase/migrations/0002_profiles.sql:14`
> Any holder of the anon key — which is in the client bundle, so everyone — can read every row.
> *Precedent:* Lovable shipped generated apps without RLS (CVE-2025-48757); 170+ production
> applications were confirmed exposed. Moltbook repeated it in 2026 and lost 1.5M API tokens.

### `/security-checklist:ship-gate` — the last checkpoint

Eight blocking gates and eight should-fix gates, ordered by how often each failure actually
appears in the corpus. Returns **SHIP** or **DO NOT SHIP**, with evidence for every pass. A gate
it could not verify is reported as unverified rather than assumed fine.

### Without the plugin

Copy the skills into any project:

```shell
git clone https://github.com/sogangCSmaster/cyber-security-checklist
cp -r cyber-security-checklist/skills/* ~/.claude/skills/     # all your projects
cp -r cyber-security-checklist/skills/* .claude/skills/       # just this one
```

Or try it without installing anything:

```shell
claude --plugin-dir ./cyber-security-checklist
```

---

## Not using Claude Code

Everything works as plain text. [`prompts/`](./prompts/) holds self-contained versions that need
nothing from this repository:

- **[`review-prompt.md`](./prompts/review-prompt.md)** — paste into any AI tool with access to
  your code
- **[`ship-gate-prompt.md`](./prompts/ship-gate-prompt.md)** — paste before deploying, for a
  go/no-go verdict
- **[`AGENTS.md.template`](./prompts/AGENTS.md.template)** — drop into **your** repository root.
  Claude Code, Cursor, Codex and most agentic tools read it automatically, so the defaults apply
  without anyone remembering to ask

---

## The evidence

[`incidents/`](./incidents/) is a quarter-by-quarter corpus covering 2016 through 2026. Each
record separates three things that are usually blurred together, because they need three
different fixes:

| | Question | What it maps to |
| --- | --- | --- |
| **Entry** | How did they get the first foothold? | Prevention |
| **Escalation** | Why did one foothold become many? | Blast radius — segmentation, scoping, least privilege |
| **Reach** | How far did it finally go? | Detection, retention, data minimization |

Plus a **human factor** field on every record, because every incident has one — someone chose the
default, skipped the review, or deferred the patch.

Records carry a closed vocabulary of tags across seven namespaces, so one `grep` selects one
dimension:

```bash
grep -rl 'entry/secrets-in-repo' incidents/20*/       # every incident that began with a committed key
grep -rho 'factor/human-error' incidents/20*/ | wc -l # how often plain human error is the root cause
grep -rlE 'tech/(firebase|supabase)' incidents/20*/   # everything involving a client-queried backend
grep -rl 'DATA-01' incidents/20*/                     # which incidents does this control answer for?
```

[`incidents/INDEX.md`](./incidents/INDEX.md) is one line per incident.
[`incidents/STATS.md`](./incidents/STATS.md) is the frequency rollup that the checklist's ordering
comes from. [`incidents/index.jsonl`](./incidents/index.jsonl) is the machine-readable version.
All three are generated:

```bash
python3 tools/build_index.py           # rebuild
python3 tools/build_index.py --check   # validate without writing
```

### What the corpus is and is not

It is **curated and representative**, not exhaustive. Thousands of breaches are disclosed
annually and most are never described in enough detail to learn from. Each quarter holds 8–14
records chosen to span the full range of failure modes rather than the largest headline numbers,
with ordinary human error and process failure deliberately over-represented — a misconfigured
bucket teaches more about prevention than a nation-state zero-day, and it is far more likely to
be your problem.

It is also **skewed toward what gets reported**: consumer data, regulated industries, and
English-language coverage. That limitation is stated in the checklist rather than hidden.

---

## Contributing

Add an incident:

1. Read [`incidents/SCHEMA.md`](./incidents/SCHEMA.md) and follow the record format exactly.
2. Use only tags defined in [`incidents/TAGS.md`](./incidents/TAGS.md). To add a tag, define it
   there first.
3. File it in the quarter of its **disclosure**, not its intrusion, recording both dates.
4. Cite at least one source, preferring regulators, court filings, and the victim's own
   post-mortem over press coverage.
5. Run `python3 tools/build_index.py` and commit the regenerated index with your record.

The `confidence` field exists so a reader can tell a regulator's finding from an attacker's
boast. If a number was never disclosed, the record says `undisclosed` — it does not say a guess.

Add a control: it needs at least one incident in the corpus that it would have stopped. A control
with no evidence behind it belongs in a different list.

---

## License

MIT. See [`LICENSE`](./LICENSE).

The incident records describe publicly disclosed events and cite their sources. They are
compiled for defensive use — understanding how systems fail in order to stop them failing the
same way again.

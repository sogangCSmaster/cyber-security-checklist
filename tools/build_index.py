#!/usr/bin/env python3
"""Build the searchable index for the incident corpus.

Reads every quarterly file under ``incidents/<YYYY>/<YYYY>-Q<N>.md``, extracts the
YAML metadata block from each record, validates it against the closed vocabulary in
``incidents/TAGS.md`` and the control IDs in ``incidents/CONTROLS.md``, and writes:

  incidents/index.jsonl        one JSON object per incident, for machine consumption
  incidents/INDEX.md           a greppable table, for humans and for skills
  incidents/STATS.md           tag frequency rollups across the whole corpus
  incidents/CONTROL-INDEX.md   every control, and the incidents that would have been broken by it

Usage:
    python3 tools/build_index.py            # build
    python3 tools/build_index.py --check    # validate only, non-zero exit on error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - the fallback keeps the tool dependency-free
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
INCIDENTS = ROOT / "incidents"

RECORD_RE = re.compile(
    r"^###\s+(?P<id>I\d{4}Q\d-\d+)\s*[·|-]\s*(?P<title>.+?)\s*$\n+```ya?ml\n(?P<yaml>.*?)\n```",
    re.MULTILINE | re.DOTALL,
)
TAG_RE = re.compile(r"`((?:entry|escalation|impact|factor|tech|actor|sector)/[a-z0-9-]+)`")
CONTROL_RE = re.compile(r"\|\s*(?P<id>[A-Z]{4,6}-\d{2})\s*\|")

REQUIRED = [
    "id", "name", "org", "date_occurred", "date_disclosed", "region",
    "sector", "actor", "entry", "escalation", "impact", "factor",
    "scale", "confidence", "controls", "sources",
]
TAG_FIELDS = ["sector", "actor", "entry", "escalation", "impact", "factor", "tech"]


def load_vocabulary() -> set[str]:
    text = (INCIDENTS / "TAGS.md").read_text(encoding="utf-8")
    return set(TAG_RE.findall(text))


def load_controls() -> set[str]:
    text = (INCIDENTS / "CONTROLS.md").read_text(encoding="utf-8")
    return set(CONTROL_RE.findall(text))


def parse_block(raw: str) -> dict:
    if yaml is not None:
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return data
        raise ValueError("metadata block is not a mapping")
    # Minimal fallback: scalars, inline lists, and dash lists only.
    data: dict = {}
    key = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - ") and key:
            data.setdefault(key, []).append(line[4:].strip())
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if value.startswith("[") and value.endswith("]"):
            data[key] = [v.strip() for v in value[1:-1].split(",") if v.strip()]
        elif value:
            data[key] = value
        else:
            data[key] = []
    return data


def quarterly_files() -> list[Path]:
    return sorted(INCIDENTS.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9][0-9][0-9]-Q[1-4].md"))


def collect(vocab: set[str], controls: set[str]) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    errors: list[str] = []
    seen_ids: dict[str, str] = {}

    for path in quarterly_files():
        rel = path.relative_to(ROOT).as_posix()
        stem = path.stem                      # e.g. 2019-Q3
        expected_prefix = "I" + stem.replace("-", "")

        text = path.read_text(encoding="utf-8")
        matches = list(RECORD_RE.finditer(text))
        if not matches:
            errors.append(f"{rel}: no incident records found")
            continue

        for match in matches:
            heading_id = match.group("id")
            where = f"{rel}:{heading_id}"
            try:
                data = parse_block(match.group("yaml"))
            except Exception as exc:                       # noqa: BLE001
                errors.append(f"{where}: unparseable metadata block ({exc})")
                continue

            for field in REQUIRED:
                if field not in data or data[field] in (None, "", []):
                    errors.append(f"{where}: missing required field '{field}'")

            if str(data.get("id", "")) != heading_id:
                errors.append(f"{where}: id field '{data.get('id')}' does not match heading")
            if not heading_id.startswith(expected_prefix):
                errors.append(f"{where}: id does not match the file's quarter ({expected_prefix}-NN)")
            if heading_id in seen_ids:
                errors.append(f"{where}: duplicate id, also in {seen_ids[heading_id]}")
            seen_ids[heading_id] = rel

            for field in TAG_FIELDS:
                for tag in as_list(data.get(field)):
                    if tag not in vocab:
                        errors.append(f"{where}: undefined tag '{tag}' in {field}")

            for control in as_list(data.get("controls")):
                if control not in controls and not control.endswith("-NEW"):
                    errors.append(f"{where}: unknown control '{control}'")

            if str(data.get("confidence", "")) not in {"high", "medium", "low"}:
                errors.append(f"{where}: confidence must be high, medium, or low")

            if not as_list(data.get("sources")):
                errors.append(f"{where}: at least one source URL is required")

            data["file"] = rel
            data["title"] = match.group("title")
            data["year"] = int(stem[:4])
            data["quarter"] = stem[-2:]
            records.append(data)

    records.sort(key=lambda r: (str(r.get("date_disclosed", "")), str(r.get("id", ""))))
    return records, errors


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def write_jsonl(records: list[dict]) -> None:
    lines = []
    for r in records:
        tags = []
        for field in TAG_FIELDS:
            tags.extend(as_list(r.get(field)))
        lines.append(json.dumps({
            "id": r.get("id"),
            "name": r.get("name"),
            "org": r.get("org"),
            "year": r.get("year"),
            "quarter": r.get("quarter"),
            "date_occurred": str(r.get("date_occurred")),
            "date_disclosed": str(r.get("date_disclosed")),
            "region": r.get("region"),
            "scale": str(r.get("scale")),
            "cost_usd": r.get("cost_usd", "undisclosed"),
            "dwell_days": r.get("dwell_days", "unknown"),
            "confidence": r.get("confidence"),
            "tags": tags,
            "controls": as_list(r.get("controls")),
            "sources": as_list(r.get("sources")),
            "file": r.get("file"),
        }, ensure_ascii=False, sort_keys=False))
    (INCIDENTS / "index.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_index_md(records: list[dict]) -> None:
    by_year: dict[int, list[dict]] = defaultdict(list)
    for r in records:
        by_year[r["year"]].append(r)

    out = [
        "# Incident Index",
        "",
        "Generated by `tools/build_index.py`. Do not edit by hand — edit the quarterly files",
        "under `incidents/<year>/` and rebuild.",
        "",
        f"**{len(records)} records** across {len(by_year)} years.",
        "",
        "One line per incident: identifier, when it was disclosed, who it happened to, how they",
        "got in, and which controls would have broken the chain. Grep this file to find a case;",
        "open the quarterly file for the full record.",
        "",
    ]
    for year in sorted(by_year):
        rows = by_year[year]
        out += [
            f"## {year} ({len(rows)} records)",
            "",
            "| ID | Disclosed | Organization | Entry | Scale | Controls |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for r in rows:
            entry = ", ".join(as_list(r.get("entry"))[:3])
            controls = ", ".join(as_list(r.get("controls"))[:4])
            link = f"[{r['id']}]({Path(r['file']).relative_to('incidents').as_posix()}#{anchor(r)})"
            out.append(
                f"| {link} | {r.get('date_disclosed')} | {r.get('org')} | {entry} | "
                f"{r.get('scale')} | {controls} |"
            )
        out.append("")
    (INCIDENTS / "INDEX.md").write_text("\n".join(out), encoding="utf-8")


def anchor(record: dict) -> str:
    text = f"{record['id']} · {record.get('title', '')}"
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s]+", "-", slug).strip("-")


def write_control_index(records: list[dict], controls: set[str]) -> list[str]:
    """Map every control to the incidents citing it. Returns controls with no evidence."""
    cited: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        for c in as_list(r.get("controls")):
            cited[c].append(r)

    titles = {}
    for line in (INCIDENTS / "CONTROLS.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*([A-Z]{4,6}-\d{2})\s*\|\s*(.+?)\s*\|", line)
        if m:
            titles[m.group(1)] = m.group(2)

    out = [
        "# Control Index",
        "",
        "Generated by `tools/build_index.py`. For every control in [`../checklist.md`](../checklist.md),",
        "the incidents in this corpus that it would have broken.",
        "",
        "This is what makes the checklist auditable: a control with no incidents behind it is a",
        "preference, and this file is where that shows.",
        "",
    ]
    empty = []
    for cid in sorted(titles, key=lambda c: (c.split("-")[0], c)):
        rows = sorted(cited.get(cid, []), key=lambda r: str(r.get("date_disclosed")))
        out.append(f"## `{cid}` — {titles[cid]}")
        out.append("")
        if not rows:
            out += ["*No incident in the corpus cites this control yet.*", ""]
            empty.append(cid)
            continue
        out.append(f"**{len(rows)} incidents.**")
        out.append("")
        out += ["| Incident | Disclosed | Organization |", "| --- | --- | --- |"]
        for r in rows:
            link = f"[{r['id']}]({Path(r['file']).relative_to('incidents').as_posix()}#{anchor(r)})"
            out.append(f"| {link} | {r.get('date_disclosed')} | {r.get('org')} |")
        out.append("")
    (INCIDENTS / "CONTROL-INDEX.md").write_text("\n".join(out), encoding="utf-8")
    return empty


def write_stats(records: list[dict]) -> None:
    counters = {field: Counter() for field in TAG_FIELDS}
    controls = Counter()
    for r in records:
        for field in TAG_FIELDS:
            counters[field].update(as_list(r.get(field)))
        controls.update(as_list(r.get("controls")))

    out = [
        "# Corpus Statistics",
        "",
        "Generated by `tools/build_index.py`. Frequencies across the whole corpus.",
        "",
        f"**{len(records)} incidents indexed.**",
        "",
        "These counts are what `checklist.md` prioritizes by: a control that appears against many",
        "incidents is not a preference, it is where the evidence is.",
        "",
    ]
    titles = {
        "entry": "How they got in",
        "escalation": "Why one foothold became many",
        "factor": "The underlying failure",
        "impact": "What was reached",
        "tech": "Technology involved",
        "actor": "Who did it",
        "sector": "Who it happened to",
    }
    for field in ["entry", "factor", "escalation", "impact", "tech", "actor", "sector"]:
        counter = counters[field]
        if not counter:
            continue
        out += [f"## {titles[field]} (`{field}/`)", "", "| Tag | Incidents |", "| --- | --- |"]
        out += [f"| `{tag}` | {n} |" for tag, n in counter.most_common()]
        out.append("")

    out += ["## Most-cited controls", "", "| Control | Incidents it would have broken |", "| --- | --- |"]
    out += [f"| `{cid}` | {n} |" for cid, n in controls.most_common()]
    out.append("")
    (INCIDENTS / "STATS.md").write_text("\n".join(out), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate only, write nothing")
    args = parser.parse_args()

    vocab = load_vocabulary()
    controls = load_controls()
    records, errors = collect(vocab, controls)

    for err in errors:
        print(f"error: {err}", file=sys.stderr)

    if not args.check:
        write_jsonl(records)
        write_index_md(records)
        write_stats(records)
        empty = write_control_index(records, controls)
        print(f"indexed {len(records)} records from {len(quarterly_files())} quarterly files")
        if empty:
            print(f"note: {len(empty)} control(s) with no incident evidence: {', '.join(empty)}")

    if errors:
        print(f"\n{len(errors)} validation error(s)", file=sys.stderr)
        return 1
    print("validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

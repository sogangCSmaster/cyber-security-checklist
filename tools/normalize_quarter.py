#!/usr/bin/env python3
"""Re-sort a quarterly file's records by date_disclosed and renumber their IDs.

Records are split on their `### I<YYYY>Q<N>-<NN> · <name>` headings, so the
separator style in the file does not matter. Use after moving a record between
quarters, or when records were written out of order.

    python3 tools/normalize_quarter.py incidents/2024/2024-Q1.md
"""
import re
import sys
from pathlib import Path

HEADING = re.compile(r'^### (I\d{4}Q\d)-(\d+) · ', re.M)


def normalize(path: Path) -> int:
    text = path.read_text(encoding='utf-8')
    head, sep, rest = text.partition('\n## Incidents\n')
    if not sep:
        raise SystemExit(f'{path}: no "## Incidents" section')
    body, tail_sep, tail = rest.partition('\n## Countermeasures and guidance')

    starts = [m.start() for m in HEADING.finditer(body)]
    if not starts:
        raise SystemExit(f'{path}: no incident records found')
    bounds = starts + [len(body)]
    blocks = [body[bounds[i]:bounds[i + 1]] for i in range(len(starts))]

    # strip any trailing horizontal rule so we can re-add them uniformly
    blocks = [re.sub(r'\n+---\s*$', '', b.rstrip()) for b in blocks]

    def disclosed(block: str) -> str:
        m = re.search(r'^date_disclosed:\s*(\S+)', block, re.M)
        return m.group(1) if m else '9999-99'

    blocks.sort(key=disclosed)

    prefix = HEADING.search(body).group(1)
    renumbered = []
    for i, block in enumerate(blocks, 1):
        renumbered.append(re.sub(rf'{prefix}-\d+', f'{prefix}-{i:02d}', block))

    body = '\n' + '\n\n---\n\n'.join(renumbered) + '\n\n---\n'
    new = head + sep + body + tail_sep + tail
    new = re.sub(r'(\*\*Records in this file:\*\* )\d+', rf'\g<1>{len(blocks)}', new)
    path.write_text(new, encoding='utf-8')
    return len(blocks)


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        p = Path(arg)
        print(f'{p}: {normalize(p)} records re-sorted and renumbered')

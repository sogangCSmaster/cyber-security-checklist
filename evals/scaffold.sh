#!/usr/bin/env bash
# Materialize a fixture app from tests/fixtures into the eval's empty workspace.
# Usage (from a case's scaffold script): "$(dirname "$0")/../scaffold.sh" <fixture>
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$ROOT/tests/fixtures/materialize.py" "$1" . >/dev/null
